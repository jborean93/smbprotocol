# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import binascii
import errno
import ntpath
import os
import socket

from collections import (
    OrderedDict,
)

from smbprotocol import (
    Dialects,
)

from smbprotocol._text import (
    to_bytes,
    to_native,
    to_text,
)

from smbprotocol.reparse_point import (
    SymbolicLinkReparseDataBuffer,
)

from smbprotocol.structure import (
    BytesField,
    EnumField,
    IntField,
    ListField,
    Structure,
    StructureField,
)


class NtStatus(object):
    """
    [MS-ERREF] https://msdn.microsoft.com/en-au/library/cc704588.aspx

    2.3.1 NTSTATUS Values
    These values are set in the status field of an SMB2Header response. This is
    not an exhaustive list but common values that are returned.
    """
    STATUS_SUCCESS = 0x00000000
    STATUS_PENDING = 0x00000103
    STATUS_NOTIFY_CLEANUP = 0x0000010B
    STATUS_NOTIFY_ENUM_DIR = 0x0000010C
    STATUS_BUFFER_OVERFLOW = 0x80000005
    STATUS_NO_MORE_FILES = 0x80000006
    STATUS_END_OF_FILE = 0xC0000011
    STATUS_INVALID_EA_NAME = 0x80000013
    STATUS_EA_LIST_INCONSISTENT = 0x80000014
    STATUS_STOPPED_ON_SYMLINK = 0x8000002D
    STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
    STATUS_INVALID_PARAMETER = 0xC000000D
    STATUS_NO_SUCH_FILE = 0xC000000F
    STATUS_END_OF_FILE = 0xC0000011
    STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
    STATUS_ACCESS_DENIED = 0xC0000022
    STATUS_BUFFER_TOO_SMALL = 0xC0000023
    STATUS_OBJECT_NAME_INVALID = 0xC0000033
    STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
    STATUS_OBJECT_NAME_COLLISION = 0xC0000035
    STATUS_OBJECT_PATH_INVALID = 0xC0000039
    STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A
    STATUS_OBJECT_PATH_SYNTAX_BAD = 0xC000003B
    STATUS_SHARING_VIOLATION = 0xC0000043
    STATUS_EAS_NOT_SUPPORTED = 0xC000004F
    STATUS_EA_TOO_LARGE = 0xC0000050
    STATUS_NONEXISTENT_EA_ENTRY = 0xC0000051
    STATUS_NO_EAS_ON_FILE = 0xC0000052
    STATUS_EA_CORRUPT_ERROR = 0xC0000053
    STATUS_PRIVILEGE_NOT_HELD = 0xC0000061
    STATUS_LOGON_FAILURE = 0xC000006D
    STATUS_PASSWORD_EXPIRED = 0xC0000071
    STATUS_INSUFFICIENT_RESOURCES = 0xC000009A
    STATUS_PIPE_BUSY = 0xC00000AE
    STATUS_PIPE_CLOSING = 0xC00000B1
    STATUS_PIPE_DISCONNECTED = 0xC00000B0
    STATUS_FILE_IS_A_DIRECTORY = 0xC00000BA
    STATUS_NOT_SUPPORTED = 0xC00000BB
    STATUS_BAD_NETWORK_NAME = 0xC00000CC
    STATUS_REQUEST_NOT_ACCEPTED = 0xC00000D0
    STATUS_PIPE_EMPTY = 0xC00000D9
    STATUS_INTERNAL_ERROR = 0xC00000E5
    STATUS_DIRECTORY_NOT_EMPTY = 0xC0000101
    STATUS_NOT_A_DIRECTORY = 0xC0000103
    STATUS_CANCELLED = 0xC0000120
    STATUS_CANNOT_DELETE = 0xC0000121
    STATUS_FILE_CLOSED = 0xC0000128
    STATUS_PIPE_BROKEN = 0xC000014B
    STATUS_USER_SESSION_DELETED = 0xC0000203
    STATUS_NOT_A_REPARSE_POINT = 0xC0000275


class SMBException(Exception):
    # Generic SMB Exception with a message
    pass


class SMBAuthenticationError(SMBException):
    # Used for authentication specific errors
    pass


class SMBOSError(OSError, SMBException):

    def __init__(self, ntstatus, filename, filename2=None):
        self.ntstatus = ntstatus
        self.filename2 = to_native(filename2) if filename2 else None

        ntstatus_name = 'STATUS_UNKNOWN'
        for name, val in vars(NtStatus).items():
            if ntstatus == val:
                ntstatus_name = name
                break

        error_details = {
            NtStatus.STATUS_OBJECT_NAME_NOT_FOUND: errno.ENOENT,
            NtStatus.STATUS_OBJECT_PATH_NOT_FOUND: errno.ENOENT,
            NtStatus.STATUS_OBJECT_NAME_COLLISION: errno.EEXIST,
            NtStatus.STATUS_PRIVILEGE_NOT_HELD: (errno.EACCES, "Required privilege not held"),
            NtStatus.STATUS_SHARING_VIOLATION: (errno.EPERM, "The process cannot access the file because it is being "
                                                             "used by another process"),
            NtStatus.STATUS_NOT_A_REPARSE_POINT: (errno.EINVAL, "The file or directory is not a reparse point"),
            NtStatus.STATUS_FILE_IS_A_DIRECTORY: errno.EISDIR,
            NtStatus.STATUS_NOT_A_DIRECTORY: errno.ENOTDIR,
            NtStatus.STATUS_DIRECTORY_NOT_EMPTY: errno.ENOTEMPTY,
            NtStatus.STATUS_END_OF_FILE: getattr(errno, 'ENODATA', 120),  # Not present on py2 for Windows.
        }.get(ntstatus, (0, "Unknown NtStatus error returned '%s'" % ntstatus_name))

        if not isinstance(error_details, tuple):
            error_details = (error_details, os.strerror(error_details))

        super(SMBOSError, self).__init__(error_details[0], error_details[1], to_native(filename))

    def __str__(self):
        msg = "[Error {0}] [NtStatus 0x{1}] {2}: '{3}'".format(self.errno, format(self.ntstatus, 'x').zfill(8),
                                                               self.strerror, self.filename)
        if self.filename2:
            msg += " -> '%s'" % self.filename2

        return msg


class SMBLinkRedirectionError(SMBException):

    @property
    def message(self):
        msg = "Encountered symlink at '%s' that points to '%s' which cannot be redirected: %s" \
              % (to_native(self.path), to_native(self.target), to_native(self.args[0]))
        return msg

    @property
    def path(self):
        return self.args[1]

    @property
    def target(self):
        return self.args[2]

    def __str__(self):
        return self.message


class SMBUnsupportedFeature(SMBException):

    @property
    def negotiated_dialect(self):
        return self.args[0]

    @property
    def required_dialect(self):
        return self.args[1]

    @property
    def feature_name(self):
        return self.args[2]

    @property
    def requires_newer(self):
        if len(self.args) > 3:
            return self.args[3]
        else:
            return None

    @property
    def message(self):
        if self.requires_newer is None:
            msg_suffix = ""
        elif self.requires_newer:
            msg_suffix = " or newer"
        else:
            msg_suffix = " or older"

        required_dialect = self._get_dialect_name(self.required_dialect)
        negotiated_dialect = self._get_dialect_name(self.negotiated_dialect)

        msg = "%s is not available on the negotiated dialect %s, " \
              "requires dialect %s%s"\
              % (self.feature_name, negotiated_dialect, required_dialect,
                 msg_suffix)
        return msg

    def __str__(self):
        return self.message

    def _get_dialect_name(self, dialect):
        dialect_field = EnumField(
            enum_type=Dialects,
            enum_strict=False,
            size=2)
        dialect_field.set_value(dialect)
        return str(dialect_field)


class SMBResponseException(SMBException):

    @property
    def header(self):
        # the full message that was returned by the server
        return self.args[0]

    @property
    def status(self):
        # the raw int status value, used by method that catch this exception
        # for control flow
        return self.args[1]

    @property
    def error_details(self):
        # list of error_details returned by the server, currently used in
        # the SMB 3.1.1 error response for certain situations
        error = SMB2ErrorResponse()
        error.unpack(self.header['data'].get_value())

        error_details = []
        for raw_error_data in error['error_data'].get_value():
            error_id = raw_error_data['error_id'].get_value()
            raw_data = raw_error_data['error_context_data'].get_value()
            if self.status == NtStatus.STATUS_STOPPED_ON_SYMLINK:
                error_data = SMB2SymbolicLinkErrorResponse()
                error_data.unpack(raw_data)
            elif self.status == NtStatus.STATUS_BAD_NETWORK_NAME and \
                    error_id == ErrorContextId.SMB2_ERROR_ID_SHARE_REDIRECT:
                error_data = SMB2ShareRedirectErrorContext()
                error_data.unpack(raw_data)
            else:
                # unknown context data so we just set it the raw bytes
                error_data = raw_data
            error_details.append(error_data)

        return error_details

    @property
    def message(self):
        error_details_msg = ""
        for error_detail in self.error_details:
            if isinstance(error_detail, SMB2SymbolicLinkErrorResponse):
                detail_msg = self._get_symlink_error_detail_msg(error_detail)
            elif isinstance(error_detail, SMB2ShareRedirectErrorContext):
                detail_msg = self._get_share_redirect_detail_msg(error_detail)
            else:
                # unknown error details in response, output raw bytes
                detail_msg = "Raw: %s" % binascii.hexlify(error_detail).decode('utf-8')

            # the first details message is set differently
            if error_details_msg == "":
                error_details_msg = "%s - %s" % (error_details_msg, detail_msg)
            else:
                error_details_msg = "%s, %s" % (error_details_msg, detail_msg)

        status_hex = format(self.status, 'x')
        error_message = "%s: 0x%s%s" % (str(self.header['status']),
                                        status_hex, error_details_msg)
        return "Received unexpected status from the server: %s" % error_message

    def __str__(self):
        return self.message

    def _get_share_redirect_detail_msg(self, error_detail):
        ip_addresses = []
        for ip_addr in error_detail['ip_addr_move_list'].get_value():
            ip_addresses.append(ip_addr.get_ipaddress())

        resource_name = error_detail['resource_name'].get_value(). \
            decode('utf-16-le')
        detail_msg = "IP Addresses: '%s', Resource Name: %s" \
                     % ("', '".join(ip_addresses), resource_name)
        return detail_msg

    def _get_symlink_error_detail_msg(self, error_detail):
        flag = str(error_detail['flags'])
        print_name = error_detail.get_print_name()
        sub_name = error_detail.get_substitute_name()
        detail_msg = "Flag: %s, Print Name: %s, Substitute Name: %s" \
                     % (flag, print_name, sub_name)
        return detail_msg


class ErrorContextId(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.2.1 SMB2 Error Context Response ErrorId
    An identifier for the error context, it MUST be set to one of the following
    values.
    """
    SMB2_ERROR_ID_DEFAULT = 0x00000000
    SMB2_ERROR_ID_SHARE_REDIRECT = 0x53526472


class SymbolicLinkErrorFlags(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.2.2.1 Symbolic Link Error Response Flags
    Specifies whether the substitute name is an absolute target path or a path
    name relative to the directory containing the symbolic link
    """
    SYMLINK_FLAG_ABSOLUTE = 0x00000000
    SYMLINK_FLAG_RELATIVE = 0x00000001


class IpAddrType(object):
    """
    [MS-SM2] v53.0 2017-09-15

    2.2.2.2.2.1 MOVE_DST_IPADDR structure Type
    Indicates the type of the destionation IP address.
    """
    MOVE_DST_IPADDR_V4 = 0x00000001
    MOVE_DST_IPADDR_V6 = 0x00000002


class SMB2ErrorResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.2 SMB2 Error Response
    The SMB2 Error Response packet is sent by the server to respond to a
    request that has failed or encountered an error. This is only used in the
    SMB 3.1.1 dialect and this code won't decode values based on older versions
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=9,
            )),
            ('error_context_count', IntField(
                size=1,
                default=lambda s: len(s['error_data'].get_value()),
            )),
            ('reserved', IntField(size=1)),
            ('byte_count', IntField(
                size=4,
                default=lambda s: len(s['error_data']),
            )),
            ('error_data', ListField(
                size=lambda s: s['byte_count'].get_value(),
                list_count=lambda s: s['error_context_count'].get_value(),
                list_type=StructureField(
                    structure_type=SMB2ErrorContextResponse
                ),
                unpack_func=lambda s, d: self._error_data_value(s, d)
            )),
        ])
        super(SMB2ErrorResponse, self).__init__()

    def _error_data_value(self, structure, data):
        context_responses = []

        while len(data) > 0:
            response = SMB2ErrorContextResponse()
            if structure['error_context_count'].get_value() > 0:
                # Working with SMB 3.1.1+ where the errors are already in an SMB2ErrorContextReponse packet, unpack the
                # data as usual
                data = response.unpack(data)
            else:
                # Working with an older SMB dialect where the response is set directly in the error_data field, need to
                # manually craft the SMB2ErrorContextResponse with the data returned.
                response['error_context_data'] = data
                data = b""

            context_responses.append(response)

        return context_responses


class SMB2ErrorContextResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.2.1 SMB2 ERROR Context Response
    For the SMB dialect 3.1.1, the server formats the error data as an array of
    SMB2 Error Context structures in the SMB2ErrorResponse message.

    """

    def __init__(self):
        self.fields = OrderedDict([
            ('error_data_length', IntField(
                size=4,
                default=lambda s: len(s['error_context_data']),
            )),
            ('error_id', EnumField(
                size=4,
                default=ErrorContextId.SMB2_ERROR_ID_DEFAULT,
                enum_type=ErrorContextId,
            )),
            ('error_context_data', BytesField(
                size=lambda s: s['error_data_length'].get_value(),
            )),
        ])
        super(SMB2ErrorContextResponse, self).__init__()


class SMB2SymbolicLinkErrorResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.2.2.1 Symbolic Link Error Response
    The Symbolic Link Error Response is used to indicate that a symbolic link
    was encountered on the create. It describes the target path that the client
    MUST use if it requires to follow the symbolic link.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('symlink_length', IntField(
                size=4,
                default=lambda s: len(s) - 4
            )),
            ('symlink_error_tag', BytesField(
                size=4,
                default=b"\x53\x59\x4d\x4c"
            )),
            ('reparse_tag', BytesField(
                size=4,
                default=b"\x0c\x00\x00\xa0"
            )),
            ('reparse_data_length', IntField(
                size=2,
                default=lambda s: len(s['path_buffer']) + 12
            )),
            # the len in utf-16-le bytes of the path beyond the substitute name
            # of the original target, e.g. \\server\share\symlink\file.txt
            # would be length of \file.txt in utf-16-le form, this is used by
            # the client to find out what part of the original path to append
            # to the substitute name returned by the server.
            ('unparsed_path_length', IntField(size=2)),
            ('substitute_name_offset', IntField(size=2)),
            ('substitute_name_length', IntField(size=2)),
            ('print_name_offset', IntField(size=2)),
            ('print_name_length', IntField(size=2)),
            ('flags', EnumField(
                size=2,
                enum_type=SymbolicLinkErrorFlags,
            )),
            # Not in the spec but Windows seems to add \x00\x80 to the end of flags which breaks our parsing. Cannot
            # seem to figure out why but this just ignored that field.
            ('reserved', IntField(size=2)),
            # use the get/set_name functions to get/set these values as they
            # also (d)encode the text and set the length and offset accordingly
            ('path_buffer', BytesField(
                size=lambda s: self._get_name_length(s, True)
            ))
        ])
        super(SMB2SymbolicLinkErrorResponse, self).__init__()

    def _get_name_length(self, structure, first):
        print_name_len = structure['print_name_length'].get_value()
        sub_name_len = structure['substitute_name_length'].get_value()
        return print_name_len + sub_name_len

    def set_name(self, print_name, substitute_name):
        """
        Set's the path_buffer and print/substitute name length of the message
        with the values passed in. These values should be a string and not a
        byte string as it is encoded in this function.

        :param print_name: The print name string to set
        :param substitute_name: The substitute name string to set
        """
        # Ensure that the to_bytes input is an actual text string for py2 compat with native strings.
        print_bytes = to_bytes(to_text(print_name), encoding='utf-16-le')
        sub_bytes = to_bytes(to_text(substitute_name), encoding='utf-16-le')
        path_buffer = print_bytes + sub_bytes

        self['print_name_offset'].set_value(0)
        self['print_name_length'].set_value(len(print_bytes))
        self['substitute_name_offset'].set_value(len(print_bytes))
        self['substitute_name_length'].set_value(len(sub_bytes))
        self['path_buffer'].set_value(path_buffer)

    def get_print_name(self):
        offset = self['print_name_offset'].get_value()
        length = self['print_name_length'].get_value()
        name_bytes = self['path_buffer'].get_value()[offset:offset + length]
        return to_text(name_bytes, encoding='utf-16-le')

    def get_substitute_name(self):
        offset = self['substitute_name_offset'].get_value()
        length = self['substitute_name_length'].get_value()
        name_bytes = self['path_buffer'].get_value()[offset:offset + length]
        return to_text(name_bytes, encoding='utf-16-le')

    def resolve_path(self, link_path):
        """
        [MS-SMB2] 2.2.2.2.1.1 Handling the Symbolic Link Error Response
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a8da655c-8b0b-415a-b726-16dc33fa5827

        Attempts to resolve the link target path. Will fail if the link is pointing to a local path or a UNC path
        on another host or share.

        :param link_path: The original path to the symbolic link to resolve relative paths from.
        :return: The resolved link target path.
        """
        substitute_name = self.get_substitute_name()
        print_name = self.get_print_name()
        unparsed_path_length = self['unparsed_path_length'].get_value()

        b_link_path = to_bytes(to_text(link_path), encoding='utf-16-le')
        unparsed_idx = len(b_link_path) - unparsed_path_length
        base_link_path = to_text(b_link_path[:unparsed_idx], encoding='utf-16-le')
        unparsed_path = to_text(b_link_path[unparsed_idx:], encoding='utf-16-le')

        # Use the common code in SymbolicLinkReparseDataBuffer() to resolve the link target.
        symlink_buffer = SymbolicLinkReparseDataBuffer()
        symlink_buffer['flags'] = self['flags'].get_value()
        symlink_buffer.set_name(substitute_name, print_name)
        target_path = symlink_buffer.resolve_link(base_link_path) + unparsed_path

        if not target_path.startswith('\\\\'):
            raise SMBLinkRedirectionError("Cannot resolve link targets that point to a local path", link_path,
                                          print_name)

        link_share = ntpath.splitdrive(link_path)[0]
        target_share = ntpath.splitdrive(target_path)[0]
        if link_share != target_share:
            raise SMBLinkRedirectionError("Cannot resolve link targets that point to a different host/share",
                                          link_path, print_name)

        return target_path


class SMB2ShareRedirectErrorContext(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.2.2.2 Share Redirect Error Context Response
    Response to a Tree Connect with the
    SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER flag set.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=4,
                default=lambda s: len(s)
            )),
            ('notification_type', IntField(
                size=4,
                default=3
            )),
            ('resource_name_offset', IntField(
                size=4,
                default=lambda s: self._resource_name_offset(s)
            )),
            ('resource_name_length', IntField(
                size=4,
                default=lambda s: len(s['resource_name'])
            )),
            ('flags', IntField(
                size=2,
                default=0
            )),
            ('target_type', IntField(
                size=2,
                default=0
            )),
            ('ip_addr_count', IntField(
                size=4,
                default=lambda s: len(s['ip_addr_move_list'].get_value())
            )),
            ('ip_addr_move_list', ListField(
                size=lambda s: s['ip_addr_count'].get_value() * 24,
                list_count=lambda s: s['ip_addr_count'].get_value(),
                list_type=StructureField(
                    size=24,
                    structure_type=SMB2MoveDstIpAddrStructure
                )
            )),
            ('resource_name', BytesField(
                size=lambda s: s['resource_name_length'].get_value()
            ))
        ])
        super(SMB2ShareRedirectErrorContext, self).__init__()

    def _resource_name_offset(self, structure):
        min_structure_size = 24
        addr_list_size = len(structure['ip_addr_move_list'])
        return min_structure_size + addr_list_size


class SMB2MoveDstIpAddrStructure(Structure):
    """
    [MS-SMB2] c53.0 2017-09-15

    2.2.2.2.2.1 MOVE_DST_IPADDR structure
    Used to indicate the destination IP address.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('type', EnumField(
                size=4,
                enum_type=IpAddrType
            )),
            ('reserved', IntField(size=4)),
            ('ip_address', BytesField(
                size=lambda s: self._ip_address_size(s)
            )),
            ('reserved2', BytesField(
                size=lambda s: self._reserved2_size(s),
                default=lambda s: b"\x00" * self._reserved2_size(s)
            ))
        ])
        super(SMB2MoveDstIpAddrStructure, self).__init__()

    def _ip_address_size(self, structure):
        if structure['type'].get_value() == IpAddrType.MOVE_DST_IPADDR_V4:
            return 4
        else:
            return 16

    def _reserved2_size(self, structure):
        if structure['type'].get_value() == IpAddrType.MOVE_DST_IPADDR_V4:
            return 12
        else:
            return 0

    def get_ipaddress(self):
        # get's the IP address in a human readable format
        ip_address = self['ip_address'].get_value()
        if self['type'].get_value() == IpAddrType.MOVE_DST_IPADDR_V4:
            return socket.inet_ntoa(ip_address)
        else:
            addr = binascii.hexlify(ip_address).decode('utf-8')
            return ":".join([addr[i:i + 4] for i in range(0, len(addr), 4)])

    def set_ipaddress(self, address):
        # set's the IP address from a human readable format, for IPv6, this
        # needs to be the full IPv6 address
        if self['type'].get_value() == IpAddrType.MOVE_DST_IPADDR_V4:
            self['ip_address'].set_value(socket.inet_aton(address))
        else:
            addr = address.replace(":", "")
            if len(addr) != 32:
                raise ValueError("When setting an IPv6 address, it must be in "
                                 "the full form without concatenation")
            self['ip_address'].set_value(binascii.unhexlify(addr))
