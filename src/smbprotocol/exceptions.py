# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import binascii
import errno
import ntpath
import os
import socket
from collections import OrderedDict
from typing import Any

from smbprotocol import Dialects
from smbprotocol._text import to_bytes, to_text
from smbprotocol.header import NtStatus, SMB2HeaderResponse
from smbprotocol.reparse_point import SymbolicLinkReparseDataBuffer
from smbprotocol.structure import (
    BytesField,
    EnumField,
    IntField,
    ListField,
    Structure,
    StructureField,
)


class SMBException(Exception):
    # Generic SMB Exception with a message
    pass


class SMBAuthenticationError(SMBException):
    # Used for authentication specific errors
    pass


class SMBConnectionClosed(SMBException):
    # Used to denote the underlying TCP transport has been closed.
    pass


class SMBOSError(OSError, SMBException):
    """Wrapper for OSError with smbprotocol specific details.

    This is a wrapper for OSError for use in smbclient. It is designed to translate the raw SMBResponseException that
    smbprotocol raises into an error that is compatible with OSError.
    """

    def __init__(self, ntstatus, filename, filename2=None):
        self.ntstatus = ntstatus
        self.filename2 = os.fspath(filename2) if filename2 else None

        ntstatus_name = "STATUS_UNKNOWN"
        for name, val in vars(NtStatus).items():
            if ntstatus == val:
                ntstatus_name = name
                break

        error_details = {
            NtStatus.STATUS_OBJECT_NAME_NOT_FOUND: errno.ENOENT,
            NtStatus.STATUS_OBJECT_PATH_NOT_FOUND: errno.ENOENT,
            NtStatus.STATUS_NOT_FOUND: errno.ENOENT,
            NtStatus.STATUS_OBJECT_NAME_COLLISION: errno.EEXIST,
            NtStatus.STATUS_PRIVILEGE_NOT_HELD: (errno.EACCES, "Required privilege not held"),
            NtStatus.STATUS_SHARING_VIOLATION: (
                errno.EPERM,
                "The process cannot access the file because it is being used by another process",
            ),
            NtStatus.STATUS_NOT_A_REPARSE_POINT: (errno.EINVAL, "The file or directory is not a reparse point"),
            NtStatus.STATUS_FILE_IS_A_DIRECTORY: errno.EISDIR,
            NtStatus.STATUS_NOT_A_DIRECTORY: errno.ENOTDIR,
            NtStatus.STATUS_DIRECTORY_NOT_EMPTY: errno.ENOTEMPTY,
            NtStatus.STATUS_END_OF_FILE: getattr(errno, "ENODATA", 120),  # Not present on py2 for Windows.
        }.get(ntstatus, (0, f"Unknown NtStatus error returned '{ntstatus_name}'"))

        if not isinstance(error_details, tuple):
            error_details = (error_details, os.strerror(error_details))

        super().__init__(error_details[0], error_details[1], os.fspath(filename))

    def __str__(self):
        status = format(self.ntstatus, "x").zfill(8)
        msg = f"[Error {self.errno}] [NtStatus 0x{status}] {self.strerror}: '{self.filename}'"
        if self.filename2:
            msg += f" -> '{self.filename2}'"

        return msg


class SMBLinkRedirectionError(SMBException):
    @property
    def message(self):
        msg = (
            f"Encountered symlink at '{self.path}' that points to "
            f"'{self.target}' which cannot be redirected: {self.args[0]}"
        )
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

        msg = (
            f"{self.feature_name} is not available on the negotiated dialect {negotiated_dialect}, "
            f"requires dialect {required_dialect}{msg_suffix}"
        )
        return msg

    def __str__(self):
        return self.message

    def _get_dialect_name(self, dialect):
        dialect_field = EnumField(enum_type=Dialects, enum_strict=False, size=2)
        dialect_field.set_value(dialect)
        return str(dialect_field)


class _SMBErrorRegistry(type):
    __registry = {}

    def __init__(cls, name, bases, attributes):
        super().__init__(name, bases, attributes)

        # Special case for the base SMBResponseException doesn't need to have _STATUS_CODE
        if cls.__module__ == _SMBErrorRegistry.__module__ and cls.__name__ == "SMBResponseException":
            return

        if not hasattr(cls, "_STATUS_CODE"):
            raise ValueError(f"{cls.__module__}.{cls.__name__} does not have the _STATUS_CODE class attribute set")

        cls.__registry[cls._STATUS_CODE] = cls

    def __call__(cls, header=None):
        # intercept construction of new SMBResponseException (and derived) instances
        if header:
            new_cls = cls.__registry.get(header["status"].get_value(), cls)

        else:
            header = SMB2HeaderResponse()
            header["status"] = cls._STATUS_CODE
            header["data"] = SMB2ErrorResponse()
            new_cls = cls

        # now use type.__call__ directly to actually construct instance
        return type.__call__(new_cls, header)


class SMBResponseException(SMBException, metaclass=_SMBErrorRegistry):
    """Base SMB response status exception.

    This is the base exception that is used when processing the status of an SMB response received from the server.
    When being called it may create one of the inherited types depending on whether the status is known or not. Each
    inherited class must implement _STATUS_CODE representing the NtStatus error it is for and may implement
    _BASE_MESSAGE to provide a better explanation of the error.
    """

    _BASE_MESSAGE = "Unknown error."

    def __init__(self, header: SMB2HeaderResponse):
        self.header = header

    @property
    def error_details(self) -> list[Any]:
        # list of error_details returned by the server, currently used in
        # the SMB 3.1.1 error response for certain situations
        error = SMB2ErrorResponse()
        error.unpack(self.header["data"].get_value())

        error_details = []
        for raw_error_data in error["error_data"].get_value():
            error_id = raw_error_data["error_id"].get_value()
            raw_data = raw_error_data["error_context_data"].get_value()
            if self.status == NtStatus.STATUS_STOPPED_ON_SYMLINK:
                error_data = SMB2SymbolicLinkErrorResponse()
                error_data.unpack(raw_data)

            elif (
                self.status == NtStatus.STATUS_BAD_NETWORK_NAME
                and error_id == ErrorContextId.SMB2_ERROR_ID_SHARE_REDIRECT
            ):
                error_data = SMB2ShareRedirectErrorContext()
                error_data.unpack(raw_data)

            else:
                # unknown context data so we just set it the raw bytes
                error_data = raw_data

            error_details.append(error_data)

        return error_details

    @property
    def message(self) -> str:
        error_details = []

        for detail in self.error_details:
            if isinstance(detail, SMB2SymbolicLinkErrorResponse):
                flag = str(detail["flags"])
                print_name = detail.get_print_name()
                sub_name = detail.get_substitute_name()
                error_details.append(f"Flag: {flag}, Print Name: {print_name}, Substitute Name: {sub_name}")

            elif isinstance(detail, SMB2ShareRedirectErrorContext):
                ip_addresses = []
                for ip_addr in detail["ip_addr_move_list"].get_value():
                    ip_addresses.append(ip_addr.get_ipaddress())

                resource_name = to_text(detail["resource_name"].get_value(), encoding="utf-16-le")
                addresses = "', '".join(ip_addresses)
                error_details.append(f"IP Addresses: '{addresses}', Resource Name: {resource_name}")

            else:
                # unknown error details in response, output raw bytes
                error_details.append("Raw: " + to_text(binascii.hexlify(detail)))

        status = format(self.status, "x").zfill(8)
        error_msg = f"{self._BASE_MESSAGE} {self.header['status']}: 0x{status}"
        if error_details:
            error_msg += " - " + (", ".join(error_details))

        return f"Received unexpected status from the server: {error_msg}"

    @property
    def status(self):
        return self.header["status"].get_value()

    def __str__(self):
        return self.message


class Unsuccessful(SMBResponseException):
    _BASE_MESSAGE = "The requested operation was unsuccessful."
    _STATUS_CODE = NtStatus.STATUS_UNSUCCESSFUL


class NetworkNameDelegated(SMBResponseException):
    _BASE_MESSAGE = "The network name was deleted."
    _STATUS_CODE = NtStatus.STATUS_NETWORK_NAME_DELETED


class StatusPending(SMBResponseException):
    _BASE_MESSAGE = "The operation that was requested is pending completion."
    _STATUS_CODE = NtStatus.STATUS_PENDING


class NotifyCleanup(SMBResponseException):
    _BASE_MESSAGE = (
        "Indicates that a notify change request has been completed due to closing the handle that made "
        "the notify change request."
    )
    _STATUS_CODE = NtStatus.STATUS_NOTIFY_CLEANUP


class NotifyEnumDir(SMBResponseException):
    _BASE_MESSAGE = (
        "Indicates that a notify change request is being completed and that the information is not "
        "being returned in the caller's buffer. The caller now needs to enumerate the files to find "
        "the changes."
    )
    _STATUS_CODE = NtStatus.STATUS_NOTIFY_ENUM_DIR


class BufferOverflow(SMBResponseException):
    _BASE_MESSAGE = "The data was too large to fit into the specified buffer."
    _STATUS_CODE = NtStatus.STATUS_BUFFER_OVERFLOW


class NoMoreFiles(SMBResponseException):
    _BASE_MESSAGE = "No more files were found which match the file specification."
    _STATUS_CODE = NtStatus.STATUS_NO_MORE_FILES


class EndOfFile(SMBResponseException):
    _BASE_MESSAGE = "The end-of-file marker has been reached. There is no valid data in the file beyond this marker."
    _STATUS_CODE = NtStatus.STATUS_END_OF_FILE


class InvalidEAName(SMBResponseException):
    _BASE_MESSAGE = "The specified extended attribute (EA) name contains at least one illegal character."
    _STATUS_CODE = NtStatus.STATUS_INVALID_EA_NAME


class EAListInconsistent(SMBResponseException):
    _BASE_MESSAGE = "The extended attribute (EA) list is inconsistent."
    _STATUS_CODE = NtStatus.STATUS_EA_LIST_INCONSISTENT


class StoppedOnSymlink(SMBResponseException):
    _BASE_MESSAGE = "The create operation stopped after reaching a symbolic link."
    _STATUS_CODE = NtStatus.STATUS_STOPPED_ON_SYMLINK


class InvalidInfoClass(SMBResponseException):
    _BASE_MESSAGE = "The specified information class is not a valid information class for the specified object."
    _STATUS_CODE = NtStatus.STATUS_INVALID_INFO_CLASS


class InfoLengthMismatch(SMBResponseException):
    _BASE_MESSAGE = (
        "The specified information record length does not match the length that is required for the "
        "specified information class."
    )
    _STATUS_CODE = NtStatus.STATUS_INFO_LENGTH_MISMATCH


class InvalidParameter(SMBResponseException):
    _BASE_MESSAGE = "An invalid parameter was passed to a service or function."
    _STATUS_CODE = NtStatus.STATUS_INVALID_PARAMETER


class NoSuchFile(SMBResponseException):
    _BASE_MESSAGE = "The file does not exist."
    _STATUS_CODE = NtStatus.STATUS_NO_SUCH_FILE


class InvalidDeviceRequest(SMBResponseException):
    _BASE_MESSAGE = "The specified request is not a valid operation for the target device."
    _STATUS_CODE = NtStatus.STATUS_INVALID_DEVICE_REQUEST


class MoreProcessingRequired(SMBResponseException):
    _BASE_MESSAGE = (
        "The specified I/O request packet (IRP) cannot be disposed of because the I/O operation is not complete."
    )
    _STATUS_CODE = NtStatus.STATUS_MORE_PROCESSING_REQUIRED


class AccessDenied(SMBResponseException):
    _BASE_MESSAGE = "A process has requested access to an object but has not been granted those access rights."
    _STATUS_CODE = NtStatus.STATUS_ACCESS_DENIED


class BufferTooSmall(SMBResponseException):
    _BASE_MESSAGE = "The buffer is too small to contain the entry. No information has been written to the buffer."
    _STATUS_CODE = NtStatus.STATUS_BUFFER_TOO_SMALL


class ObjectNameInvalid(SMBResponseException):
    _BASE_MESSAGE = "The object name is invalid."
    _STATUS_CODE = NtStatus.STATUS_OBJECT_NAME_INVALID


class ObjectNameNotFound(SMBResponseException):
    _BASE_MESSAGE = "The object name is not found."
    _STATUS_CODE = NtStatus.STATUS_OBJECT_NAME_NOT_FOUND


class ObjectNameCollision(SMBResponseException):
    _BASE_MESSAGE = "The object name already exists."
    _STATUS_CODE = NtStatus.STATUS_OBJECT_NAME_COLLISION


class ObjectPathInvalid(SMBResponseException):
    _BASE_MESSAGE = "The object path component was not a directory object."
    _STATUS_CODE = NtStatus.STATUS_OBJECT_PATH_INVALID


class ObjectPathNotFound(SMBResponseException):
    _BASE_MESSAGE = "The path does not exist."
    _STATUS_CODE = NtStatus.STATUS_OBJECT_PATH_NOT_FOUND


class ObjectPathSyntaxBad(SMBResponseException):
    _BASE_MESSAGE = "The object path component was not a directory object."
    _STATUS_CODE = NtStatus.STATUS_OBJECT_PATH_SYNTAX_BAD


class SharingViolation(SMBResponseException):
    _BASE_MESSAGE = "A file cannot be opened because the share access flags are incompatible."
    _STATUS_CODE = NtStatus.STATUS_SHARING_VIOLATION


class EASNotSupported(SMBResponseException):
    _BASE_MESSAGE = "An operation involving EAs failed because the file system does not support EAs."
    _STATUS_CODE = NtStatus.STATUS_EAS_NOT_SUPPORTED


class EATooLarge(SMBResponseException):
    _BASE_MESSAGE = "An EA operation failed because the EA set is too large."
    _STATUS_CODE = NtStatus.STATUS_EA_TOO_LARGE


class NonExistentEAEntry(SMBResponseException):
    _BASE_MESSAGE = "An EA operation failed because the name or EA index is invalid."
    _STATUS_CODE = NtStatus.STATUS_NONEXISTENT_EA_ENTRY


class NoEASOnFile(SMBResponseException):
    _BASE_MESSAGE = "The file for which EAs were requested has no EAs."
    _STATUS_CODE = NtStatus.STATUS_NO_EAS_ON_FILE


class EACorruptError(SMBResponseException):
    _BASE_MESSAGE = "The EA is corrupt and cannot be read."
    _STATUS_CODE = NtStatus.STATUS_EA_CORRUPT_ERROR


class DeletePending(SMBResponseException):
    _BASE_MESSAGE = "A non-close operation has been requested of a file object that has a delete pending."
    _STATUS_CODE = NtStatus.STATUS_DELETE_PENDING


class PrivilegeNotHeld(SMBResponseException):
    _BASE_MESSAGE = "A required privilege is not held by the client."
    _STATUS_CODE = NtStatus.STATUS_PRIVILEGE_NOT_HELD


class WrongPassword(SMBResponseException):
    _BASE_MESSAGE = "The specified password is not correct or the user is locked out."
    _STATUS_CODE = NtStatus.STATUS_WRONG_PASSWORD


class LogonFailure(SMBResponseException):
    _BASE_MESSAGE = (
        "The attempted logon is invalid. This is either due to a bad username or authentication information."
    )
    _STATUS_CODE = NtStatus.STATUS_LOGON_FAILURE


class PasswordExpired(SMBResponseException):
    _BASE_MESSAGE = "The user account password has expired."
    _STATUS_CODE = NtStatus.STATUS_PASSWORD_EXPIRED


class NoneMapped(SMBResponseException):
    _BASE_MESSAGE = "None of the information to be translated has been translated."
    _STATUS_CODE = NtStatus.STATUS_NONE_MAPPED


class InsufficientResources(SMBResponseException):
    _BASE_MESSAGE = "Insufficient system resources exist to complete the API."
    _STATUS_CODE = NtStatus.STATUS_INSUFFICIENT_RESOURCES


class PipeNotAvailable(SMBResponseException):
    _BASE_MESSAGE = "An instance of a named pipe cannot be found in the listening state."
    _STATUS_CODE = NtStatus.STATUS_PIPE_NOT_AVAILABLE


class PipeBusy(SMBResponseException):
    _BASE_MESSAGE = (
        "The specified pipe is set to complete operations and there are current I/O operations queued "
        "so that it cannot be changed to queue operations."
    )
    _STATUS_CODE = NtStatus.STATUS_PIPE_BUSY


class PipeClosing(SMBResponseException):
    _BASE_MESSAGE = "The specified named pipe is in the closing state."
    _STATUS_CODE = NtStatus.STATUS_PIPE_CLOSING


class IOTimeout(SMBResponseException):
    _BASE_MESSAGE = "The specified I/O operation was not completed before the time-out period expired."
    _STATUS_CODE = NtStatus.STATUS_IO_TIMEOUT


class PipeDisconnected(SMBResponseException):
    _BASE_MESSAGE = "The specified named pipe is in the disconnected state."
    _STATUS_CODE = NtStatus.STATUS_PIPE_DISCONNECTED


class FileIsADirectory(SMBResponseException):
    _BASE_MESSAGE = (
        "The file that was specified as a target is a directory, and the caller specified that it could "
        "be anything but a directory."
    )
    _STATUS_CODE = NtStatus.STATUS_FILE_IS_A_DIRECTORY


class NotSupported(SMBResponseException):
    _BASE_MESSAGE = "The request is not supported."
    _STATUS_CODE = NtStatus.STATUS_NOT_SUPPORTED


class BadNetworkName(SMBResponseException):
    _BASE_MESSAGE = "The specified share name cannot be found on the remote server."
    _STATUS_CODE = NtStatus.STATUS_BAD_NETWORK_NAME


class RequestNotAccepted(SMBResponseException):
    _BASE_MESSAGE = (
        "No more connections can be made to this remote computer at this time because the computer has "
        "already accepted the maximum number of connections."
    )
    _STATUS_CODE = NtStatus.STATUS_REQUEST_NOT_ACCEPTED


class PipeEmpty(SMBResponseException):
    _BASE_MESSAGE = "Used to indicate that a read operation was done on an empty pipe."
    _STATUS_CODE = NtStatus.STATUS_PIPE_EMPTY


class InternalError(SMBResponseException):
    _BASE_MESSAGE = "An internal error occurred."
    _STATUS_CODE = NtStatus.STATUS_INTERNAL_ERROR


class DirectoryNotEmpty(SMBResponseException):
    _BASE_MESSAGE = "Indicates that the directory trying to be deleted is not empty."
    _STATUS_CODE = NtStatus.STATUS_DIRECTORY_NOT_EMPTY


class StatusNotADirectory(SMBResponseException):
    _BASE_MESSAGE = "A requested opened file is not a directory."
    _STATUS_CODE = NtStatus.STATUS_NOT_A_DIRECTORY


class Cancelled(SMBResponseException):
    _BASE_MESSAGE = "The I/O request was canceled."
    _STATUS_CODE = NtStatus.STATUS_CANCELLED


class CannotDelete(SMBResponseException):
    _BASE_MESSAGE = "An attempt has been made to remove a file or directory that cannot be deleted."
    _STATUS_CODE = NtStatus.STATUS_CANNOT_DELETE


class FileClosed(SMBResponseException):
    _BASE_MESSAGE = (
        "An I/O request other than close and several other special case operations was attempted using "
        "a file object that had already been closed."
    )
    _STATUS_CODE = NtStatus.STATUS_FILE_CLOSED


class PipeBroken(SMBResponseException):
    _BASE_MESSAGE = "The pipe operation has failed because the other end of the pipe has been closed."
    _STATUS_CODE = NtStatus.STATUS_PIPE_BROKEN


class FSDriverRequired(SMBResponseException):
    _BASE_MESSAGE = (
        "A volume has been accessed for which a file system driver is required that has not yet been loaded."
    )
    _STATUS_CODE = NtStatus.STATUS_FS_DRIVER_REQUIRED


class UserSessionDeleted(SMBResponseException):
    _BASE_MESSAGE = "The remote user session has been deleted."
    _STATUS_CODE = NtStatus.STATUS_USER_SESSION_DELETED


class InsuffServerResources(SMBResponseException):
    _BASE_MESSAGE = "Insufficient server resources exist to complete the request."
    _STATUS_CODE = NtStatus.STATUS_INSUFF_SERVER_RESOURCES


class NotFound(SMBResponseException):
    _BASE_MESSAGE = "The object was not found."
    _STATUS_CODE = NtStatus.STATUS_NOT_FOUND


class PathNotCovered(SMBResponseException):
    _BASE_MESSAGE = "The contacted server does not support the indicated part of the DFS namespace."
    _STATUS_CODE = NtStatus.STATUS_PATH_NOT_COVERED


class DfsUnavailable(SMBResponseException):
    _BASE_MESSAGE = "DFS is unavailable on the contacted server."
    _STATUS_CODE = NtStatus.STATUS_DFS_UNAVAILABLE


class NotAReparsePoint(SMBResponseException):
    _BASE_MESSAGE = "The NTFS file or directory is not a reparse point."
    _STATUS_CODE = NtStatus.STATUS_NOT_A_REPARSE_POINT


class ServerUnavailable(SMBResponseException):
    _BASE_MESSAGE = "The file server is temporarily unavailable."
    _STATUS_CODE = NtStatus.STATUS_SERVER_UNAVAILABLE


class ErrorContextId:
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.2.1 SMB2 Error Context Response ErrorId
    An identifier for the error context, it MUST be set to one of the following
    values.
    """

    SMB2_ERROR_ID_DEFAULT = 0x00000000
    SMB2_ERROR_ID_SHARE_REDIRECT = 0x53526472


class SymbolicLinkErrorFlags:
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.2.2.1 Symbolic Link Error Response Flags
    Specifies whether the substitute name is an absolute target path or a path
    name relative to the directory containing the symbolic link
    """

    SYMLINK_FLAG_ABSOLUTE = 0x00000000
    SYMLINK_FLAG_RELATIVE = 0x00000001


class IpAddrType:
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
        self.fields = OrderedDict(
            [
                (
                    "structure_size",
                    IntField(
                        size=2,
                        default=9,
                    ),
                ),
                (
                    "error_context_count",
                    IntField(
                        size=1,
                        default=lambda s: len(s["error_data"].get_value()),
                    ),
                ),
                ("reserved", IntField(size=1)),
                (
                    "byte_count",
                    IntField(
                        size=4,
                        default=lambda s: len(s["error_data"]),
                    ),
                ),
                (
                    "error_data",
                    ListField(
                        size=lambda s: s["byte_count"].get_value(),
                        list_count=lambda s: s["error_context_count"].get_value(),
                        list_type=StructureField(structure_type=SMB2ErrorContextResponse),
                        unpack_func=lambda s, d: self._error_data_value(s, d),
                    ),
                ),
            ]
        )
        super().__init__()

    def _error_data_value(self, structure, data):
        context_responses = []

        while len(data) > 0:
            response = SMB2ErrorContextResponse()
            if structure["error_context_count"].get_value() > 0:
                # Working with SMB 3.1.1+ where the errors are already in an SMB2ErrorContextReponse packet, unpack the
                # data as usual
                data = response.unpack(data)
            else:
                # Working with an older SMB dialect where the response is set directly in the error_data field, need to
                # manually craft the SMB2ErrorContextResponse with the data returned.
                response["error_context_data"] = data
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
        self.fields = OrderedDict(
            [
                (
                    "error_data_length",
                    IntField(
                        size=4,
                        default=lambda s: len(s["error_context_data"]),
                    ),
                ),
                (
                    "error_id",
                    EnumField(
                        size=4,
                        default=ErrorContextId.SMB2_ERROR_ID_DEFAULT,
                        enum_type=ErrorContextId,
                    ),
                ),
                (
                    "error_context_data",
                    BytesField(
                        size=lambda s: s["error_data_length"].get_value(),
                    ),
                ),
            ]
        )
        super().__init__()


class SMB2SymbolicLinkErrorResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.2.2.1 Symbolic Link Error Response
    The Symbolic Link Error Response is used to indicate that a symbolic link
    was encountered on the create. It describes the target path that the client
    MUST use if it requires to follow the symbolic link.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("symlink_length", IntField(size=4, default=lambda s: len(s) - 4)),
                ("symlink_error_tag", BytesField(size=4, default=b"\x53\x59\x4d\x4c")),
                ("reparse_tag", BytesField(size=4, default=b"\x0c\x00\x00\xa0")),
                ("reparse_data_length", IntField(size=2, default=lambda s: len(s["path_buffer"]) + 12)),
                # the len in utf-16-le bytes of the path beyond the substitute name
                # of the original target, e.g. \\server\share\symlink\file.txt
                # would be length of \file.txt in utf-16-le form, this is used by
                # the client to find out what part of the original path to append
                # to the substitute name returned by the server.
                ("unparsed_path_length", IntField(size=2)),
                ("substitute_name_offset", IntField(size=2)),
                ("substitute_name_length", IntField(size=2)),
                ("print_name_offset", IntField(size=2)),
                ("print_name_length", IntField(size=2)),
                (
                    "flags",
                    EnumField(
                        size=2,
                        enum_type=SymbolicLinkErrorFlags,
                    ),
                ),
                # Not in the spec but Windows seems to add \x00\x80 to the end of flags which breaks our parsing. Cannot
                # seem to figure out why but this just ignored that field.
                ("reserved", IntField(size=2)),
                # use the get/set_name functions to get/set these values as they
                # also (d)encode the text and set the length and offset accordingly
                ("path_buffer", BytesField(size=lambda s: self._get_name_length(s, True))),
            ]
        )
        super().__init__()

    def _get_name_length(self, structure, first):
        print_name_len = structure["print_name_length"].get_value()
        sub_name_len = structure["substitute_name_length"].get_value()
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
        print_bytes = to_bytes(to_text(print_name), encoding="utf-16-le")
        sub_bytes = to_bytes(to_text(substitute_name), encoding="utf-16-le")
        path_buffer = print_bytes + sub_bytes

        self["print_name_offset"].set_value(0)
        self["print_name_length"].set_value(len(print_bytes))
        self["substitute_name_offset"].set_value(len(print_bytes))
        self["substitute_name_length"].set_value(len(sub_bytes))
        self["path_buffer"].set_value(path_buffer)

    def get_print_name(self):
        offset = self["print_name_offset"].get_value()
        length = self["print_name_length"].get_value()
        name_bytes = self["path_buffer"].get_value()[offset : offset + length]
        return to_text(name_bytes, encoding="utf-16-le")

    def get_substitute_name(self):
        offset = self["substitute_name_offset"].get_value()
        length = self["substitute_name_length"].get_value()
        name_bytes = self["path_buffer"].get_value()[offset : offset + length]
        return to_text(name_bytes, encoding="utf-16-le")

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
        unparsed_path_length = self["unparsed_path_length"].get_value()

        b_link_path = to_bytes(to_text(link_path), encoding="utf-16-le")
        unparsed_idx = len(b_link_path) - unparsed_path_length
        base_link_path = to_text(b_link_path[:unparsed_idx], encoding="utf-16-le")
        unparsed_path = to_text(b_link_path[unparsed_idx:], encoding="utf-16-le")

        # Use the common code in SymbolicLinkReparseDataBuffer() to resolve the link target.
        symlink_buffer = SymbolicLinkReparseDataBuffer()
        symlink_buffer["flags"] = self["flags"].get_value()
        symlink_buffer.set_name(substitute_name, print_name)
        target_path = symlink_buffer.resolve_link(base_link_path) + unparsed_path

        if not target_path.startswith("\\\\"):
            raise SMBLinkRedirectionError(
                "Cannot resolve link targets that point to a local path", link_path, print_name
            )

        link_share = ntpath.splitdrive(link_path)[0]
        target_share = ntpath.splitdrive(target_path)[0]
        if link_share != target_share:
            raise SMBLinkRedirectionError(
                "Cannot resolve link targets that point to a different host/share", link_path, print_name
            )

        return target_path


class SMB2ShareRedirectErrorContext(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.2.2.2 Share Redirect Error Context Response
    Response to a Tree Connect with the
    SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER flag set.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("structure_size", IntField(size=4, default=lambda s: len(s))),
                ("notification_type", IntField(size=4, default=3)),
                ("resource_name_offset", IntField(size=4, default=lambda s: self._resource_name_offset(s))),
                ("resource_name_length", IntField(size=4, default=lambda s: len(s["resource_name"]))),
                ("flags", IntField(size=2, default=0)),
                ("target_type", IntField(size=2, default=0)),
                ("ip_addr_count", IntField(size=4, default=lambda s: len(s["ip_addr_move_list"].get_value()))),
                (
                    "ip_addr_move_list",
                    ListField(
                        size=lambda s: s["ip_addr_count"].get_value() * 24,
                        list_count=lambda s: s["ip_addr_count"].get_value(),
                        list_type=StructureField(size=24, structure_type=SMB2MoveDstIpAddrStructure),
                    ),
                ),
                ("resource_name", BytesField(size=lambda s: s["resource_name_length"].get_value())),
            ]
        )
        super().__init__()

    def _resource_name_offset(self, structure):
        min_structure_size = 24
        addr_list_size = len(structure["ip_addr_move_list"])
        return min_structure_size + addr_list_size


class SMB2MoveDstIpAddrStructure(Structure):
    """
    [MS-SMB2] c53.0 2017-09-15

    2.2.2.2.2.1 MOVE_DST_IPADDR structure
    Used to indicate the destination IP address.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("type", EnumField(size=4, enum_type=IpAddrType)),
                ("reserved", IntField(size=4)),
                ("ip_address", BytesField(size=lambda s: self._ip_address_size(s))),
                (
                    "reserved2",
                    BytesField(
                        size=lambda s: self._reserved2_size(s), default=lambda s: b"\x00" * self._reserved2_size(s)
                    ),
                ),
            ]
        )
        super().__init__()

    def _ip_address_size(self, structure):
        if structure["type"].get_value() == IpAddrType.MOVE_DST_IPADDR_V4:
            return 4
        else:
            return 16

    def _reserved2_size(self, structure):
        if structure["type"].get_value() == IpAddrType.MOVE_DST_IPADDR_V4:
            return 12
        else:
            return 0

    def get_ipaddress(self):
        # get's the IP address in a human readable format
        ip_address = self["ip_address"].get_value()
        if self["type"].get_value() == IpAddrType.MOVE_DST_IPADDR_V4:
            return socket.inet_ntoa(ip_address)
        else:
            addr = binascii.hexlify(ip_address).decode("utf-8")
            return ":".join([addr[i : i + 4] for i in range(0, len(addr), 4)])

    def set_ipaddress(self, address):
        # set's the IP address from a human readable format, for IPv6, this
        # needs to be the full IPv6 address
        if self["type"].get_value() == IpAddrType.MOVE_DST_IPADDR_V4:
            self["ip_address"].set_value(socket.inet_aton(address))
        else:
            addr = address.replace(":", "")
            if len(addr) != 32:
                raise ValueError("When setting an IPv6 address, it must be in the full form without concatenation")
            self["ip_address"].set_value(binascii.unhexlify(addr))
