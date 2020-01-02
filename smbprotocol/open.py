# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import logging

from collections import (
    OrderedDict,
)

from smbprotocol import (
    Commands,
    Dialects,
    MAX_PAYLOAD_SIZE,
)

from smbprotocol.create_contexts import (
    SMB2CreateContextRequest,
)

from smbprotocol.exceptions import (
    NtStatus,
    SMBException,
    SMBResponseException,
    SMBUnsupportedFeature,
)

from smbprotocol.file_info import (
    FileBothDirectoryInformation,
    FileDirectoryInformation,
    FileFullDirectoryInformation,
    FileFullEaInformation,
    FileIdBothDirectoryInformation,
    FileIdFullDirectoryInformation,
    FileNamesInformation,
    FileStreamInformation,
    InfoType,

    # While this shouldn't ever be removed, we need to keep this imported so we stay backwards compat. These were
    # originally defined here.
    FileAttributes,
    FileInformationClass,
)

from smbprotocol.structure import (
    BytesField,
    DateTimeField,
    EnumField,
    FlagField,
    IntField,
    ListField,
    Structure,
    StructureField,
)

log = logging.getLogger(__name__)


class RequestedOplockLevel(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.31 SMB2 CREATE Request RequestedOplockLevel
    The requested oplock level used when creating/accessing a file.
    """
    SMB2_OPLOCK_LEVEL_NONE = 0x00
    SMB2_OPLOCK_LEVEL_II = 0x01
    SMB2_OPLOCK_LEVEL_EXCLUSIVE = 0x08
    SMB2_OPLOCK_LEVEL_BATCH = 0x09
    SMB2_OPLOCK_LEVEL_LEASE = 0xFF


class ImpersonationLevel(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.31 SMB2 CREATE Request ImpersonationLevel
    The impersonation level requested by the application in a create request.
    """
    Anonymous = 0x0
    Identification = 0x1
    Impersonation = 0x2
    Delegate = 0x3


class ShareAccess(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.31 SMB2 CREATE Request ShareAccess
    The sharing mode for the open
    """
    FILE_SHARE_READ = 0x1
    FILE_SHARE_WRITE = 0x2
    FILE_SHARE_DELETE = 0x4


class CreateDisposition(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.31 SMB2 CREATE Request CreateDisposition
    Defines the action the server must take if the file that is specific
    already exists.
    """
    FILE_SUPERSEDE = 0x0
    FILE_OPEN = 0x1
    FILE_CREATE = 0x2
    FILE_OPEN_IF = 0x3
    FILE_OVERWRITE = 0x4
    FILE_OVERWRITE_IF = 0x5


class CreateOptions(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.31 SMB2 CREATE Request CreateOptions
    Specifies the options to be applied when creating or opening the file
    """
    FILE_DIRECTORY_FILE = 0x00000001
    FILE_WRITE_THROUGH = 0x00000002
    FILE_SEQUENTIAL_ONLY = 0x00000004
    FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008
    FILE_SYNCHRONOUS_IO_ALERT = 0x00000010
    FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
    FILE_NON_DIRECTORY_FILE = 0x00000040
    FILE_COMPLETE_IF_OPLOCKED = 0x00000100
    FILE_NO_EA_KNOWLEDGE = 0x00000200
    FILE_RANDOM_ACCESS = 0x00000800
    FILE_DELETE_ON_CLOSE = 0x00001000
    FILE_OPEN_BY_FILE_ID = 0x00002000
    FILE_OPEN_FOR_BACKUP_INTENT = 0x00004000
    FILE_NO_COMPRESSION = 0x00008000
    FILE_OPEN_REMOTE_INSTANCE = 0x00000400
    FILE_OPEN_REQUIRING_OPLOCK = 0x00010000
    FILE_DISALLOW_EXCLUSIVE = 0x00020000
    FILE_RESERVE_OPFILTER = 0x00100000
    FILE_OPEN_REPARSE_POINT = 0x00200000
    FILE_OPEN_NO_RECALL = 0x00400000
    FILE_OPEN_FOR_FREE_SPACE_QUERY = 0x00800000


class FilePipePrinterAccessMask(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.13.1.1 File_Pipe_Printer_Access_Mask
    Access Mask flag values to be used when accessing a file, pipe, or printer
    """
    FILE_READ_DATA = 0x00000001
    FILE_WRITE_DATA = 0x00000002
    FILE_APPEND_DATA = 0x00000004
    FILE_READ_EA = 0x00000008
    FILE_WRITE_EA = 0x00000010
    FILE_DELETE_CHILD = 0x00000040
    FILE_EXECUTE = 0x00000020
    FILE_READ_ATTRIBUTES = 0x00000080
    FILE_WRITE_ATTRIBUTES = 0x00000100
    DELETE = 0x00010000
    READ_CONTROL = 0x00020000
    WRITE_DAC = 0x00040000
    WRITE_OWNER = 0x00080000
    SYNCHRONIZE = 0x00100000
    ACCESS_SYSTEM_SECURITY = 0x01000000
    MAXIMUM_ALLOWED = 0x02000000
    GENERIC_ALL = 0x10000000
    GENERIC_EXECUTE = 0x20000000
    GENERIC_WRITE = 0x40000000
    GENERIC_READ = 0x80000000


class DirectoryAccessMask(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.13.1.2 Directory_Access_Mask
    Access Mask flag values to be used when accessing a directory
    """
    FILE_LIST_DIRECTORY = 0x00000001
    FILE_ADD_FILE = 0x00000002
    FILE_ADD_SUBDIRECTORY = 0x00000004
    FILE_READ_EA = 0x00000008
    FILE_WRITE_EA = 0x00000010
    FILE_TRAVERSE = 0x00000020
    FILE_DELETE_CHILD = 0x00000040
    FILE_READ_ATTRIBUTES = 0x00000080
    FILE_WRITE_ATTRIBUTES = 0x00000100
    DELETE = 0x00010000
    READ_CONTROL = 0x00020000
    WRITE_DAC = 0x00040000
    WRITE_OWNER = 0x00080000
    SYNCHRONIZE = 0x00100000
    ACCESS_SYSTEM_SECURITY = 0x01000000
    MAXIMUM_ALLOWED = 0x02000000
    GENERIC_ALL = 0x10000000
    GENERIC_EXECUTE = 0x20000000
    GENERIC_WRITE = 0x40000000
    GENERIC_READ = 0x80000000


class FileFlags(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.14 SMB2 CREATE Response Flags
    Flag that details info about the file that was opened.
    """
    SMB2_CREATE_FLAG_REPARSEPOINT = 0x1


class CreateAction(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.14 SMB2 CREATE Response Flags
    The action taken in establishing the open.
    """
    FILE_SUPERSEDED = 0x0
    FILE_OPENED = 0x1
    FILE_CREATED = 0x2
    FILE_OVERWRITTEN = 0x3


class CloseFlags(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.15 SMB2 CLOSE Request Flags
    Flags to indicate how to process the operation
    """
    SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB = 0x01


class ReadFlags(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.19 SMB2 READ Request Flags
    Read flags for SMB 3.0.2 and newer dialects
    """
    SMB2_READFLAG_READ_UNBUFFERED = 0x01


class ReadWriteChannel(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.19/21 SMB2 READ/Write Request Channel
    Channel information for an SMB2 READ Request message
    """
    SMB2_CHANNEL_NONE = 0x0
    SMB2_CHANNEL_RDMA_V1 = 0x1
    SMB2_CHANNEL_RDMA_V1_INVALIDATE = 0x2


class WriteFlags(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.21 SMB2 WRITE Request Flags
    Flags to indicate how to process the operation
    """
    SMB2_WRITEFLAG_WRITE_THROUGH = 0x00000001
    SMB2_WRITEFLAG_WRITE_UNBUFFERED = 0x00000002


class QueryDirectoryFlags(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.33 SMB2 QUERY_DIRECTORY Request Flags
    Indicates how the query directory operation MUST be processed.
    """
    SMB2_RESTART_SCANS = 0x01
    SMB2_RETURN_SINGLE_ENTRY = 0x02
    SMB2_INDEX_SPECIFIED = 0x04
    SMB2_REOPEN = 0x10


class QueryInfoFlags(object):
    """
    [MS-SMB2] 2.2.37 SMB2 QUERY_INFO Request - Flags
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d623b2f7-a5cd-4639-8cc9-71fa7d9f9ba9

    Flags to set on a QUERY_INFO request.
    """
    SL_RESTART_SCAN = 0x00000001
    SL_RETURN_SINGLE_ENTRY = 0x00000002
    SL_INDEX_SPECIFIED = 0x00000004


class InfoAdditionalInformation(object):
    """
    [MS-SMB2] 2.2.39 SMB2 SET_INFO Request - AdditionalInformation
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ee9614c4-be54-4a3c-98f1-769a7032a0e4

    If security information is being set, this value must contains one or more of the following flags.
    """
    OWNER_SECURTIY_INFORMATION = 0x00000001
    GROUP_SECURITY_INFORMATION = 0x00000002
    DACL_SECURITY_INFORMATION = 0x00000004
    SACL_SECURITY_INFORMATION = 0x00000008
    LABEL_SECURITY_INFORMATION = 0x00000010
    ATTRIBUTE_SECURITY_INFORMATION = 0x00000020
    SCOPE_SECURITY_INFORMATION = 0x00000040
    BACKUP_SECURITY_INFORMATION = 0x00010000


class SMB2CreateRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.13 SMB2 CREATE Request
    The SMB2 Create Request packet is sent by a client to request either
    creation of or access to a file.
    """
    COMMAND = Commands.SMB2_CREATE

    def __init__(self):
        # pep 80 char issues force me to define this here
        create_con_req = SMB2CreateContextRequest
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=57,
            )),
            ('security_flags', IntField(size=1)),
            ('requested_oplock_level', EnumField(
                size=1,
                enum_type=RequestedOplockLevel
            )),
            ('impersonation_level', EnumField(
                size=4,
                enum_type=ImpersonationLevel
            )),
            ('smb_create_flags', IntField(size=8)),
            ('reserved', IntField(size=8)),
            ('desired_access', IntField(size=4)),
            ('file_attributes', IntField(size=4)),
            ('share_access', FlagField(
                size=4,
                flag_type=ShareAccess
            )),
            ('create_disposition', EnumField(
                size=4,
                enum_type=CreateDisposition
            )),
            ('create_options', FlagField(
                size=4,
                flag_type=CreateOptions
            )),
            ('name_offset', IntField(
                size=2,
                default=120  # (header size 64) + (structure size 56)
            )),
            ('name_length', IntField(
                size=2,
                default=lambda s: self._name_length(s)
            )),
            ('create_contexts_offset', IntField(
                size=4,
                default=lambda s: self._create_contexts_offset(s)
            )),
            ('create_contexts_length', IntField(
                size=4,
                default=lambda s: len(s['buffer_contexts'])
            )),
            # Technically these are all under buffer but we split it to make
            # things easier
            ('buffer_path', BytesField(
                size=lambda s: self._buffer_path_size(s),
            )),
            ('padding', BytesField(
                size=lambda s: self._padding_size(s),
                default=lambda s: b"\x00" * self._padding_size(s)
            )),
            ('buffer_contexts', ListField(
                size=lambda s: s['create_contexts_length'].get_value(),
                list_type=StructureField(
                    structure_type=create_con_req
                ),
                unpack_func=lambda s, d: self._buffer_context_list(s, d)
            ))
        ])
        super(SMB2CreateRequest, self).__init__()

    def _name_length(self, structure):
        buffer_path = structure['buffer_path'].get_value()
        return len(buffer_path) if buffer_path != b"\x00\x00" else 0

    def _create_contexts_offset(self, structure):
        if len(structure['buffer_contexts']) == 0:
            return 0
        else:
            return structure['name_offset'].get_value() + \
                len(structure['padding']) + len(structure['buffer_path'])

    def _buffer_path_size(self, structure):
        name_length = structure['name_length'].get_value()
        return name_length if name_length != 0 else 2

    def _padding_size(self, structure):
        # no padding is needed if there are no contexts
        if structure['create_contexts_length'].get_value() == 0:
            return 0

        mod = structure['name_length'].get_value() % 8
        return 0 if mod == 0 else 8 - mod

    def _buffer_context_list(self, structure, data):
        context_list = []
        last_context = data == b""
        while not last_context:
            create_context = SMB2CreateContextRequest()
            data = create_context.unpack(data)
            context_list.append(create_context)
            last_context = create_context['next'].get_value() == 0

        return context_list


class SMB2CreateResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.14 SMB2 CREATE Response
    The SMB2 Create Response packet is sent by the server to an SMB2 CREATE
    Request.
    """
    COMMAND = Commands.SMB2_CREATE

    def __init__(self):
        create_con_req = SMB2CreateContextRequest
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=89
            )),
            ('oplock_level', EnumField(
                size=1,
                enum_type=RequestedOplockLevel
            )),
            ('flag', FlagField(
                size=1,
                flag_type=FileFlags
            )),
            ('create_action', EnumField(
                size=4,
                enum_type=CreateAction
            )),
            ('creation_time', DateTimeField(size=8)),
            ('last_access_time', DateTimeField(size=8)),
            ('last_write_time', DateTimeField(size=8)),
            ('change_time', DateTimeField(size=8)),
            ('allocation_size', IntField(size=8)),
            ('end_of_file', IntField(size=8)),
            ('file_attributes', FlagField(
                size=4,
                flag_type=FileAttributes
            )),
            ('reserved2', IntField(size=4)),
            ('file_id', BytesField(size=16)),
            ('create_contexts_offset', IntField(
                size=4,
                default=lambda s: self._create_contexts_offset(s)
            )),
            ('create_contexts_length', IntField(
                size=4,
                default=lambda s: len(s['buffer'])
            )),
            ('buffer', ListField(
                size=lambda s: s['create_contexts_length'].get_value(),
                list_type=StructureField(
                    structure_type=create_con_req
                ),
                unpack_func=lambda s, d: self._buffer_context_list(s, d)
            ))
        ])
        super(SMB2CreateResponse, self).__init__()

    def _create_contexts_offset(self, structure):
        if len(structure['buffer']) == 0:
            return 0
        else:
            return 152

    def _buffer_context_list(self, structure, data):
        context_list = []
        last_context = data == b""
        while not last_context:
            create_context = SMB2CreateContextRequest()
            data = create_context.unpack(data)
            context_list.append(create_context)
            # Manually make sure the final padding is present
            create_context['padding2'] = b"\x00" * create_context._padding2_size(create_context)
            last_context = create_context['next'].get_value() == 0

        return context_list


class SMB2CloseRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.15 SMB2 CLOSE Request
    Used by the client to close an instance of a file
    """
    COMMAND = Commands.SMB2_CLOSE

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=24
            )),
            ('flags', FlagField(
                size=2,
                flag_type=CloseFlags
            )),
            ('reserved', IntField(size=4)),
            ('file_id', BytesField(size=16)),
        ])
        super(SMB2CloseRequest, self).__init__()


class SMB2CloseResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.16 SMB2 CLOSE Response
    The response of a SMB2 CLOSE Request
    """
    COMMAND = Commands.SMB2_CLOSE

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=60
            )),
            ('flags', FlagField(
                size=2,
                flag_type=CloseFlags
            )),
            ('reserved', IntField(size=4)),
            ('creation_time', DateTimeField()),
            ('last_access_time', DateTimeField()),
            ('last_write_time', DateTimeField()),
            ('change_time', DateTimeField()),
            ('allocation_size', IntField(size=8)),
            ('end_of_file', IntField(size=8)),
            ('file_attributes', FlagField(
                size=4,
                flag_type=FileAttributes
            ))
        ])
        super(SMB2CloseResponse, self).__init__()


class SMB2FlushRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.17 SMB2 FLUSH Request
    Flush all cached file information for a specified open of a file to the
    persistent store that backs the file.
    """
    COMMAND = Commands.SMB2_FLUSH

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=24
            )),
            ('reserved1', IntField(size=2)),
            ('reserved2', IntField(size=4)),
            ('file_id', BytesField(size=16)),
        ])
        super(SMB2FlushRequest, self).__init__()


class SMB2FlushResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.18 SMB2 FLUSH Response
    SMB2 FLUSH Response packet sent by the server.
    """
    COMMAND = Commands.SMB2_FLUSH

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=4
            )),
            ('reserved', IntField(size=2))
        ])
        super(SMB2FlushResponse, self).__init__()


class SMB2ReadRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.19 SMB2 READ Request
    The request is used to run a read operation on the file specified.
    """
    COMMAND = Commands.SMB2_READ

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=49
            )),
            ('padding', IntField(size=1)),
            ('flags', FlagField(
                size=1,
                flag_type=ReadFlags
            )),
            ('length', IntField(
                size=4
            )),
            ('offset', IntField(
                size=8
            )),
            ('file_id', BytesField(size=16)),
            ('minimum_count', IntField(
                size=4
            )),
            ('channel', FlagField(
                size=4,
                flag_type=ReadWriteChannel
            )),
            ('remaining_bytes', IntField(size=4)),
            ('read_channel_info_offset', IntField(
                size=2,
                default=lambda s: self._get_read_channel_info_offset(s)
            )),
            ('read_channel_info_length', IntField(
                size=2,
                default=lambda s: self._get_read_channel_info_length(s)
            )),
            ('buffer', BytesField(
                size=lambda s: self._get_buffer_length(s),
                default=b"\x00"
            ))
        ])
        super(SMB2ReadRequest, self).__init__()

    def _get_read_channel_info_offset(self, structure):
        if structure['channel'].get_value() == 0:
            return 0
        else:
            return 64 + structure['structure_size'].get_value() - 1

    def _get_read_channel_info_length(self, structure):
        if structure['channel'].get_value() == 0:
            return 0
        else:
            return len(structure['buffer'].get_value())

    def _get_buffer_length(self, structure):
        # buffer should contain 1 byte of \x00 and not be empty
        if structure['channel'].get_value() == 0:
            return 1
        else:
            return structure['read_channel_info_length'].get_value()


class SMB2ReadResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.20 SMB2 READ Response
    Response to an SMB2 READ Request.
    """
    COMMAND = Commands.SMB2_READ

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=17
            )),
            ('data_offset', IntField(size=1)),
            ('reserved', IntField(size=1)),
            ('data_length', IntField(
                size=4,
                default=lambda s: len(s['buffer'])
            )),
            ('data_remaining', IntField(size=4)),
            ('reserved2', IntField(size=4)),
            ('buffer', BytesField(
                size=lambda s: s['data_length'].get_value()
            ))
        ])
        super(SMB2ReadResponse, self).__init__()


class SMB2WriteRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.21 SMB2 WRITE Request
    A write packet to sent to an open file or named pipe on the server
    """
    COMMAND = Commands.SMB2_WRITE

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=49
            )),
            ('data_offset', IntField(  # offset to the buffer field
                size=2,
                default=0x70  # seems to be hardcoded to this value
            )),
            ('length', IntField(
                size=4,
                default=lambda s: len(s['buffer'])
            )),
            ('offset', IntField(size=8)),  # the offset in the file of the data
            ('file_id', BytesField(size=16)),
            ('channel', FlagField(
                size=4,
                flag_type=ReadWriteChannel
            )),
            ('remaining_bytes', IntField(size=4)),
            ('write_channel_info_offset', IntField(
                size=2,
                default=lambda s: self._get_write_channel_info_offset(s)
            )),
            ('write_channel_info_length', IntField(
                size=2,
                default=lambda s: len(s['buffer_channel_info'])
            )),
            ('flags', FlagField(
                size=4,
                flag_type=WriteFlags
            )),
            ('buffer', BytesField(
                size=lambda s: s['length'].get_value()
            )),
            ('buffer_channel_info', BytesField(
                size=lambda s: s['write_channel_info_length'].get_value()
            ))
        ])
        super(SMB2WriteRequest, self).__init__()

    def _get_write_channel_info_offset(self, structure):
        if len(structure['buffer_channel_info']) == 0:
            return 0
        else:
            header_size = 64
            packet_size = structure['structure_size'].get_value() - 1
            buffer_size = len(structure['buffer'])
            return header_size + packet_size + buffer_size


class SMB2WriteResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.22 SMB2 WRITE Response
    The response to the SMB2 WRITE Request sent by the server
    """
    COMMAND = Commands.SMB2_WRITE

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=17
            )),
            ('reserved', IntField(size=2)),
            ('count', IntField(size=4)),
            ('remaining', IntField(size=4)),
            ('write_channel_info_offset', IntField(size=2)),
            ('write_channel_info_length', IntField(size=2))
        ])
        super(SMB2WriteResponse, self).__init__()


class SMB2QueryDirectoryRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.33 QUERY_DIRECTORY Request
    Used by the client to obtain a directory enumeration on a directory open.
    """
    COMMAND = Commands.SMB2_QUERY_DIRECTORY

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=33
            )),
            ('file_information_class', EnumField(
                size=1,
                enum_type=FileInformationClass
            )),
            ('flags', FlagField(
                size=1,
                flag_type=QueryDirectoryFlags
            )),
            ('file_index', IntField(size=4)),
            ('file_id', BytesField(size=16)),
            ('file_name_offset', IntField(
                size=2,
                default=lambda s: 0 if len(s['buffer']) == 0 else 96
            )),
            ('file_name_length', IntField(
                size=2,
                default=lambda s: len(s['buffer'])
            )),
            ('output_buffer_length', IntField(size=4)),
            # UTF-16-LE encoded search pattern
            ('buffer', BytesField(
                size=lambda s: s['file_name_length'].get_value()
            ))
        ])
        super(SMB2QueryDirectoryRequest, self).__init__()

    @staticmethod
    def unpack_response(file_information_class, buffer):
        """
        Pass in the buffer value from the response object to unpack it and
        return a list of query response structures for the request.

        :param file_information_class: The info class that represents the
            buffer.
        :param buffer: The raw bytes value of the SMB2QueryDirectoryResponse
            buffer field.
        :return: List of query_info.* structures based on the
            FileInformationClass used in the initial query request.
        """
        resp_structure = {
            FileInformationClass.FILE_DIRECTORY_INFORMATION: FileDirectoryInformation,
            FileInformationClass.FILE_NAMES_INFORMATION: FileNamesInformation,
            FileInformationClass.FILE_BOTH_DIRECTORY_INFORMATION: FileBothDirectoryInformation,
            FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION: FileIdBothDirectoryInformation,
            FileInformationClass.FILE_FULL_DIRECTORY_INFORMATION: FileFullDirectoryInformation,
            FileInformationClass.FILE_ID_FULL_DIRECTORY_INFORMATION: FileIdFullDirectoryInformation,
        }[file_information_class]
        query_results = []

        current_offset = 0
        is_next = True
        while is_next:
            result = resp_structure()
            result.unpack(buffer[current_offset:])
            query_results.append(result)
            current_offset += result['next_entry_offset'].get_value()
            is_next = result['next_entry_offset'].get_value() != 0

        return query_results


class SMB2QueryDirectoryResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.34 SMB2 QUERY_DIRECTORY Response
    Response to an SMB2 QUERY_DIRECTORY Request.
    """

    COMMAND = Commands.SMB2_QUERY_DIRECTORY

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=9
            )),
            ('output_buffer_offset', IntField(
                size=2,
                default=72
            )),
            ('output_buffer_length', IntField(
                size=4,
                default=lambda s: len(s['buffer'])
            )),
            # this structure varies based on the requested information class
            ('buffer', BytesField(
                size=lambda s: s['output_buffer_length'].get_value()
            ))
        ])
        super(SMB2QueryDirectoryResponse, self).__init__()


class SMB2QueryInfoRequest(Structure):
    """
    [MS-SMB2] 2.2.37 SMB2 QUERY_INFO Request
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d623b2f7-a5cd-4639-8cc9-71fa7d9f9ba9

    Sent by a client to request information on a file, named pipe, or underlying volume.
    """
    COMMAND = Commands.SMB2_QUERY_INFO

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=41,
            )),
            ('info_type', EnumField(
                size=1,
                enum_type=InfoType,
            )),
            ('file_info_class', EnumField(
                size=1,
                enum_type=FileInformationClass,
                default=FileInformationClass.FILE_NONE
            )),
            ('output_buffer_length', IntField(
                size=4,
                default=lambda s: 0,
            )),
            ('input_buffer_offset', IntField(
                size=2,
                default=lambda s: 0 if s['input_buffer_length'].get_value() == 0 else 104,
            )),
            ('reserved', IntField(size=2)),
            ('input_buffer_length', IntField(
                size=4,
                default=lambda s: len(s['buffer']),
            )),
            ('additional_information', IntField(size=4)),
            ('flags', FlagField(
                size=4,
                flag_type=QueryInfoFlags,
            )),
            ('file_id', BytesField(size=16)),
            ('buffer', BytesField(
                size=lambda s: s['input_buffer_length'].get_value(),
            )),
        ])
        super(SMB2QueryInfoRequest, self).__init__()


class SMB2QueryInfoResponse(Structure):
    """
    [MS-SMB2] 2.2.38 SMB2 QUERY_INFO Response
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3b1b3598-a898-44ca-bfac-2dcae065247f

    Sent by the server in response to an SMB2QueryInfoRequest.
    """
    COMMAND = Commands.SMB2_QUERY_INFO

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=9,
            )),
            ('output_buffer_offset', IntField(
                size=2,
                default=72,
            )),
            ('output_buffer_length', IntField(
                size=4,
                default=lambda s: len(s['buffer']),
            )),
            ('buffer', BytesField(
                size=lambda s: s['output_buffer_length'].get_value(),
            )),
        ])
        super(SMB2QueryInfoResponse, self).__init__()

    def parse_buffer(self, file_info_type):
        buffer = self['buffer'].get_value()

        def unpack_list(buffer, byte_boundary):
            info_list = []
            while buffer:
                entry = file_info_type()
                buffer = entry.unpack(buffer)

                padded_size = len(entry) % byte_boundary
                buffer_offset = (byte_boundary - padded_size) if padded_size else 0
                buffer = buffer[buffer_offset:]

                info_list.append(entry)

            return info_list

        file_obj = file_info_type()
        if isinstance(file_obj, FileFullEaInformation):
            return unpack_list(buffer, 4)
        elif isinstance(file_obj, FileStreamInformation):
            return unpack_list(buffer, 8)
        else:
            file_obj.unpack(buffer)
            return file_obj


class SMB2SetInfoRequest(Structure):
    """
    [MS-SMB2] 2.2.39 SMB2 SET_INFO Request
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ee9614c4-be54-4a3c-98f1-769a7032a0e4

    Sent by a client to set information on a file or underlying object store.
    """
    COMMAND = Commands.SMB2_SET_INFO

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=33,
            )),
            ('info_type', EnumField(
                size=1,
                enum_type=InfoType,
            )),
            ('file_info_class', EnumField(
                size=1,
                enum_type=FileInformationClass,
                default=FileInformationClass.FILE_NONE
            )),
            ('buffer_length', IntField(
                size=4,
                default=lambda s: len(s['buffer']),
            )),
            ('buffer_offset', IntField(
                size=2,
                default=96
            )),
            ('reserved', IntField(size=2)),
            ('additional_information', EnumField(
                size=4,
                enum_type=InfoAdditionalInformation,
            )),
            ('file_id', BytesField(size=16)),
            ('buffer', BytesField(
                size=lambda s: s['buffer_length'].get_value()
            ))
        ])
        super(SMB2SetInfoRequest, self).__init__()


class SMB2SetInfoResponse(Structure):
    """
    [MS-SMB2] 2.2.40 SMB2 SET_INFO Response
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c4318eb4-bdab-49b7-9352-abd7005c7f19

    Sent by the server in response to an SMB2SetInfoRequest to notify the client that its request has been successfully
    processed.
    """
    COMMAND = Commands.SMB2_SET_INFO

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=2
            )),
        ])
        super(SMB2SetInfoResponse, self).__init__()


class Open(object):

    def __init__(self, tree, name):
        """
        [MS-SMB2] v53.0 2017-09-15

        3.2.1.6 Per Application Open of a File
        Attributes per each open of a file. A file can be a File, Pipe,
        Directory, or Printer

        :param tree: The Tree (share) the file is located in.
        :param name: The name of the file, excluding the share path.
        """
        # properties available based on the file itself
        self._connected = False
        self.creation_time = None
        self.last_access_time = None
        self.last_write_time = None
        self.change_time = None
        self.allocation_size = None
        self.end_of_file = None
        self.file_attributes = None

        # properties used privately
        # set to { 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF } to allow message
        # compounding with the open as the first message, once opened this
        # will be overwritten by the open response
        self.file_id = b"\xff" * 16
        self.tree_connect = tree
        self.connection = tree.session.connection
        self.oplock_level = None
        self.durable = None
        self.file_name = name
        self.resilient_handle = None
        self.last_disconnect_time = None
        self.resilient_timeout = None

        # an array of entries used to maintain information about outstanding
        # lock and unlock operations performed on resilient Opens. Contains
        #     sequence_number - 4-bit integer modulo 16
        #     free - boolean value where False is no outstanding requests
        self.operation_buckets = []

        # SMB 3.x+
        self.durable_timeout = None

        # Table of outstanding requests, lookup by Request.cancel_id,
        # message_id
        self.outstanding_requests = {}

        self.create_guid = None
        self.is_persistent = None
        self.desired_access = None
        self.share_mode = None
        self.create_options = None
        self.file_attributes = None
        self.create_disposition = None

    @property
    def connected(self):
        return self._connected

    def create(self, impersonation_level, desired_access, file_attributes,
               share_access, create_disposition, create_options,
               create_contexts=None,
               oplock_level=RequestedOplockLevel.SMB2_OPLOCK_LEVEL_NONE,
               send=True):
        """
        This will open the file based on the input parameters supplied. Any
        file open should also be called with Open.close() when it is finished.

        More details on how each option affects the open process can be found
        here https://msdn.microsoft.com/en-us/library/cc246502.aspx.

        Supports out of band send function, call this function with send=False
        to return a tuple of (SMB2CreateRequest, receive_func) instead of
        sending the the request and waiting for the response. The receive_func
        can be used to get the response from the server by passing in the
        Request that was used to sent it out of band.

        :param impersonation_level: (ImpersonationLevel) The type of
            impersonation level that is issuing the create request.
        :param desired_access: The level of access that is required of the
            open. FilePipePrinterAccessMask or DirectoryAccessMask should be
            used depending on the type of file being opened.
        :param file_attributes: (FileAttributes) attributes to set on the file
            being opened, this usually is for opens that creates a file.
        :param share_access: (ShareAccess) Specifies the sharing mode for the
            open.
        :param create_disposition: (CreateDisposition) Defines the action the
            server MUST take if the file already exists.
        :param create_options: (CreateOptions) Specifies the options to be
            applied when creating or opening the file.
        :param create_contexts: (List<SMB2CreateContextRequest>) List of
            context request values to be applied to the create.

        Create Contexts are used to encode additional flags and attributes when
        opening files. More details on create context request values can be
        found here https://msdn.microsoft.com/en-us/library/cc246504.aspx.

        :param oplock_level: The requested oplock level of the request.
        :param send: Whether to send the request in the same call or return the
            message to the caller and the unpack function

        :return: List of context response values or None if there are no
            context response values. If the context response value is not known
            to smbprotocol then the list value would be raw bytes otherwise
            it is a Structure defined in create_contexts.py
        """
        create = SMB2CreateRequest()
        create['requested_oplock_level'] = oplock_level
        create['impersonation_level'] = impersonation_level
        create['desired_access'] = desired_access
        create['file_attributes'] = file_attributes
        create['share_access'] = share_access
        create['create_disposition'] = create_disposition
        create['create_options'] = create_options
        if self.file_name == "":
            create['buffer_path'] = b"\x00\x00"
        else:
            create['buffer_path'] = self.file_name.encode('utf-16-le')
        if create_contexts:
            create['buffer_contexts'] = SMB2CreateContextRequest.pack_multiple(create_contexts)

        if self.connection.dialect >= Dialects.SMB_3_0_0:
            self.desired_access = desired_access
            self.share_mode = share_access
            self.create_options = create_options
            self.file_attributes = file_attributes
            self.create_disposition = create_disposition

        if not send:
            return create, self._create_response

        log.info("Session: %s, Tree Connect: %s - sending SMB2 Create Request "
                 "for file %s" % (self.tree_connect.session.username,
                                  self.tree_connect.share_name,
                                  self.file_name))

        log.debug(create)
        request = self.connection.send(create,
                                       self.tree_connect.session.session_id,
                                       self.tree_connect.tree_connect_id)
        return self._create_response(request)

    def _create_response(self, request):
        log.info("Session: %s, Tree Connect: %s - receiving SMB2 Create "
                 "Response" % (self.tree_connect.session.username,
                               self.tree_connect.share_name))
        response = self.connection.receive(request)
        create_response = SMB2CreateResponse()
        create_response.unpack(response['data'].get_value())

        # Manually set the length so the debug log won't fail due to some servers returning a padded value which is not
        # reflected in the padding2 of the context response.
        create_response['create_contexts_length'] = len(create_response['buffer'])

        self._connected = True
        log.debug(create_response)

        self.file_id = create_response['file_id'].get_value()
        self.tree_connect.session.open_table[self.file_id] = self
        self.oplock_level = create_response['oplock_level'].get_value()
        self.durable = False
        self.resilient_handle = False
        self.last_disconnect_time = 0

        self.creation_time = create_response['creation_time'].get_value()
        self.last_access_time = create_response['last_access_time'].get_value()
        self.last_write_time = create_response['last_write_time'].get_value()
        self.change_time = create_response['change_time'].get_value()
        self.allocation_size = create_response['allocation_size'].get_value()
        self.end_of_file = create_response['end_of_file'].get_value()
        self.file_attributes = create_response['file_attributes'].get_value()

        create_contexts_response = None
        if create_response['create_contexts_length'].get_value() > 0:
            create_contexts_response = []
            for context in create_response['buffer'].get_value():
                create_contexts_response.append(context.get_context_data())

        return create_contexts_response

    def read(self, offset, length, min_length=0, unbuffered=False, wait=True,
             send=True):
        """
        Reads from an opened file or pipe

        Supports out of band send function, call this function with send=False
        to return a tuple of (SMB2ReadRequest, receive_func) instead of
        sending the the request and waiting for the response. The receive_func
        can be used to get the response from the server by passing in the
        Request that was used to sent it out of band.

        :param offset: The offset to start the read of the file.
        :param length: The number of bytes to read from the offset.
        :param min_length: The minimum number of bytes to be read for a
            successful operation.
        :param unbuffered: Whether to the server should cache the read data at
            intermediate layers, only value for SMB 3.0.2 or newer
        :param wait: If send=True, whether to wait for a response if
            STATUS_PENDING was received from the server or fail.
        :param send: Whether to send the request in the same call or return the
            message to the caller and the unpack function
        :return: A byte string of the bytes read
        """
        if length > self.connection.max_read_size:
            raise SMBException("The requested read length %d is greater than "
                               "the maximum negotiated read size %d"
                               % (length, self.connection.max_read_size))

        read = SMB2ReadRequest()
        read['length'] = length
        read['offset'] = offset
        read['minimum_count'] = min_length
        read['file_id'] = self.file_id
        read['padding'] = b"\x50"

        if unbuffered:
            if self.connection.dialect < Dialects.SMB_3_0_2:
                raise SMBUnsupportedFeature(self.connection.dialect,
                                            Dialects.SMB_3_0_2,
                                            "SMB2_READFLAG_READ_UNBUFFERED",
                                            True)
            read['flags'].set_flag(ReadFlags.SMB2_READFLAG_READ_UNBUFFERED)

        if not send:
            return read, self._read_response

        log.info("Session: %s, Tree Connect ID: %s - sending SMB2 Read "
                 "Request for file %s" % (self.tree_connect.session.username,
                                          self.tree_connect.share_name,
                                          self.file_name))
        log.debug(read)
        request = self.connection.send(read,
                                       self.tree_connect.session.session_id,
                                       self.tree_connect.tree_connect_id)
        return self._read_response(request, wait)

    def _read_response(self, request, wait=True):
        log.info("Session: %s, Tree Connect ID: %s - receiving SMB2 Read "
                 "Response" % (self.tree_connect.session.username,
                               self.tree_connect.share_name))
        response = self.connection.receive(request, wait=wait)
        read_response = SMB2ReadResponse()
        read_response.unpack(response['data'].get_value())
        log.debug(read_response)

        return read_response['buffer'].get_value()

    def write(self, data, offset=0, write_through=False, unbuffered=False,
              wait=True, send=True):
        """
        Writes data to an opened file.

        Supports out of band send function, call this function with send=False
        to return a tuple of (SMBWriteRequest, receive_func) instead of
        sending the the request and waiting for the response. The receive_func
        can be used to get the response from the server by passing in the
        Request that was used to sent it out of band.

        :param data: The bytes data to write.
        :param offset: The offset in the file to write the bytes at
        :param write_through: Whether written data is persisted to the
            underlying storage, not valid for SMB 2.0.2.
        :param unbuffered: Whether to the server should cache the write data at
            intermediate layers, only value for SMB 3.0.2 or newer
        :param wait: If send=True, whether to wait for a response if
            STATUS_PENDING was received from the server or fail.
        :param send: Whether to send the request in the same call or return the
            message to the caller and the unpack function
        :return: The number of bytes written
        """
        data_len = len(data)
        if data_len > self.connection.max_write_size:
            raise SMBException("The requested write length %d is greater than "
                               "the maximum negotiated write size %d"
                               % (data_len, self.connection.max_write_size))

        write = SMB2WriteRequest()
        write['length'] = len(data)
        write['offset'] = offset
        write['file_id'] = self.file_id
        write['buffer'] = data

        if write_through:
            if self.connection.dialect < Dialects.SMB_2_1_0:
                raise SMBUnsupportedFeature(self.connection.dialect,
                                            Dialects.SMB_2_1_0,
                                            "SMB2_WRITEFLAG_WRITE_THROUGH",
                                            True)
            write['flags'].set_flag(WriteFlags.SMB2_WRITEFLAG_WRITE_THROUGH)

        if unbuffered:
            if self.connection.dialect < Dialects.SMB_3_0_2:
                raise SMBUnsupportedFeature(self.connection.dialect,
                                            Dialects.SMB_3_0_2,
                                            "SMB2_WRITEFLAG_WRITE_UNBUFFERED",
                                            True)
            write['flags'].set_flag(WriteFlags.SMB2_WRITEFLAG_WRITE_UNBUFFERED)

        if not send:
            return write, self._write_response

        log.info("Session: %s, Tree Connect: %s - sending SMB2 Write Request "
                 "for file %s" % (self.tree_connect.session.username,
                                  self.tree_connect.share_name,
                                  self.file_name))
        log.debug(write)
        request = self.connection.send(write,
                                       self.tree_connect.session.session_id,
                                       self.tree_connect.tree_connect_id)
        return self._write_response(request, wait)

    def _write_response(self, request, wait=True):
        log.info("Session: %s, Tree Connect: %s - receiving SMB2 Write "
                 "Response" % (self.tree_connect.session.username,
                               self.tree_connect.share_name))
        response = self.connection.receive(request, wait=wait)
        write_response = SMB2WriteResponse()
        write_response.unpack(response['data'].get_value())
        log.debug(write_response)

        return write_response['count'].get_value()

    def flush(self, send=True):
        """
        A command sent by the client to request that a server flush all cached
        file information for the opened file.

        Supports out of band send function, call this function with send=False
        to return a tuple of (SMB2FlushRequest, receive_func) instead of
        sending the the request and waiting for the response. The receive_func
        can be used to get the response from the server by passing in the
        Request that was used to sent it out of band.

        :param send: Whether to send the request in the same call or return the
            message to the caller and the unpack function
        :return: The SMB2FlushResponse received from the server
        """
        flush = SMB2FlushRequest()
        flush['file_id'] = self.file_id

        if not send:
            return flush, self._flush_response

        log.info("Session: %s, Tree Connect: %s - sending SMB2 Flush Request "
                 "for file %s" % (self.tree_connect.session.username,
                                  self.tree_connect.share_name,
                                  self.file_name))
        log.debug(flush)
        request = self.connection.send(flush,
                                       self.tree_connect.session.session_id,
                                       self.tree_connect.tree_connect_id)
        return self._flush_response(request)

    def _flush_response(self, request):
        log.info("Session: %s, Tree Connect: %s - receiving SMB2 Flush "
                 "Response" % (self.tree_connect.session.username,
                               self.tree_connect.share_name))
        response = self.connection.receive(request)
        flush_response = SMB2FlushResponse()
        flush_response.unpack(response['data'].get_value())
        log.debug(flush_response)
        return flush_response

    def query_directory(self, pattern, file_information_class, flags=None,
                        file_index=0, max_output=MAX_PAYLOAD_SIZE, send=True):
        """
        Run a Query/Find on an opened directory based on the params passed in.

        Supports out of band send function, call this function with send=False
        to return a tuple of (SMB2QueryDirectoryRequest, receive_func) instead
        of sending the the request and waiting for the response. The
        receive_func can be used to get the response from the server by passing
        in the Request that was used to sent it out of band.

        :param pattern: The string pattern to use for the query, this pattern
            format is based on the SMB server but * is usually a wildcard
        :param file_information_class: FileInformationClass that defines the
            format of the result that is returned
        :param flags: QueryDirectoryFlags that control how the operation must
            be processed.
        :param file_index: If the flags SMB2_INDEX_SPECIFIED, this is the index
            the query should resume on, otherwise should be 0
        :param max_output: The maximum output size, defaulted to the max credit
            size but can be increased to reduced round trip operations.
        :param send: Whether to send the request in the same call or return the
            message to the caller and the unpack function
        :return: A list of structures defined in query_info.py, the list entry
            structure is based on the value of file_information_class in the
            request message
        """
        query = SMB2QueryDirectoryRequest()
        query['file_information_class'] = file_information_class
        query['flags'] = flags
        query['file_index'] = file_index
        query['file_id'] = self.file_id
        query['output_buffer_length'] = max_output
        query['buffer'] = pattern.encode('utf-16-le')

        if not send:
            return query, self._query_directory_response

        log.info("Session: %s, Tree Connect: %s - sending SMB2 Query "
                 "Directory Request for directory %s"
                 % (self.tree_connect.session.username,
                    self.tree_connect.share_name, self.file_name))
        log.debug(query)
        request = self.connection.send(query,
                                       self.tree_connect.session.session_id,
                                       self.tree_connect.tree_connect_id)
        return self._query_directory_response(request)

    def _query_directory_response(self, request):
        log.info("Session: %s, Tree Connect: %s - receiving SMB2 Query "
                 "Response" % (self.tree_connect.session.username,
                               self.tree_connect.share_name))
        response = self.connection.receive(request)
        query_response = SMB2QueryDirectoryResponse()
        query_response.unpack(response['data'].get_value())
        log.debug(query_response)

        query_request = SMB2QueryDirectoryRequest()
        query_request.unpack(request.message['data'].get_value())
        file_cl = query_request['file_information_class'].get_value()
        data = query_response['buffer'].get_value()
        results = SMB2QueryDirectoryRequest.unpack_response(file_cl, data)
        return results

    def close(self, get_attributes=False, send=True):
        """
        Closes an opened file.

        Supports out of band send function, call this function with send=False
        to return a tuple of (SMB2CloseRequest, receive_func) instead of
        sending the the request and waiting for the response. The receive_func
        can be used to get the response from the server by passing in the
        Request that was used to sent it out of band.

        :param get_attributes: (Bool) whether to get the latest attributes on
            the close and set them on the Open object
        :param send: Whether to send the request in the same call or return the
            message to the caller and the unpack function
        :return: SMB2CloseResponse message received from the server
        """
        # it is already closed and this isn't for an out of band request
        if not self._connected and send:
            return

        close = SMB2CloseRequest()

        close['file_id'] = self.file_id
        if get_attributes:
            close['flags'] = CloseFlags.SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB

        if not send:
            return close, self._close_response

        log.info("Session: %s, Tree Connect: %s - sending SMB2 Close Request "
                 "for file %s" % (self.tree_connect.session.username,
                                  self.tree_connect.share_name,
                                  self.file_name))
        log.debug(close)
        request = self.connection.send(close,
                                       self.tree_connect.session.session_id,
                                       self.tree_connect.tree_connect_id)
        return self._close_response(request)

    def _close_response(self, request):
        log.info("Session: %s, Tree Connect: %s - receiving SMB2 Close "
                 "Response" % (self.tree_connect.session.username,
                               self.tree_connect.share_name))
        try:
            response = self.connection.receive(request)
        except SMBResponseException as exc:
            # check if it was already closed
            if exc.status == NtStatus.STATUS_FILE_CLOSED:
                self._connected = False
                self.tree_connect.session.open_table.pop(self.file_id, None)
                return
            # else raise the exception
            raise exc

        c_resp = SMB2CloseResponse()
        c_resp.unpack(response['data'].get_value())
        log.debug(c_resp)
        self._connected = False
        del self.tree_connect.session.open_table[self.file_id]

        # update the attributes if requested
        close_request = SMB2CloseRequest()
        close_request.unpack(request.message['data'].get_value())
        if close_request['flags'].has_flag(
                CloseFlags.SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB):
            self.creation_time = c_resp['creation_time'].get_value()
            self.last_access_time = c_resp['last_access_time'].get_value()
            self.last_write_time = c_resp['last_write_time'].get_value()
            self.change_time = c_resp['change_time'].get_value()
            self.allocation_size = c_resp['allocation_size'].get_value()
            self.end_of_file = c_resp['end_of_file'].get_value()
            self.file_attributes = c_resp['file_attributes'].get_value()
        return c_resp
