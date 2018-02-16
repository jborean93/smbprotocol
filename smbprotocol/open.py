import logging

import smbprotocol.create_contexts
from smbprotocol.exceptions import SMBResponseException, SMBUnsupportedFeature
from smbprotocol.structure import BytesField, DateTimeField, EnumField, \
    FlagField, IntField, ListField, Structure, StructureField
from smbprotocol.connection import Commands, Dialects, NtStatus

try:
    from collections import OrderedDict
except ImportError:  # pragma: no cover
    from ordereddict import OrderedDict

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


class FileAttributes(object):
    """
    [MS-FSCC]

    2.6 File Attributes
    Combination of file attributes for a file or directory
    """
    FILE_ATTRIBUTE_ARCHIVE = 0x00000020
    FILE_ATTRIBUTE_COMPRESSED = 0x00000800
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    FILE_ATTRIBUTE_ENCRYPTED = 0x00004000
    FILE_ATTRIBUTE_HIDDEN = 0x00000002
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000
    FILE_ATTRIBUTE_OFFLINE = 0x00001000
    FILE_ATTRIBUTE_READONLY = 0x00000001
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200
    FILE_ATTRIBUTE_SYSTEM = 0x00000004
    FILE_ATTRIBUTE_TEMPORARY = 0x00000100
    FILE_ATTRIBUTE_INTEGRITY_STREAM = 0x00008000
    FILE_ATTRIBUTE_NO_SCRUB_DATA = 0x00020000


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


class SMB2CreateRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.13 SMB2 CREATE Request
    The SMB2 Create Request packet is sent by a client to request either
    creation of or access to a file.
    """

    def __init__(self):
        # pep 80 char issues force me to define this here
        create_con_req = smbprotocol.create_contexts.SMB2CreateContextRequest
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
                default=lambda s: len(s['buffer_path'])
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
                size=lambda s: s['name_length'].get_value(),
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

    def _create_contexts_offset(self, structure):
        if len(structure['buffer_contexts']) == 0:
            return 0
        else:
            return structure['name_offset'].get_value() + \
                len(structure['padding']) + len(structure['buffer_path'])

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
            create_context = \
                smbprotocol.create_contexts.SMB2CreateContextRequest()
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

    def __init__(self):
        create_con_req = smbprotocol.create_contexts.SMB2CreateContextRequest
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
            ('file_id', StructureField(
                size=16,
                structure_type=SMB2FileId
            )),
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
            create_context = \
                smbprotocol.create_contexts.SMB2CreateContextRequest()
            data = create_context.unpack(data)
            context_list.append(create_context)
            last_context = create_context['next'].get_value() == 0

        return context_list


class SMB2FileId(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.14.1 SMB2_FILEID
    Used to represent an open to a file
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('persistent', BytesField(size=8)),
            ('volatile', BytesField(size=8)),
        ])
        super(SMB2FileId, self).__init__()


class SMB2CloseRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.15 SMB2 CLOSE Request
    Used by the client to close an instance of a file
    """

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
            ('file_id', StructureField(
                size=16,
                structure_type=SMB2FileId
            ))
        ])
        super(SMB2CloseRequest, self).__init__()


class SMB2CloseResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.16 SMB2 CLOSE Response
    The response of a SMB2 CLOSE Request
    """

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

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=24
            )),
            ('reserved1', IntField(size=2)),
            ('reserved2', IntField(size=4)),
            ('file_id', StructureField(
                structure_type=SMB2FileId
            ))
        ])
        super(SMB2FlushRequest, self).__init__()


class SMB2FlushResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.18 SMB2 FLUSH Response
    SMB2 FLUSH Response packet sent by the server.
    """

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
            ('file_id', StructureField(
                structure_type=SMB2FileId
            )),
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
            ('buffer', BytesField())
        ])
        super(SMB2ReadResponse, self).__init__()


class SMB2WriteRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.21 SMB2 WRITE Request
    A write packet to sent to an open file or named pipe on the server
    """

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
            ('file_id', StructureField(
                structure_type=SMB2FileId
            )),
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


class Open(object):

    def __init__(self, tree, name):
        """
        [MS-SMB2] v53.0 2017-09-15

        3.2.1.6 Per Application Open of a File
        Attributes per each open of a file. A file can be a File, Pipe,
        Directory, or Printer

        :param tree: The Tree (share) the file is located in.
        :param name: The name of the file, excluding the share path, e.g.
            \\server\share\folder\file.txt would be folder\file.txt
        """
        # properties available based on the file itself
        self.opened = False
        self.creation_time = None
        self.last_access_time = None
        self.last_write_time = None
        self.change_time = None
        self.allocation_size = None
        self.end_of_file = None
        self.file_attributes = None

        # properties used privately
        self.file_id = None
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

    def open(self, impersonation_level, desired_access, file_attributes,
             share_access, create_disposition, create_options,
             create_contexts=list()):
        """
        This will open the file based on the input parameters supplied. Any
        file open should also be called with Open.close() when it is finished.

        More details on how each option affects the open process can be found
        here https://msdn.microsoft.com/en-us/library/cc246502.aspx.

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

        :return: List of context response values or None if there are no
            context response values. If the context response value is not known
            to smbprotocol then the list value would be raw bytes otherwise
            it is a Structure defined in create_contexts.py
        """
        log_header = "Session: %s, Tree Connect ID: %s" \
                     % (self.tree_connect.session.session_id,
                        self.tree_connect.tree_connect_id)

        create = SMB2CreateRequest()
        create['impersonation_level'] = impersonation_level
        create['desired_access'] = desired_access
        create['file_attributes'] = file_attributes
        create['share_access'] = share_access
        create['create_disposition'] = create_disposition
        create['create_options'] = create_options
        create['buffer_path'] = self.file_name.encode('utf-16-le')
        create['buffer_contexts'] = smbprotocol.create_contexts.\
            SMB2CreateContextRequest.pack_multiple(create_contexts)

        log.info("%s - sending SMB2 Create Request for file %s"
                 % (log_header, self.file_name))
        log.debug(str(create))
        header = self.connection.send(create, Commands.SMB2_CREATE,
                                      self.tree_connect.session,
                                      self.tree_connect)

        log.info("%s - receiving SMB2 Create Response" % log_header)
        response = self.connection.receive(header['message_id'].get_value())
        create_response = SMB2CreateResponse()
        create_response.unpack(response['data'].get_value())
        log.debug(str(create_response))

        self.file_id = create_response['file_id'].get_value()
        self.oplock_level = create_response['oplock_level'].get_value()
        self.durable = False
        self.resilient_handle = False
        self.last_disconnect_time = 0

        if self.connection.dialect >= Dialects.SMB_3_0_0:
            self.desired_access = desired_access
            self.share_mode = share_access
            self.create_options = create_options
            self.file_attributes = file_attributes
            self.create_disposition = create_disposition

        self.creation_time = create_response['creation_time'].get_value()
        self.last_access_time = create_response['last_access_time'].get_value()
        self.last_write_time = create_response['last_write_time'].get_value()
        self.change_time = create_response['change_time'].get_value()
        self.allocation_size = create_response['allocation_size'].get_value()
        self.end_of_file = create_response['end_of_file'].get_value()
        self.file_attributes = create_response['file_attributes'].get_value()
        self.opened = True

        create_contexts_response = None
        if create_response['create_contexts_length'].get_value() > 0:
            create_contexts_response = []
            for context in create_response['buffer'].get_value():
                create_contexts_response.append(context.get_context_data())

        return create_contexts_response

    def read(self, offset, length, min_length=0, unbuffered=False, wait=False):
        """
        Reads from an opened file or pipe

        :param offset: The offset to start the read of the file.
        :param length: The number of bytes to read from the offset.
        :param min_length: The minimum number of bytes to be read for a
            successful operation.
        :param unbuffered: Whether to the server should cache the read data at
            intermediate layers, only value for SMB 3.0.2 or newer
        :param wait: Whether to wait for a response if STATUS_PENDING was
            received from the server or fail.
        :return: A byte string of the bytes read
        """
        log_header = "Session: %s, Tree Connect ID: %s" \
                     % (self.tree_connect.session.session_id,
                        self.tree_connect.tree_connect_id)
        read = SMB2ReadRequest()

        if unbuffered:
            if self.connection.dialect < Dialects.SMB_3_0_2:
                raise SMBUnsupportedFeature(self.connection.dialect,
                                            Dialects.SMB_3_0_2,
                                            "SMB2_READFLAG_READ_UNBUFFERED",
                                            True)
            read['flags'].set_flag(ReadFlags.SMB2_READFLAG_READ_UNBUFFERED)

        read['length'] = length
        read['offset'] = offset
        read['minimum_count'] = min_length
        read['file_id'] = self.file_id
        read['padding'] = b"\x50"

        # deal with length greater than connection max size
        log.info("%s - sending SMB2 Read Request for file %s"
                 % (log_header, self.file_name))
        log.debug(str(read))
        header = self.connection.send(read, Commands.SMB2_READ,
                                      self.tree_connect.session,
                                      self.tree_connect)

        status = NtStatus.STATUS_PENDING
        log.info("%s - receiving SMB2 Read Response" % log_header)
        while True:
            try:
                response = self.connection.receive(
                    header['message_id'].get_value()
                )
            except SMBResponseException as exc:
                if not wait:
                    raise exc
                elif status != NtStatus.STATUS_PENDING:
                    raise exc
                else:
                    pass
            else:
                break

        read_response = SMB2ReadResponse()
        read_response.unpack(response['data'].get_value())
        log.debug(str(read_response))

        return read_response['buffer'].get_value()

    def write(self, data, offset=0, write_through=False, unbuffered=False):
        """
        Writes data to an opened file.

        :param data: The bytes data to write.
        :param offset: The offset in the file to write the bytes at
        :param write_through: Whether written data is persisted to the
            underlying storage, not valid for SMB 2.0.2.
        :param unbuffered: Whether to the server should cache the write data at
            intermediate layers, only value for SMB 3.0.2 or newer
        :return: The number of bytes written
        """
        # handle data over max write size
        log_header = "Session: %s, Tree Connect ID: %s" \
                     % (self.tree_connect.session.session_id,
                        self.tree_connect.tree_connect_id)
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

        log.info("%s - sending SMB2 Write Request for file %s"
                 % (log_header, self.file_name))
        log.debug(str(write))
        header = self.connection.send(write, Commands.SMB2_WRITE,
                                      self.tree_connect.session,
                                      self.tree_connect)

        log.info("%s - receiving SMB2 Write Response" % log_header)
        response = self.connection.receive(
            header['message_id'].get_value()
        )
        write_response = SMB2WriteResponse()
        write_response.unpack(response['data'].get_value())
        log.debug(str(write_response))

        return write_response['count'].get_value()

    def flush(self):
        """
        A command sent by the client to request that a server flush all cached
        file information for the opened file.
        """
        log_header = "Session: %s, Tree Connect ID: %s" \
                     % (self.tree_connect.session.session_id,
                        self.tree_connect.tree_connect_id)
        flush = SMB2FlushRequest()

        flush['file_id'] = self.file_id

        log.info("%s - sending SMB2 Flush Request for file %s"
                 % (log_header, self.file_name))
        log.debug(str(flush))
        header = self.connection.send(flush, Commands.SMB2_FLUSH,
                                      self.tree_connect.session,
                                      self.tree_connect)

        log.info("%s - receiving SMB2 Flush Response" % log_header)
        response = self.connection.receive(
            header['message_id'].get_value()
        )
        flush_response = SMB2FlushResponse()
        flush_response.unpack(response['data'].get_value())
        log.debug(str(flush_response))

    def close(self, get_attributes=False):
        """
        Closes an opened file.

        :param get_attributes: (Bool) whether to get the latest attributes on
            the close and set them on the Open object.
        """
        log_header = "Session: %s, Tree Connect ID: %s" \
                     % (self.tree_connect.session.session_id,
                        self.tree_connect.tree_connect_id)
        close = SMB2CloseRequest()

        close['file_id'] = self.file_id
        if get_attributes:
            close['flags'] = CloseFlags.SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB

        log.info("%s - sending SMB2 Close Request for file %s"
                 % (log_header, self.file_name))
        log.debug(str(close))
        header = self.connection.send(close, Commands.SMB2_CLOSE,
                                      self.tree_connect.session,
                                      self.tree_connect)

        log.info("%s - receiving SMB2 Close Response" % log_header)
        response = self.connection.receive(
            header['message_id'].get_value()
        )
        c_resp = SMB2CloseResponse()
        c_resp.unpack(response['data'].get_value())
        log.debug(str(c_resp))

        # update the attributes if requested
        if get_attributes:
            self.creation_time = c_resp['creation_time'].get_value()
            self.last_access_time = c_resp['last_access_time'].get_value()
            self.last_write_time = c_resp['last_write_time'].get_value()
            self.change_time = c_resp['change_time'].get_value()
            self.allocation_size = c_resp['allocation_size'].get_value()
            self.end_of_file = c_resp['end_of_file'].get_value()
            self.file_attributes = c_resp['file_attributes'].get_value()
        self.opened = False
