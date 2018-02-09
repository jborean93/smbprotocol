import hashlib
from cryptography.hazmat.primitives.ciphers import aead


class Smb1Flags2(object):
    """
    [MS-CIFS] and [MS-SMB]

    Various flags that are used in an SMBv1 message. Only a small amount of
    these flags are used in the initial SMBv1 negotiate message and are mostly
    irrevalent.
    """
    SMB_FLAGS2_LONG_NAME = 0x0001
    SMB_FLAGS2_EAS = 0x0002
    SMB_FLAGS2_SMB_SECURITY_SIGNATURE = 0x0004
    SMB_FLAGS2_COMPRESSES = 0x0008
    SMB_FLAGS2_SMB_SECURITY_SIGNATURE_REQUIRED = 0x0010
    SMB_FLAGS2_IS_LONG_NAME = 0x0040
    SMB_FLAGS2_REPARSE_PATH = 0x0400
    SMB_FLAGS2_EXTENDED_SECURITY = 0x0800
    SMB_FLAGS2_DFS = 0x1000
    SMB_FLAGS2_PAGING_IO = 0x2000
    SMB_FLAGS2_NT_STATUS = 0x4000
    SMB_FLAGS2_UNICODE = 0x8000


class Commands(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.1.2 SMB2 Packet Header - SYNC Command
    The command code of an SMB2 packet, it is used in the packet header.
    """
    SMB2_NEGOTIATE = 0x0000
    SMB2_SESSION_SETUP = 0x0001
    SMB2_LOGOFF = 0x0002
    SMB2_TREE_CONNECT = 0x0003
    SMB2_TREE_DISCONNECT = 0x0004
    SMB2_CREATE = 0x0005
    SMB2_CLOSE = 0x0006
    SMB2_FLUSH = 0x0007
    SMB2_READ = 0x0008
    SMB2_WRITE = 0x0009
    SMB2_LOCK = 0x000A
    SMB2_IOCTL = 0x000B
    SMB2_CANCEL = 0x000C
    SMB2_ECHO = 0x000D
    SMB2_QUERY_DIRECTORY = 0x000E
    SMB2_CHANGE_NOTIFY = 0x000F
    SMB2_QUERY_INFO = 0x0010
    SMB2_SET_INFO = 0x0011
    SMB2_OPLOCK_BREAK = 0x0012


class Smb2Flags(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.1.2 SMB2 Packet Header - SYNC Flags
    Indicates various processing rules that need to be done on the SMB2 packet.
    """
    SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001
    SMB2_FLAGS_ASYNC_COMMAND = 0x00000002
    SMB2_FLAGS_RELATED_OPERATIONS = 0x00000004
    SMB2_FLAGS_SIGNED = 0x00000008
    SMB2_FLAGS_PRIORITY_MASK = 0x00000070
    SMB2_FLAGS_DFS_OPERATIONS = 0x10000000
    SMB2_FLAGS_REPLAY_OPERATIONS = 0x20000000


class SecurityMode(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.3 SMB2 NEGOTIATE Request SecurityMode
    Indicates whether SMB signing is enabled or required by the client.
    """
    SMB2_NEGOTIATE_SIGNING_ENABLED = 0x0001
    SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002


class Capabilities(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.3 SMB2 NEGOTIATE Request Capabilities
    Used in SMB3.x and above, used to specify the capabilities supported.
    """
    SMB2_GLOBAL_CAP_DFS = 0x00000001
    SMB2_GLOBAL_CAP_LEASING = 0x00000002
    SMB2_GLOBAL_CAP_MTU = 0x00000004
    SMB2_GLOBAL_CAP_MULTI_CHANNEL = 0x00000008
    SMB2_GLOBAL_CAP_PERSISTENT_HANDLES = 0x00000010
    SMB2_GLOBAL_CAP_DIRECTORY_LEASING = 0x00000020
    SMB2_GLOBAL_CAP_ENCRYPTION = 0x00000040


class Dialects(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.3 SMB2 NEGOTIATE Request Dialects
    16-bit integeres specifying an SMB2 dialect that is supported. 0x02FF is
    used in the SMBv1 negotiate request to say that dialects greater than
    2.0.2 is supported.
    """
    SMB_2_0_2 = 0x0202
    SMB_2_1_0 = 0x0210
    SMB_3_0_0 = 0x0300
    SMB_3_0_2 = 0x0302
    SMB_3_1_1 = 0x0311
    SMB_2_WILDCARD = 0x02FF


class NegotiateContextType(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.3.1 SMB2 NEGOTIATE_CONTENT Request ContextType
    Specifies the type of context in an SMB2 NEGOTIATE_CONTEXT message.
    """
    SMB2_PREAUTH_INTEGRITY_CAPABILITIES = 0x0001
    SMB2_ENCRYPTION_CAPABILITIES = 0x0002


class HashAlgorithms(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.3.1.1 SMB2_PREAUTH_INTEGRITY_CAPABILITIES
    16-bit integer IDs that specify the integrity hash algorithm supported
    """
    SHA_512 = 0x0001

    @staticmethod
    def get_algorithm(hash):
        return {
            HashAlgorithms.SHA_512: hashlib.sha512
        }[hash]


class Ciphers(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.3.1.2 SMB2_ENCRYPTION_CAPABILITIES
    16-bit integer IDs that specify the supported encryption algorithms.
    """
    AES_128_CCM = 0x0001
    AES_128_GCM = 0x0002

    @staticmethod
    def get_cipher(cipher):
        return {
            Ciphers.AES_128_CCM: aead.AESCCM,
            Ciphers.AES_128_GCM: aead.AESGCM
        }[cipher]


class SessionFlags(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.6 SMB2 SESSION_SETUP Response Flags
    Flags the indicates additional information about the session.
    """
    SMB2_SESSION_FLAG_IS_GUEST = 0x0001
    SMB2_SESSION_FLAG_IS_NULL = 0x0002
    SMB2_SESSION_FLAG_ENCRYPT_DATA = 0x0004


class TreeFlags(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.9 SMB2 TREE_CONNECT Response Flags
    Flags used in SMB 3.1.1  to indicate how to process the operation.
    """
    SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT = 0x0004
    SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER = 0x0002
    SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT = 0x0001


class ShareType(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.10 SMB2 TREE_CONNECT Response Capabilities
    The type of share being accessed
    """
    SMB2_SHARE_TYPE_DISK = 0x01
    SMB2_SHARE_TYPE_PIPE = 0x02
    SMB2_SHARE_TYPE_PRINT = 0x03


class ShareFlags(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.10 SMB2 TREE_CONNECT Response Capabilities
    Properties for the share
    """
    SMB2_SHAREFLAG_MANUAL_CACHING = 0x00000000
    SMB2_SHAREFLAG_AUTO_CACHING = 0x00000010
    SMB2_SHAREFLAG_VDO_CACHING = 0x00000020
    SMB2_SHAREFLAG_NO_CACHING = 0x00000030
    SMB2_SHAREFLAG_DFS = 0x00000001
    SMB2_SHAREFLAG_DFS_ROOT = 0x00000002
    SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS = 0x00000100
    SMB2_SHAREFLAG_FORCE_SHARED_DELETE = 0x00000200
    SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING = 0x00000400
    SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM = 0x00000800
    SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK = 0x00001000
    SMB2_SHAREFLAG_ENABLE_HASH_V1 = 0x00002000
    SMB2_SHAREFLAG_ENABLE_HASH_V2 = 0x00004000
    SMB2_SHAREFLAG_ENCRYPT_DATA = 0x00008000
    SMB2_SHAREFLAG_IDENTITY_REMOTING = 0x00040000


class ShareCapabilities(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.10 SMB2 TREE_CONNECT Response Capabilities
    Indicates various capabilities for a share
    """
    SMB2_SHARE_CAP_DFS = 0x00000008
    SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY = 0x00000010
    SMB2_SHARE_CAP_SCALEOUT = 0x00000020
    SMB2_SHARE_CAP_CLUSTER = 0x00000040
    SMB2_SHARE_CAP_ASYMMETRIC = 0x00000080
    SMB2_SHARE_CAP_REDIRECT_TO_OWNER = 0x00000100


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


class CreateContextName(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.13.2 SMB2_CREATE_CONTEXT Request Values
    Valid names for the name to set on a SMB2_CREATE_CONTEXT Request entry
    """
    SMB2_CREATE_EA_BUFFER = 0x45787441
    SMB2_CREATE_SD_BUFFER = 0x53656344
    SMB2_CREATE_DURABLE_HANDLE_REQUEST = 0x44486e51
    SMB2_CREATE_DURABLE_HANDLE_RECONNECT = 0x44486e43
    SMB2_CREATE_ALLOCATION_SIZE = 0x416c5369
    SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST = 0x4d784163
    SMB2_CREATE_TIMEWARP_TOKEN = 0x54577270
    SMB2_CREATE_QUERY_ON_DISK_ID = 0x51466964
    SMB2_CREATE_REQUEST_LEASE = 0x52714c73
    SMB2_CREATE_REQUEST_LEASE_V2 = 0x52714c73
    SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2 = 0x44483251
    SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2 = 0x44483243
    SMB2_CREATE_APP_INSTANCE_ID = 0x45BCA66AEFA7F74A9008FA462E144D74
    SMB2_CREATE_APP_INSTANCE_VERSION = 0xB982D0B73B56074FA07B524A8116A010
    SVHDX_OPEN_DEVICE_CONTEXT = 0x9CCBCF9E04C1E643980E158DA1F6EC83


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
    SMB2_WRITEFLAG_WRITE_THROUGH = 0x1
    SMB2_WRITEFLAG_WRITE_UNBUFFERED = 0x2


class CtlCode(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.31 SMB2 IOCTL Request CtlCode
    The control code of the FSCTL_IOCTL method.
    """
    FSCTL_DFS_GET_REFERRALS = 0x00060194
    FSCTL_PIPE_PEEK = 0x0011400C
    FSCTL_PIPE_WAIT = 0x00110018
    FSCTL_PIPE_TRANSCEIVE = 0x0011C017
    FSCTL_SRV_COPYCHUNK = 0x001440F2
    FSCTL_SRV_ENUMERATE_SNAPSHOTS = 0x00144064
    FSCTL_SRV_REQUEST_RESUME_KEY = 0x00140078
    FSCTL_SRV_READ_HASH = 0x001441bb
    FSCTL_SRV_COPYCHUNK_WRITE = 0x001480F2
    FSCTL_LMR_REQUEST_RESILIENCY = 0x001401D4
    FSCTL_QUERY_NETWORK_INTERFACE_INFO = 0x001401FC
    FSCTL_SET_REPARSE_POINT = 0x000900A4
    FSCTL_DFS_GET_REFERRALS_EX = 0x000601B0
    FSCTL_FILE_LEVEL_TRIM = 0x00098208
    FSCTL_VALIDATE_NEGOTIATE_INFO = 0x00140204


class IOCTLFlags(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.31 SMB2 IOCTL Request Flags
    A flag that indicates how to process the operation
    """
    SMB2_0_IOCTL_IS_IOCTL = 0x00000000
    SMB2_0_IOCTL_IS_FSCTL = 0x00000001


class FileInformationClass(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.33 SMB2 QUERY_DIRECTORY Request FileInformationClass
    Describes the format that the data MUST be returned in
    """
    FILE_DIRECTORY_INFORMATION = 0x01
    FILE_FULL_DIRECTORY_INFORMATION = 0x02
    FILE_ID_FULL_DIRECTORY_INFORMATION = 0x26
    FILE_BOTH_DIRECTORY_INFORMATION = 0x03
    FILE_ID_BOTH_DIRECTORY_INFROMATION = 0x25
    FILE_NAMES_INFORMATION = 0x0C


class QueryDirectoryFlags(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.33 SMB2 QUERY_DIRECTORY Request Flags
    Indicates how the query directory operation MUST be processed
    """
    SMB2_RESTART_SCANS = 0x01
    SMB2_RETURN_SINGLE_ENTRY = 0x02
    SMB2_INDEX_SPECIFIED = 0x04
    SMB2_REOPEN = 0x10


class NtStatus(object):
    """
    [MS-ERREF] https://msdn.microsoft.com/en-au/library/cc704588.aspx

    2.3.1 NTSTATUS Values
    These values are set in the status field of an SMB2Header response. This is
    not an exhaustive list but common values that are returned.
    """
    STATUS_SUCCESS = 0x00000000
    STATUS_PENDING = 0x00000103
    STATUS_INVALID_PARAMETER = 0xC000000D
    STATUS_END_OF_FILE = 0xC0000011
    STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
    STATUS_ACCESS_DENIED = 0xC0000022
    STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
    STATUS_SHARING_VIOLATION = 0xC0000043
    STATUS_LOGON_FAILURE = 0xC000006D
    STATUS_PASSWORD_EXPIRED = 0xC0000071
    STATUS_INSUFFICIENT_RESOURCES = 0xC000009A
    STATUS_PIPE_BUSY = 0xC00000AE
    STATUS_FILE_IS_A_DIRECTORY = 0xC00000BA
    STATUS_NOT_SUPPORTED = 0xC00000BB
    STATUS_BAD_NETWORK_NAME = 0xC00000CC
    STATUS_REQUEST_NOT_ACCEPTED = 0xC00000D0
    STATUS_NOT_A_DIRECTORY = 0xC0000103
    STATUS_FILE_CLOSED = 0xC0000128
    STATUS_PIPE_BROKEN = 0xC000014B
    STATUS_USER_SESSION_DELETED = 0xC0000203
