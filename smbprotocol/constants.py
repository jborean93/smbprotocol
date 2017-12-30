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


class NtStatus(object):
    """
    [MS-ERREF] https://msdn.microsoft.com/en-au/library/cc704588.aspx

    2.3.1 NTSTATUS Values
    These values are set in the status field of an SMB2Header response. This is
    not an exhaustive list but common values that are returned.
    """
    STATUS_SUCCESS = 0x00000000
    STATUS_INVALID_PARAMETER = 0xC000000D
    STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
    STATUS_ACCESS_DENIED = 0xC0000022
    STATUS_LOGON_FAILURE = 0xC000006D
    STATUS_PASSWORD_EXPIRED = 0xC0000071
    STATUS_INSUFFICIENT_RESOURCES = 0xC000009A
    STATUS_BAD_NETWORK_NAME = 0xC00000CC
    STATUS_REQUEST_NOT_ACCEPTED = 0xC00000D0
    STATUS_USER_SESSION_DELETED = 0xC0000203
