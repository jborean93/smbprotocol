# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from collections import OrderedDict

from smbprotocol.structure import BytesField, EnumField, FlagField, IntField, Structure


class Commands:
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


class NtStatus:
    """
    [MS-ERREF] https://msdn.microsoft.com/en-au/library/cc704588.aspx

    2.3.1 NTSTATUS Values
    These values are set in the status field of an SMB2Header response. This is
    not an exhaustive list but common values that are returned.
    """

    STATUS_SUCCESS = 0x00000000
    STATUS_UNSUCCESSFUL = 0xC0000001
    STATUS_NETWORK_NAME_DELETED = 0xC00000C9
    STATUS_PENDING = 0x00000103
    STATUS_NOTIFY_CLEANUP = 0x0000010B
    STATUS_NOTIFY_ENUM_DIR = 0x0000010C
    STATUS_BUFFER_OVERFLOW = 0x80000005
    STATUS_NO_MORE_FILES = 0x80000006
    STATUS_END_OF_FILE = 0xC0000011
    STATUS_INVALID_EA_NAME = 0x80000013
    STATUS_EA_LIST_INCONSISTENT = 0x80000014
    STATUS_STOPPED_ON_SYMLINK = 0x8000002D
    STATUS_INVALID_INFO_CLASS = 0xC0000003
    STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
    STATUS_INVALID_PARAMETER = 0xC000000D
    STATUS_NO_SUCH_FILE = 0xC000000F
    STATUS_INVALID_DEVICE_REQUEST = 0xC0000010
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
    STATUS_DELETE_PENDING = 0xC0000056
    STATUS_PRIVILEGE_NOT_HELD = 0xC0000061
    STATUS_WRONG_PASSWORD = 0xC000006A
    STATUS_LOGON_FAILURE = 0xC000006D
    STATUS_PASSWORD_EXPIRED = 0xC0000071
    STATUS_NONE_MAPPED = 0xC0000073
    STATUS_INSUFFICIENT_RESOURCES = 0xC000009A
    STATUS_PIPE_NOT_AVAILABLE = 0xC00000AC
    STATUS_PIPE_BUSY = 0xC00000AE
    STATUS_PIPE_DISCONNECTED = 0xC00000B0
    STATUS_PIPE_CLOSING = 0xC00000B1
    STATUS_IO_TIMEOUT = 0xC00000B5
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
    STATUS_FS_DRIVER_REQUIRED = 0xC000019C
    STATUS_USER_SESSION_DELETED = 0xC0000203
    STATUS_INSUFF_SERVER_RESOURCES = 0xC0000205
    STATUS_NOT_FOUND = 0xC0000225
    STATUS_PATH_NOT_COVERED = 0xC0000257
    STATUS_DFS_UNAVAILABLE = 0xC000026D
    STATUS_NOT_A_REPARSE_POINT = 0xC0000275
    STATUS_SERVER_UNAVAILABLE = 0xC0000466
    STATUS_DISK_FULL = 0xC000007F


class Smb2Flags:
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


class SMB2HeaderAsync(Structure):
    """
    [MS-SMB2] 2.2.1.1 SMB2 Packer Header - ASYNC
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ea4560b7-90da-4803-82b5-344754b92a79

    The SMB2 Packet header for async commands.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                (
                    "protocol_id",
                    BytesField(
                        size=4,
                        default=b"\xfeSMB",
                    ),
                ),
                (
                    "structure_size",
                    IntField(
                        size=2,
                        default=64,
                    ),
                ),
                ("credit_charge", IntField(size=2)),
                ("channel_sequence", IntField(size=2)),
                ("reserved", IntField(size=2)),
                (
                    "command",
                    EnumField(
                        size=2,
                        enum_type=Commands,
                    ),
                ),
                ("credit_request", IntField(size=2)),
                (
                    "flags",
                    FlagField(
                        size=4,
                        flag_type=Smb2Flags,
                    ),
                ),
                ("next_command", IntField(size=4)),
                ("message_id", IntField(size=8)),
                ("async_id", IntField(size=8)),
                ("session_id", IntField(size=8)),
                (
                    "signature",
                    BytesField(
                        size=16,
                        default=b"\x00" * 16,
                    ),
                ),
                ("data", BytesField()),
            ]
        )
        super().__init__()


class SMB2HeaderRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.1.2 SMB2 Packet Header - SYNC
    This is the header definition that contains the ChannelSequence/Reserved
    instead of the Status field used for a Packet request.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                (
                    "protocol_id",
                    BytesField(
                        size=4,
                        default=b"\xfeSMB",
                    ),
                ),
                (
                    "structure_size",
                    IntField(
                        size=2,
                        default=64,
                    ),
                ),
                ("credit_charge", IntField(size=2)),
                ("channel_sequence", IntField(size=2)),
                ("reserved", IntField(size=2)),
                ("command", EnumField(size=2, enum_type=Commands)),
                ("credit_request", IntField(size=2)),
                (
                    "flags",
                    FlagField(
                        size=4,
                        flag_type=Smb2Flags,
                    ),
                ),
                ("next_command", IntField(size=4)),
                ("message_id", IntField(size=8)),
                ("process_id", IntField(size=4)),
                ("tree_id", IntField(size=4)),
                ("session_id", IntField(size=8)),
                (
                    "signature",
                    BytesField(
                        size=16,
                        default=b"\x00" * 16,
                    ),
                ),
                ("data", BytesField()),
            ]
        )
        super().__init__()


class SMB2HeaderResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.1.2 SMB2 Packet Header - SYNC
    The header definition for an SMB Response that contains the Status field
    instead of the ChannelSequence/Reserved used for a Packet response.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                (
                    "protocol_id",
                    BytesField(
                        size=4,
                        default=b"\xfeSMB",
                    ),
                ),
                (
                    "structure_size",
                    IntField(
                        size=2,
                        default=64,
                    ),
                ),
                ("credit_charge", IntField(size=2)),
                ("status", EnumField(size=4, enum_type=NtStatus, enum_strict=False)),
                (
                    "command",
                    EnumField(
                        size=2,
                        enum_type=Commands,
                        enum_strict=False,
                    ),
                ),
                ("credit_response", IntField(size=2)),
                (
                    "flags",
                    FlagField(
                        size=4,
                        flag_type=Smb2Flags,
                    ),
                ),
                ("next_command", IntField(size=4)),
                ("message_id", IntField(size=8)),
                ("reserved", IntField(size=4)),
                ("tree_id", IntField(size=4)),
                ("session_id", IntField(size=8)),
                (
                    "signature",
                    BytesField(
                        size=16,
                        default=b"\x00" * 16,
                    ),
                ),
                ("data", BytesField()),
            ]
        )
        super().__init__()
