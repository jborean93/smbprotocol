import copy
import hashlib
import hmac
import logging
import os
import struct
import sys
from datetime import datetime
from multiprocessing.dummy import Lock

from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import aead, algorithms

import smbprotocol.exceptions
from smbprotocol.structure import BytesField, DateTimeField, EnumField, \
    FlagField, IntField, ListField, Structure, StructureField, UuidField
from smbprotocol.transport import Tcp

try:
    from collections import OrderedDict
except ImportError:  # pragma: no cover
    from ordereddict import OrderedDict

if sys.version[0] == '2':
    from Queue import Empty
else:
    from queue import Empty

log = logging.getLogger(__name__)


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

    @staticmethod
    def get_supported_ciphers():
        supported_ciphers = []
        try:
            aead.AESGCM(b"\x00" * 16)
            supported_ciphers.append(Ciphers.AES_128_GCM)
        except UnsupportedAlgorithm:  # pragma: no cover
            pass
        try:
            aead.AESCCM(b"\x00" * 16)
        except UnsupportedAlgorithm:  # pragma: no cover
            pass
        return supported_ciphers


class NtStatus(object):
    """
    [MS-ERREF] https://msdn.microsoft.com/en-au/library/cc704588.aspx

    2.3.1 NTSTATUS Values
    These values are set in the status field of an SMB2Header response. This is
    not an exhaustive list but common values that are returned.
    """
    STATUS_SUCCESS = 0x00000000
    STATUS_PENDING = 0x00000103
    STATUS_EA_LIST_INCONSISTENT = 0x80000014
    STATUS_STOPPED_ON_SYMLINK = 0x8000002D
    STATUS_INVALID_PARAMETER = 0xC000000D
    STATUS_END_OF_FILE = 0xC0000011
    STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
    STATUS_ACCESS_DENIED = 0xC0000022
    STATUS_BUFFER_TOO_SMALL = 0xC0000023
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


class SMB1PacketHeader(Structure):
    """
    [MS-SMB] v46.0 2017-0-01

    2.2.3.1 SMB Header Extensions
    Used in the initial negotiation process, the SMBv1 header must be sent
    with the SMBv1 Negotiate Request packet in order to determine if the server
    supports SMBv2+.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('protocol', BytesField(
                size=4,
                default=b'\xffSMB',
            )),
            ('command', IntField(size=1)),
            ('status', IntField(size=4)),
            ('flags', IntField(size=1)),
            ('flags2', FlagField(
                size=2,
                flag_type=Smb1Flags2,
            )),
            ('pid_high', IntField(size=2)),
            ('security_features', IntField(size=8)),
            ('reserved', IntField(size=2)),
            ('tid', IntField(size=2)),
            ('pid_low', IntField(size=2)),
            ('uid', IntField(size=2)),
            ('mid', IntField(size=2)),
            ('data', StructureField(
                structure_type=SMB1NegotiateRequest
            ))
        ])
        super(SMB1PacketHeader, self).__init__()


class SMB2PacketHeader(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.1.2 SMB2 Packet Header - SYNC
    The header of all SMBv2 Protocol requests and responses. This is the SYNC
    form of the header is is used for all server responses and on client
    requests if SMBv2 was negotiated. If SMBv3 was negotiated then
    SMB3PacketHeader is used on all client requests.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('protocol_id', BytesField(
                size=4,
                default=b'\xfeSMB',
            )),
            ('structure_size', IntField(
                size=2,
                default=64,
            )),
            ('credit_charge', IntField(size=2)),
            ('status', EnumField(
                size=4,
                enum_type=NtStatus,
                enum_strict=False
            )),
            ('command', EnumField(
                size=2,
                enum_type=Commands
            )),
            ('credit', IntField(size=2)),
            ('flags', FlagField(
                size=4,
                flag_type=Smb2Flags,
            )),
            ('next_command', IntField(size=4)),
            ('message_id', IntField(size=8)),
            ('reserved', IntField(size=4)),
            ('tree_id', IntField(size=4)),
            ('session_id', IntField(size=8)),
            ('signature', BytesField(
                size=16,
                default=b"\x00" * 16,
            )),
            ('data', BytesField()),
        ])
        super(SMB2PacketHeader, self).__init__()


class SMB3PacketHeader(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.1.2 SMB2 Packet Header - SYNC
    This is the same as SMB2PacketHeader except it contains the
    channel_sequence + reserved fields instead of status. This is used on all
    client requests if the Dialect negotiated is v3.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('protocol_id', BytesField(
                size=4,
                default=b"\xfeSMB",
            )),
            ('structure_size', IntField(
                size=2,
                default=64,
            )),
            ('credit_charge', IntField(size=2)),
            ('channel_sequence', IntField(size=2)),
            ('reserved', IntField(size=2)),
            ('command', EnumField(
                size=2,
                enum_type=Commands
            )),
            ('credit', IntField(size=2)),
            ('flags', FlagField(
                size=4,
                flag_type=Smb2Flags,
            )),
            ('next_command', IntField(size=4)),
            ('message_id', IntField(size=8)),
            ('process_id', IntField(size=4)),
            ('tree_id', IntField(size=4)),
            ('session_id', IntField(size=8)),
            ('signature', BytesField(
                size=16,
                default=b"\x00" * 16,
            )),
            ('data', BytesField()),
        ])
        super(SMB3PacketHeader, self).__init__()


class SMB1NegotiateRequest(Structure):
    """
    [MS-CIFS] v27.0 2017-06-01

    2.2.4.52 SMB_COM_NEGOTIATE (0x72)
    The command is used to initial an SMB connection between the client and
    the server. This is used only in the initial negotiation process to
    determine whether SMBv2+ is supported on the server.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('word_count', IntField(size=1)),
            ('byte_count', IntField(
                size=2,
                default=lambda s: len(s['dialects']),
            )),
            ('dialects', BytesField(
                size=lambda s: s['byte_count'].get_value(),
            )),
        ])
        super(SMB1NegotiateRequest, self).__init__()


class SMB2NegotiateRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.3 SMB2 Negotiate Request
    The SMB2 NEGOTIATE Request packet is used by the client to notify the
    server what dialects of the SMB2 Protocol the client understands. This is
    only used if the client explicitly sets the Dialect to use to a version
    less than 3.1.1. Dialect 3.1.1 added support for negotiate_context and
    SMB3NegotiateRequest should be used to support that.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=36,
            )),
            ('dialect_count', IntField(
                size=2,
                default=lambda s: len(s['dialects'].get_value()),
            )),
            ('security_mode', FlagField(
                size=2,
                flag_type=SecurityMode
            )),
            ('reserved', IntField(size=2)),
            ('capabilities', FlagField(
                size=4,
                flag_type=Capabilities,
            )),
            ('client_guid', UuidField()),
            ('client_start_time', IntField(size=8)),
            ('dialects', ListField(
                size=lambda s: s['dialect_count'].get_value() * 2,
                list_count=lambda s: s['dialect_count'].get_value(),
                list_type=EnumField(size=2, enum_type=Dialects),
            )),
        ])

        super(SMB2NegotiateRequest, self).__init__()


class SMB3NegotiateRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.3 SMB2 Negotiate Request
    Like SMB2NegotiateRequest but with support for setting a list of
    Negotiate Context values. This is used by default and is for Dialects 3.1.1
    or greater.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=36,
            )),
            ('dialect_count', IntField(
                size=2,
                default=lambda s: len(s['dialects'].get_value()),
            )),
            ('security_mode', FlagField(
                size=2,
                flag_type=SecurityMode,
            )),
            ('reserved', IntField(size=2)),
            ('capabilities', FlagField(
                size=4,
                flag_type=Capabilities,
            )),
            ('client_guid', UuidField()),
            ('negotiate_context_offset', IntField(
                size=4,
                default=lambda s: self._negotiate_context_offset_value(s),
            )),
            ('negotiate_context_count', IntField(
                size=2,
                default=lambda s: len(s['negotiate_context_list'].get_value()),
            )),
            ('reserved2', IntField(size=2)),
            ('dialects', ListField(
                size=lambda s: s['dialect_count'].get_value() * 2,
                list_count=lambda s: s['dialect_count'].get_value(),
                list_type=EnumField(size=2, enum_type=Dialects),
            )),
            ('padding', BytesField(
                size=lambda s: self._padding_size(s),
                default=lambda s: b"\x00" * self._padding_size(s),
            )),
            ('negotiate_context_list', ListField(
                list_count=lambda s: s['negotiate_context_count'].get_value(),
                unpack_func=lambda s, d: self._negotiate_context_list(s, d),
            )),
        ])
        super(SMB3NegotiateRequest, self).__init__()

    def _negotiate_context_offset_value(self, structure):
        # The offset from the beginning of the SMB2 header to the first, 8-byte
        # aligned, negotiate context
        header_size = 64
        negotiate_size = structure['structure_size'].get_value()
        dialect_size = len(structure['dialects'])
        padding_size = self._padding_size(structure)
        return header_size + negotiate_size + dialect_size + padding_size

    def _padding_size(self, structure):
        # Padding between the end of the buffer value and the first Negotiate
        # context value so that the first value is 8-byte aligned. Padding is
        # 4 is there are no dialects specified
        mod = (structure['dialect_count'].get_value() * 2) % 8
        return 0 if mod == 0 else mod

    def _negotiate_context_list(self, structure, data):
        context_count = structure['negotiate_context_count'].get_value()
        context_list = []
        for idx in range(0, context_count):
            field, data = self._parse_negotiate_context_entry(data, idx)
            context_list.append(field)

        return context_list

    def _parse_negotiate_context_entry(self, data, idx):
        data_length = struct.unpack("<H", data[2:4])[0]
        negotiate_context = SMB2NegotiateContextRequest()
        negotiate_context.unpack(data[:data_length + 8])
        return negotiate_context, data[8 + data_length:]


class SMB2NegotiateContextRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.3.1 SMB2 NEGOTIATE_CONTEXT Request Values
    The SMB2_NEGOTIATE_CONTEXT structure is used by the SMB2 NEGOTIATE Request
    and the SMB2 NEGOTIATE Response to encode additional properties.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('context_type', EnumField(
                size=2,
                enum_type=NegotiateContextType,
            )),
            ('data_length', IntField(
                size=2,
                default=lambda s: len(s['data'].get_value()),
            )),
            ('reserved', IntField(size=4)),
            ('data', StructureField(
                size=lambda s: s['data_length'].get_value(),
                structure_type=lambda s: self._data_structure_type(s)
            )),
            # not actually a field but each list entry must start at the 8 byte
            # alignment
            ('padding', BytesField(
                size=lambda s: self._padding_size(s),
                default=lambda s: b"\x00" * self._padding_size(s),
            ))
        ])
        super(SMB2NegotiateContextRequest, self).__init__()

    def _data_structure_type(self, structure):
        con_type = structure['context_type'].get_value()
        if con_type == \
                NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
            return SMB2PreauthIntegrityCapabilities
        elif con_type == NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES:
            return SMB2EncryptionCapabilities

    def _padding_size(self, structure):
        data_size = len(structure['data'])
        return 8 - data_size if data_size <= 8 else 8 - (data_size % 8)


class SMB2PreauthIntegrityCapabilities(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.3.1.1 SMB2_PREAUTH_INTEGRITY_CAPABILITIES
    The SMB2_PREAUTH_INTEGRITY_CAPABILITIES context is specified in an SMB2
    NEGOTIATE request by the client to indicate which preauthentication
    integrity hash algorithms it supports and to optionally supply a
    preauthentication integrity hash salt value.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('hash_algorithm_count', IntField(
                size=2,
                default=lambda s: len(s['hash_algorithms'].get_value()),
            )),
            ('salt_length', IntField(
                size=2,
                default=lambda s: len(s['salt']),
            )),
            ('hash_algorithms', ListField(
                size=lambda s: s['hash_algorithm_count'].get_value() * 2,
                list_count=lambda s: s['hash_algorithm_count'].get_value(),
                list_type=EnumField(size=2, enum_type=HashAlgorithms),
            )),
            ('salt', BytesField(
                size=lambda s: s['salt_length'].get_value(),
            )),
        ])
        super(SMB2PreauthIntegrityCapabilities, self).__init__()


class SMB2EncryptionCapabilities(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.3.1.2 SMB2_ENCRYPTION_CAPABILITIES
    The SMB2_ENCRYPTION_CAPABILITIES context is specified in an SMB2 NEGOTIATE
    request by the client to indicate which encryption algorithms the client
    supports.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('cipher_count', IntField(
                size=2,
                default=lambda s: len(s['ciphers'].get_value()),
            )),
            ('ciphers', ListField(
                size=lambda s: s['cipher_count'].get_value() * 2,
                list_count=lambda s: s['cipher_count'].get_value(),
                list_type=EnumField(size=2, enum_type=Ciphers),
            )),
        ])
        super(SMB2EncryptionCapabilities, self).__init__()


class SMB2NegotiateResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.4 SMB2 NEGOTIATE Response
    The SMB2 NEGOTIATE Response packet is sent by the server to notify the
    client of the preferred common dialect.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=65,
            )),
            ('security_mode', FlagField(
                size=2,
                flag_type=SecurityMode,
            )),
            ('dialect_revision', EnumField(
                size=2,
                enum_type=Dialects,
            )),
            ('negotiate_context_count', IntField(
                size=2,
                default=lambda s: self._negotiate_context_count_value(s),
            )),
            ('server_guid', UuidField()),
            ('capabilities', FlagField(
                size=4,
                flag_type=Capabilities
            )),
            ('max_transact_size', IntField(size=4)),
            ('max_read_size', IntField(size=4)),
            ('max_write_size', IntField(size=4)),
            ('system_time', DateTimeField()),
            ('server_start_time', DateTimeField()),
            ('security_buffer_offset', IntField(
                size=2,
                default=128,  # (header size 64) + (structure size 64)
            )),
            ('security_buffer_length', IntField(
                size=2,
                default=lambda s: len(s['buffer'].get_value()),
            )),
            ('negotiate_context_offset', IntField(
                size=4,
                default=lambda s: self._negotiate_context_offset_value(s),
            )),
            ('buffer', BytesField(
                size=lambda s: s['security_buffer_length'].get_value(),
            )),
            ('padding', BytesField(
                size=lambda s: self._padding_size(s),
                default=lambda s: b"\x00" * self._padding_size(s),
            )),
            ('negotiate_context_list', ListField(
                list_count=lambda s: s['negotiate_context_count'].get_value(),
                unpack_func=lambda s, d:
                self._negotiate_context_list(s, d),
            )),
        ])
        super(SMB2NegotiateResponse, self).__init__()

    def _negotiate_context_count_value(self, structure):
        # If the dialect_revision is SMBv3.1.1, this field specifies the
        # number of negotiate contexts in negotiate_context_list; otherwise
        # this field must not be used and must be reserved (0).
        if structure['dialect_revision'].get_value() == Dialects.SMB_3_1_1:
            return len(structure['negotiate_context_list'].get_value())
        else:
            return None

    def _negotiate_context_offset_value(self, structure):
        # If the dialect_revision is SMBv3.1.1, this field specifies the offset
        # from the beginning of the SMB2 header to the first 8-byte
        # aligned negotiate context entry in negotiate_context_list; otherwise
        # this field must not be used and must be reserved (0).
        if structure['dialect_revision'].get_value() == Dialects.SMB_3_1_1:
            buffer_offset = structure['security_buffer_offset'].get_value()
            buffer_size = structure['security_buffer_length'].get_value()
            padding_size = self._padding_size(structure)
            return buffer_offset + buffer_size + padding_size
        else:
            return None

    def _padding_size(self, structure):
        # Padding between the end of the buffer value and the first Negotiate
        # context value so that the first value is 8-byte aligned. Padding is
        # not required if there are not negotiate contexts
        if structure['negotiate_context_count'].get_value() == 0:
            return 0

        mod = structure['security_buffer_length'].get_value() % 8
        return 0 if mod == 0 else 8 - mod

    def _negotiate_context_list(self, structure, data):
        context_count = structure['negotiate_context_count'].get_value()
        context_list = []
        for idx in range(0, context_count):
            field, data = self._parse_negotiate_context_entry(data)
            context_list.append(field)

        return context_list

    def _parse_negotiate_context_entry(self, data):
        data_length = struct.unpack("<H", data[2:4])[0]
        negotiate_context = SMB2NegotiateContextRequest()
        negotiate_context.unpack(data[:data_length + 8])
        padded_size = data_length % 8
        if padded_size != 0:
            padded_size = 8 - padded_size

        return negotiate_context, data[8 + data_length + padded_size:]


class SMB2TransformHeader(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.41 SMB@ TRANSFORM_HEADER
    The SMB2 Transform Header is used by the client or server when sending
    encrypted message. This is only valid for the SMB.x dialect family.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('protocol_id', BytesField(
                size=4,
                default=b"\xfdSMB"
            )),
            ('signature', BytesField(
                size=16,
                default=b"\x00" * 16
            )),
            ('nonce', BytesField(size=16)),
            ('original_message_size', IntField(size=4)),
            ('reserved', IntField(size=2, default=0)),
            ('flags', IntField(
                size=2,
                default=1
            )),
            ('session_id', IntField(size=8)),
            ('data', BytesField())  # not in spec
        ])
        super(SMB2TransformHeader, self).__init__()


class Connection(object):

    def __init__(self, guid, server_name, port, require_signing=True):
        """
        [MS-SMB2] v53.0 2017-09-15

        3.2.1.2 Per SMB2 Transport Connection
        Used as the transport interface for a server. Some values have been
        omitted as they can be retrieved by the Server object stored in
        self.server

        :param guid: A uniqure guid that represents the client
        :param server_name: The server to start the connection
        :param port: The port to use for the transport
        :param require_signing: Whether signing is required on SMB messages
            sent over this connection
        """
        log.info("Initialising connection, guid: %s, require_singing: %s, "
                 "server_name: %s, port: %d"
                 % (guid, require_signing, server_name, port))
        self.server_name = server_name
        self.port = port
        self.transport = Tcp(server_name, port)

        # Table of Session entries
        self.session_table = {}

        # Table of sessions that have not completed authentication, indexed by
        # session_id
        self.preauth_session_table = {}

        # Table of Requests that have yet to be picked up by the application,
        # it MAY contain a response from the server as well
        self.outstanding_requests = dict()

        # Table of available sequence numbers
        self.sequence_window = dict(
            low=0,
            high=0
        )

        # Byte array containing the negotiate token and remembered for
        # authentication
        self.gss_negotiate_token = None

        self.server_guid = None
        self.max_transact_size = None
        self.max_read_size = None
        self.max_write_size = None
        self.require_signing = require_signing

        # SMB 2.1+
        self.dialect = None
        self.supports_file_leasing = None
        self.supports_multi_credit = None
        self.client_guid = guid

        # SMB 3.x+
        self.salt = None
        self.supports_directory_leasing = None
        self.supports_multi_channel = None
        self.supports_persistent_handles = None
        self.supports_encryption = None

        # used for SMB 3.x for secure negotiate verification on tree connect
        self.negotiated_dialects = []

        # TODO: Add more capabilities
        self.client_capabilities = Capabilities.SMB2_GLOBAL_CAP_ENCRYPTION
        self.client_security_mode = \
            SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED if \
            require_signing else SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        self.server_security_mode = None
        self.server_capabilities = None

        # SMB 3.1.1+
        # The hashing algorithm object that was negotiated
        self.preauth_integrity_hash_id = None

        # Preauth integrity hash value computed for the SMB2 NEGOTIATE request
        # contains the messages used to compute the hash
        self.preauth_integrity_hash_value = []

        # The cipher object that was negotiated
        self.cipher_id = None

        # used to ensure sequence num/message id's are gathered/sent in the
        # same order if running in multiple threads
        self.lock = Lock()

    def connect(self, dialect=None):
        """
        Will connect to the target server and negotiate the capabilities
        with the client. Once setup, the client MUST call the disconnect()
        function to close the listener thread. This function will populate
        various connection properties that denote the capabilities of the
        server.

        :param dialect: If specified, forces the dialect that is negotiated
            with the server, if not set, then the newest dialect supported by
            the server is used up to SMB 3.1.1
        """
        log.info("Setting up transport connection")
        self.transport.connect()

        log.info("Starting negotiation with SMB server")
        smb_response = self._send_smb1_negotiate(dialect)

        # Renegotiate with SMB2NegotiateRequest if 2.??? was received back
        if smb_response['dialect_revision'].get_value() == \
                Dialects.SMB_2_WILDCARD:
            smb_response = self._send_smb2_negotiate(dialect)

        log.info("Negotiated dialect: %s"
                 % str(smb_response['dialect_revision']))
        self.dialect = smb_response['dialect_revision'].get_value()
        self.max_transact_size = smb_response['max_transact_size'].get_value()
        self.max_read_size = smb_response['max_read_size'].get_value()
        self.max_write_size = smb_response['max_write_size'].get_value()
        self.server_guid = smb_response['server_guid'].get_value()
        self.gss_negotiate_token = smb_response['buffer'].get_value()

        if not self.require_signing and \
                smb_response['security_mode'].get_value() == \
                SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED:
            self.require_signing = True
        log.info("Connection require signing: %s" % self.require_signing)
        capabilities = smb_response['capabilities']

        # SMB 2.1
        if self.dialect >= Dialects.SMB_2_1_0:
            self.supports_file_leasing = \
                capabilities.has_flag(Capabilities.SMB2_GLOBAL_CAP_LEASING)
            self.supports_multi_credit = \
                capabilities.has_flag(Capabilities.SMB2_GLOBAL_CAP_MTU)

        # SMB 3.x
        if self.dialect >= Dialects.SMB_3_0_0:
            self.supports_directory_leasing = capabilities.has_flag(
                Capabilities.SMB2_GLOBAL_CAP_DIRECTORY_LEASING)
            self.supports_multi_channel = capabilities.has_flag(
                Capabilities.SMB2_GLOBAL_CAP_MULTI_CHANNEL)

            # TODO: SMB2_GLOBAL_CAP_PERSISTENT_HANDLES
            self.supports_persistent_handles = False
            self.supports_encryption = capabilities.has_flag(
                Capabilities.SMB2_GLOBAL_CAP_ENCRYPTION) \
                and self.dialect < Dialects.SMB_3_1_1
            self.server_capabilities = capabilities
            self.server_security_mode = \
                smb_response['security_mode'].get_value()

            # TODO: Check/add server to server_list in Client Page 203

        # SMB 3.1
        if self.dialect >= Dialects.SMB_3_1_1:
            for context in smb_response['negotiate_context_list']:
                if context['context_type'].get_value() == \
                        NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES:
                    cipher_id = context['data']['ciphers'][0]
                    self.cipher_id = Ciphers.get_cipher(cipher_id)
                    self.supports_encryption = self.cipher_id != 0
                else:
                    hash_id = context['data']['hash_algorithms'][0]
                    self.preauth_integrity_hash_id = \
                        HashAlgorithms.get_algorithm(hash_id)

    def disconnect(self, close=True):
        """
        Closes the connection as well as logs off any of the
        Disconnects the TCP connection and shuts down the socket listener
        running in a thread.

        :param close: Will close all sessions in the connection as well as the
            tree connections of each session.
        """
        if close:
            for session in list(self.session_table.values()):
                session.disconnect(True)

        log.info("Disconnecting transport connection")
        self.transport.disconnect()

    def send(self, message, command, session=None, tree=None):
        """
        Will send a message to the server that is passed in. The final
        unencrypted header is returned to the function that called this.

        :param message: An SMB message structure to send
        :param command: The Commands value that is set on the SMB Header
        :param session: A Session object that the message is sent for
        :param tree: A TreeConnect object that the message is sent for
        :return: SMB2PacketHeader or SMB3PacketHeader of the final message sent
        """
        if command == Commands.SMB2_NEGOTIATE:
            header = SMB2PacketHeader()
        elif self.dialect < Dialects.SMB_3_0_0:
            header = SMB2PacketHeader()
        else:
            header = SMB3PacketHeader()

        header['command'] = command

        if session:
            header['session_id'] = session.session_id
        if tree:
            header['tree_id'] = tree.tree_connect_id

        # when run in a thread or subprocess, getting the message id and
        # sending the messages in order are important
        self.lock.acquire()
        # TODO: pass through the message id to cancel
        message_id = 0
        if command != Commands.SMB2_CANCEL:
            message_id = self.sequence_window['low']
            self._increment_sequence_windows(1)

        header['message_id'] = message_id
        log.info("Sending SMB Header for %s request" % str(header['command']))
        log.debug(str(header))

        # now add the actual data so we don't pollute the logs too much
        header['data'] = message

        if (session and session.encrypt_data) or (tree and tree.encrypt_data):
            final_header = self._encrypt(header, session)
        elif session and session.signing_required and session.signing_key:
            self._sign(header, session)
            final_header = header
        else:
            final_header = header

        request = Request(final_header)
        self.outstanding_requests[message_id] = request
        self.transport.send(request)
        self.lock.release()

        return header

    def receive(self, message_id):
        """
        Polls the message buffer of the TCP connection and waits until a valid
        message is received based on the message_id passed in.

        :param message_id: The message id to wait for
        :return: SMB2PacketHeader or SMB3PacketHeader of the received message
        """
        request = self.outstanding_requests.get(message_id, None)
        if not request:
            error_msg = "No request with the ID %d is expecting a response"\
                        % message_id
            raise smbprotocol.exceptions.SMBException(error_msg)

        # check if we have received a response
        response = None
        if request.response:
            response = request.response
        else:
            # otherwise wait until we receive a response
            while not response:
                self._flush_message_buffer()
                request = self.outstanding_requests[message_id]
                response = request.response

        status = response['status'].get_value()

        if status == NtStatus.STATUS_PENDING:
            request.response = None
            self.outstanding_requests[message_id] = request

        if status != NtStatus.STATUS_SUCCESS:
            raise smbprotocol.exceptions.SMBResponseException(response, status,
                                                              message_id)

        # now we have a retrieval request for the response, we can delete the
        # request from the outstanding requests
        del self.outstanding_requests[message_id]

        return response

    def _flush_message_buffer(self):
        """
        Loops through the transport message_buffer until there are no messages
        left in the queue. Each response is assigned to the Request object
        based on the message_id which are then available in
        self.outstanding_requests
        """
        while True:
            try:
                message_bytes = self.transport.message_buffer.get(block=False)
            except Empty:
                # raises Empty if wait=False and there are no messages, in this
                # case we have nothing to parse and so break from the loop
                break

            # if bytes then it is an unknown message, if TransformHeader we
            # need to decrypt it
            if message_bytes[:4] == b"\xfeSMB":
                message = SMB2PacketHeader()
                message.unpack(message_bytes)
            elif message_bytes[:4] == b"\xfdSMB":
                message = SMB2TransformHeader()
                message.unpack(message_bytes)
                message = self._decrypt(message)
            else:
                error_msg = "Invalid header '%s' received from the server"\
                            % message_bytes[:4]
                raise smbprotocol.exceptions.SMBException(error_msg)
            self._verify(message)

            message_id = message['message_id'].get_value()
            request = self.outstanding_requests.get(message_id, None)
            if not request:
                raise smbprotocol.exceptions.SMBException("Received request "
                                                          "with an unknown"
                                                          " message ID: %d"
                                                          % message_id)
            request.response = message
            self.outstanding_requests[message_id] = request

    def _sign(self, message, session):
        message['flags'].set_flag(Smb2Flags.SMB2_FLAGS_SIGNED)
        signature = self._generate_signature(message, session)
        message['signature'] = signature

    def _verify(self, message, verify_session=False):
        if message['message_id'].get_value() == 0xFFFFFFFFFFFFFFFF:
            return
        elif not message['flags'].has_flag(Smb2Flags.SMB2_FLAGS_SIGNED):
            return
        elif message['command'].get_value() == Commands.SMB2_SESSION_SETUP \
                and not verify_session:
            return

        session_id = message['session_id'].get_value()
        session = self.session_table.get(session_id, None)
        if session is None:
            error_msg = "Failed to find session %d for message verification" \
                        % session_id
            raise smbprotocol.exceptions.SMBException(error_msg)
        expected = self._generate_signature(message, session)
        actual = message['signature'].get_value()
        if actual != expected:
            error_msg = "Server message signature could not be verified: " \
                        "%s != %s" % (actual, expected)
            raise smbprotocol.exceptions.SMBException(error_msg)

    def _generate_signature(self, message, session):
        msg = copy.deepcopy(message)
        msg['signature'] = b"\x00" * 16
        msg_data = msg.pack()

        if self.dialect >= Dialects.SMB_3_0_0:
            # TODO: work out when to get channel.signing_key
            signing_key = session.signing_key

            c = cmac.CMAC(algorithms.AES(signing_key),
                          backend=default_backend())
            c.update(msg_data)
            signature = c.finalize()
        else:
            signing_key = session.signing_key
            hmac_algo = hmac.new(signing_key, msg=msg_data,
                                 digestmod=hashlib.sha256)
            signature = hmac_algo.digest()[:16]

        return signature

    def _encrypt(self, message, session):
        header = SMB2TransformHeader()
        header['original_message_size'] = len(message)
        header['session_id'] = message['session_id'].get_value()

        encryption_key = session.encryption_key
        if self.dialect >= Dialects.SMB_3_1_1:
            cipher = self.cipher_id
        else:
            cipher = Ciphers.get_cipher(Ciphers.AES_128_CCM)
        if cipher == aead.AESGCM:
            nonce = os.urandom(12)
            header['nonce'] = nonce + (b"\x00" * 4)
        else:
            nonce = os.urandom(11)
            header['nonce'] = nonce + (b"\x00" * 5)

        cipher_text = cipher(encryption_key).encrypt(nonce, message.pack(),
                                                     header.pack()[20:])
        signature = cipher_text[-16:]
        enc_message = cipher_text[:-16]

        header['signature'] = signature
        header['data'] = enc_message

        return header

    def _decrypt(self, message):
        if message['flags'].get_value() != 0x0001:
            error_msg = "Expecting flag of 0x0001 but got %s in the SMB " \
                        "Transform Header Response"\
                        % format(message['flags'].get_value(), 'x')
            raise smbprotocol.exceptions.SMBException(error_msg)

        session_id = message['session_id'].get_value()
        session = self.session_table.get(session_id, None)
        if session is None:
            error_msg = "Failed to find valid session %s for message " \
                        "decryption" % session_id
            raise smbprotocol.exceptions.SMBException(error_msg)

        if self.dialect >= Dialects.SMB_3_1_1:
            cipher = self.cipher_id
        else:
            cipher = Ciphers.get_cipher(Ciphers.AES_128_CCM)

        if cipher == aead.AESGCM:
            nonce = message['nonce'].get_value()[:12]
        else:
            nonce = message['nonce'].get_value()[:11]

        signature = message['signature'].get_value()
        enc_message = message['data'].get_value() + signature

        c = cipher(session.decryption_key)
        dec_message = c.decrypt(nonce, enc_message, message.pack()[20:52])

        packet = SMB2PacketHeader()
        packet.unpack(dec_message)

        return packet

    def _send_smb1_negotiate(self, dialect):
        header = SMB1PacketHeader()
        header['command'] = 0x72  # SMBv1 Negotiate Protocol
        header['flags2'] = Smb1Flags2.SMB_FLAGS2_LONG_NAME | \
            Smb1Flags2.SMB_FLAGS2_EXTENDED_SECURITY | \
            Smb1Flags2.SMB_FLAGS2_NT_STATUS | \
            Smb1Flags2.SMB_FLAGS2_UNICODE
        header['data'] = SMB1NegotiateRequest()
        dialects = b"\x02SMB 2.002\x00"
        if dialect != Dialects.SMB_2_0_2:
            dialects += b"\x02SMB 2.???\x00"
        else:
            self.negotiated_dialects = [Dialects.SMB_2_0_2]
        header['data']['dialects'] = dialects
        request = Request(header)

        log.info("Sending SMB1 Negotiate message with dialects: %s" % dialects)
        log.debug(str(header))
        self.transport.send(request)

        self._increment_sequence_windows(1)
        response = self.transport.message_buffer.get(block=True)
        smb_header = SMB2PacketHeader()
        smb_header.unpack(response)
        log.info("Receiving SMB1 Negotiate response")
        log.debug(str(smb_header))
        smb_response = SMB2NegotiateResponse()
        try:
            smb_response.unpack(smb_header['data'].get_value())
        except ValueError as exc:
            error_msg = "Expecting SMB2NegotiateResponse message in " \
                        "response but could not unpack data for structure: " \
                        "%s" % str(exc)
            raise smbprotocol.exceptions.SMBException(error_msg)

        return smb_response

    def _send_smb2_negotiate(self, dialect):
        self.salt = os.urandom(32)

        if dialect is None:
            neg_req = SMB3NegotiateRequest()
            self.negotiated_dialects = [
                Dialects.SMB_2_0_2,
                Dialects.SMB_2_1_0,
                Dialects.SMB_3_0_0,
                Dialects.SMB_3_0_2,
                Dialects.SMB_3_1_1
            ]
            highest_dialect = Dialects.SMB_3_1_1
        else:
            if dialect >= Dialects.SMB_3_1_1:
                neg_req = SMB3NegotiateRequest()
            else:
                neg_req = SMB2NegotiateRequest()
            self.negotiated_dialects = [
                dialect
            ]
            highest_dialect = dialect
        neg_req['dialects'] = self.negotiated_dialects
        log.info("Negotiating with SMB2 protocol with highest client dialect "
                 "of: %s" % [dialect for dialect, v in vars(Dialects).items()
                             if v == highest_dialect][0])

        neg_req['security_mode'] = self.client_security_mode

        if highest_dialect >= Dialects.SMB_2_1_0:
            log.debug("Adding client guid %s to negotiate request"
                      % self.client_guid)
            neg_req['client_guid'] = self.client_guid

        if highest_dialect >= Dialects.SMB_3_0_0:
            log.debug("Adding client capabilities %d to negotiate request"
                      % self.client_capabilities)
            neg_req['capabilities'] = self.client_capabilities

        if highest_dialect >= Dialects.SMB_3_1_1:
            int_cap = SMB2NegotiateContextRequest()
            int_cap['context_type'] = \
                NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES
            int_cap['data'] = SMB2PreauthIntegrityCapabilities()
            int_cap['data']['hash_algorithms'] = [
                HashAlgorithms.SHA_512
            ]
            int_cap['data']['salt'] = self.salt
            log.debug("Adding preauth integrity capabilities of hash SHA512 "
                      "and salt %s to negotiate request" % self.salt)

            enc_cap = SMB2NegotiateContextRequest()
            enc_cap['context_type'] = \
                NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES
            enc_cap['data'] = SMB2EncryptionCapabilities()
            supported_ciphers = Ciphers.get_supported_ciphers()
            enc_cap['data']['ciphers'] = supported_ciphers
            # remove extra padding for last list entry
            enc_cap['padding'].size = 0
            enc_cap['padding'] = b""
            log.debug("Adding encryption capabilities of AES128 GCM and "
                      "AES128 CCM to negotiate request")

            neg_req['negotiate_context_list'] = [
                int_cap,
                enc_cap
            ]

        log.info("Sending SMB2 Negotiate message")
        log.debug(str(neg_req))
        header = self.send(neg_req, Commands.SMB2_NEGOTIATE)
        self.preauth_integrity_hash_value.append(header)

        response = self.receive(header['message_id'].get_value())
        log.info("Receiving SMB2 Negotiate response")
        log.debug(str(response))
        self.preauth_integrity_hash_value.append(response)

        smb_response = SMB2NegotiateResponse()
        smb_response.unpack(response['data'].get_value())

        return smb_response

    def _increment_sequence_windows(self, credit_charge):
        high_value = self.sequence_window['high']
        self.sequence_window['low'] = high_value + credit_charge
        self.sequence_window['high'] = high_value + credit_charge


class Request(object):

    def __init__(self, message):
        """
        [MS-SMB2] v53.0 2017-09-15

        3.2.1.7 Per Pending Request
        For each request that was sent to the server and is await a response
        :param message: The message to be sent in the request
        """
        self.cancel_id = os.urandom(8)
        self.async_id = os.urandom(8)
        self.message = message
        self.timestamp = datetime.now()

        # not in SMB spec
        # Used to contain the corresponding response from the server as the
        # receiving in done in parallel
        self.response = None
