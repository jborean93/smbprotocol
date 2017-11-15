import struct

from smbprotocol.structure import Structure, IntField, BytesField, \
    ListField, UuidField, DateTimeField, StructureField
from smbprotocol.constants import Dialects, NegotiateContextType

try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict


# value lambda is executed when we call .pack()
# size lambda is executed when .set_value()
# None is \x00 * size
class DirectTCPPacket(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.1 Transport
    The Directory TCP transport packet header MUST have the following
    structure.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('stream_protocol_length', IntField(
                size=4,
                byte_order='>',
                default=lambda s: len(s['smb2_message']),
            )),
            ('smb2_message', StructureField(
                size=lambda s: s['stream_protocol_length'].get_value(),
                structure_type=SMB2PacketHeader,
            )),
        ])
        super(DirectTCPPacket, self).__init__()


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
            ('flags2', IntField(size=2)),
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
            ('status', IntField(size=4)),
            ('command', IntField(size=2)),
            ('credit', IntField(size=2)),
            ('flags', IntField(size=4)),
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
            ('command', IntField(size=2)),
            ('credit', IntField(size=2)),
            ('flags', IntField(size=4)),
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
                unpack_func=lambda s, d: self._error_data_value(s, d)
            )),
        ])
        super(SMB2ErrorResponse, self).__init__()

    def _error_data_value(self, structure, data):
        # parse raw bytes into a list we can iterate through
        # TODO: add code to parse data into a list
        return []


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
            ('error_id', IntField(size=4)),
            ('error_context_data', BytesField(
                size=lambda s: s['error_data_length'].get_value(),
            )),
        ])
        super(SMB2ErrorContextResponse, self).__init__()


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
            ('security_mode', IntField(size=2)),
            ('reserved', BytesField(
                size=2,
                default=b"\x00" * 2
            )),
            ('capabilities', IntField(size=4)),
            ('client_guid', UuidField()),
            ('client_start_time', BytesField(size=8)),
            ('dialects', ListField(
                size=lambda s: s['dialect_count'].get_value() * 2,
                list_count=lambda s: s['dialect_count'].get_value(),
                list_type=IntField(size=2),
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
            ('security_mode', IntField(size=2)),
            ('reserved', BytesField(
                size=2,
                default=b"\x00" * 2
            )),
            ('capabilities', IntField(size=4)),
            ('client_guid', UuidField()),
            ('negotiate_context_offset', IntField(
                size=4,
                default=lambda s: self._negotiate_context_offset_value(s),
            )),
            ('negotiate_context_count', IntField(
                size=2,
                default=lambda s: len(s['negotiate_context_list'].get_value()),
            )),
            ('reserved2', BytesField(
                size=2,
                default=b"\x00" * 2
            )),
            ('dialects', ListField(
                size=lambda s: s['dialect_count'].get_value() * 2,
                list_count=lambda s: s['dialect_count'].get_value(),
                list_type=IntField(size=2),
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
        # Padding between the end of the Dialects array and the first Negotiate
        # context value so that the first value is 8-byte aligned.
        mod = len(structure['dialects']) % 8
        if len(structure['dialects']) <= 8:
            return 8 - mod
        else:
            return mod

    def _negotiate_context_list(self, structure, data):
        # TODO: add this work in here
        pass


class SMB2NegotiateContextRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.3.1 SMB2 NEGOTIATE_CONTEXT Request Values
    The SMB2_NEGOTIATE_CONTEXT structure is used by the SMB2 NEGOTIATE Request
    and the SMB2 NEGOTIATE Response to encode additional properties.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('context_type', IntField(size=2)),
            ('data_length', IntField(
                size=2,
                default=lambda s: len(s['data'].get_value()),
            )),
            ('reserved', IntField(size=4)),
            ('data', StructureField(
                size=lambda s: s['data_length'].get_value(),
                structure_type=lambda s: self._data_structure_type(s)
            )),
        ])
        super(SMB2NegotiateContextRequest, self).__init__()

    def _data_structure_type(self, structure):
        con_type = structure['context_type']
        if con_type == \
                NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
            return SMB2PreauthIntegrityCapabilities
        elif con_type == NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES:
            return SMB2EncryptionCapabilities
        else:
            raise Exception("Could not detect type of "
                            "SMB2NegotiateContextRequest data type %d"
                            % con_type)


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
                list_type=IntField(size=2),
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
                list_type=IntField(size=2),
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
            ('security_mode', IntField(size=2)),
            ('dialect_revision', IntField(size=2)),
            ('negotiate_context_count', IntField(
                size=2,
                default=lambda s: self._negotiate_context_count_value(s),
            )),
            ('server_guid', UuidField()),
            ('capabilities', IntField(size=4)),
            ('max_transact_size', IntField(size=4)),
            ('max_read_size', IntField(size=4)),
            ('max_write_size', IntField(size=4)),
            ('system_time', DateTimeField()),
            ('server_start_time', DateTimeField()),
            ('security_buffer_offset', IntField(
                size=2,
                default=128,  # Header size = 64 + response size = 64
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
        # context value so that the first value is 8-byte aligned.
        mod = structure['security_buffer_length'].get_value() % 8
        if structure['security_buffer_length'].get_value() <= 8:
            return 8 - mod
        else:
            return mod

    def _negotiate_context_list(self, structure, data):
        # handle no list
        if data == b'':
            return []

        context_list = []
        while True:
            field, data = \
                self._parse_negotiate_context_entry(data)
            context_list.append(field)
            if data == b"":
                break

        return context_list

    def _parse_negotiate_context_entry(self, data):
        context_type = struct.unpack("<H", data[0:2])[0]
        data_length = struct.unpack("<H", data[2:4])[0]
        if context_type == \
                NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
            structure_type = SMB2PreauthIntegrityCapabilities
        elif context_type == NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES:
            structure_type = SMB2EncryptionCapabilities
        else:
            raise Exception("TODO: Better error, unknown context_type")

        field = StructureField(
            structure_type=structure_type,
            size=data_length,
            default=data[8:data_length + 8]
        )
        field.name = "context_list entry"
        field.set_value(field.default)
        return field, data[8 + data_length:]
