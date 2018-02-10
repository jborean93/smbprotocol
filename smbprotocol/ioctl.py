from smbprotocol.structure import BytesField, EnumField, FlagField, IntField, \
    ListField, Structure, StructureField, UuidField
from smbprotocol.connection import Capabilities, Dialects, SecurityMode
from smbprotocol.open import SMB2FileId

try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict


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


class SMB2IOCTLRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.31 SMB2 IOCTL Request
    Send by the client to issue an implementation-specific file system control
    or device control command across the network.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(size=2, default=57)),
            ('reserved', IntField(size=2, default=0)),
            ('ctl_code', EnumField(
                size=4,
                enum_type=CtlCode,
            )),
            ('file_id', StructureField(
                size=16,
                structure_type=SMB2FileId
            )),
            ('input_offset', IntField(
                size=4,
                default=lambda s: self._buffer_offset_value(s)
            )),
            ('input_count', IntField(
                size=4,
                default=lambda s: len(s['buffer']),
            )),
            ('max_input_response', IntField(size=4)),
            ('output_offset', IntField(
                size=4,
                default=lambda s: self._buffer_offset_value(s)
            )),
            ('output_count', IntField(size=4, default=0)),
            ('max_output_response', IntField(size=4)),
            ('flags', EnumField(
                size=4,
                enum_type=IOCTLFlags,
            )),
            ('reserved2', IntField(size=4, default=0)),
            ('buffer', BytesField(
                size=lambda s: s['input_count'].get_value()
            ))
        ])
        super(SMB2IOCTLRequest, self).__init__()

    def _buffer_offset_value(self, structure):
        # The offset from the beginning of the SMB2 header to the value of the
        # buffer, 0 if no buffer is set
        if len(structure['buffer']) > 0:
            header_size = 64
            request_size = structure['structure_size'].get_value()
            return header_size + request_size - 1
        else:
            return 0


class SMB2ValidateNegotiateInfoRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.31.4 VALIDATE_NEGOTIATE_INFO Request
    Packet sent to the server to request validation of a previous SMB 2
    NEGOTIATE request.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('capabilities', FlagField(
                size=4,
                flag_type=Capabilities,
            )),
            ('guid', UuidField()),
            ('security_mode', EnumField(
                size=2,
                enum_type=SecurityMode,
            )),
            ('dialect_count', IntField(
                size=2,
                default=lambda s: len(s['dialects'].get_value())
            )),
            ('dialects', ListField(
                size=lambda s: s['dialect_count'].get_value() * 2,
                list_count=lambda s: s['dialect_count'].get_value(),
                list_type=EnumField(size=2, enum_type=Dialects),
            ))
        ])
        super(SMB2ValidateNegotiateInfoRequest, self).__init__()


class SMB2IOCTLResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.32 SMB2 IOCTL Response
    Sent by the server to transmit the results of a client SMB2 IOCTL Request.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(size=2, default=49)),
            ('reserved', IntField(size=2, default=0)),
            ('ctl_code', EnumField(
                size=4,
                enum_type=CtlCode,
            )),
            ('file_id', StructureField(
                size=16,
                structure_type=SMB2FileId
            )),
            ('input_offset', IntField(size=4)),
            ('input_count', IntField(size=4)),
            ('output_offset', IntField(size=4)),
            ('output_count', IntField(size=4)),
            ('flags', IntField(size=4, default=0)),
            ('reserved2', IntField(size=4, default=0)),
            ('buffer', BytesField(
                size=lambda s: s['output_count'].get_value(),
            ))
        ])
        super(SMB2IOCTLResponse, self).__init__()


class SMB2ValidateNegotiateInfoResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.32.6 VALIDATE_NEGOTIATE_INFO Response
    Packet sent by the server on a request validation of SMB 2 negotiate
    request.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('capabilities', FlagField(
                size=4,
                flag_type=Capabilities,
            )),
            ('guid', UuidField()),
            ('security_mode', EnumField(
                size=2,
                enum_type=SecurityMode,
            )),
            ('dialect', EnumField(
                size=2,
                enum_type=Dialects
            ))
        ])
        super(SMB2ValidateNegotiateInfoResponse, self).__init__()
