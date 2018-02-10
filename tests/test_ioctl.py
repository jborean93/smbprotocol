import uuid

from smbprotocol.connection import Dialects
from smbprotocol.ioctl import CtlCode, IOCTLFlags, SMB2IOCTLRequest, \
    SMB2IOCTLResponse, SMB2ValidateNegotiateInfoRequest, \
    SMB2ValidateNegotiateInfoResponse


class TestSMB2IOCTLRequest(object):

    def test_create_message(self):
        message = SMB2IOCTLRequest()
        message['ctl_code'] = CtlCode.FSCTL_VALIDATE_NEGOTIATE_INFO
        message['file_id'] = b"\xff" * 16
        message['max_input_response'] = 12
        message['max_output_response'] = 12
        message['flags'] = IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL
        message['buffer'] = b"\x12\x13\x14\x15"
        expected = b"\x39\x00" \
                   b"\x00\x00" \
                   b"\x04\x02\x14\x00" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\x78\x00\x00\x00" \
                   b"\x04\x00\x00\x00" \
                   b"\x0c\x00\x00\x00" \
                   b"\x78\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x0c\x00\x00\x00" \
                   b"\x01\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x12\x13\x14\x15"
        actual = message.pack()
        assert len(message) == 60
        assert actual == expected

    def test_create_message_no_buffer(self):
        message = SMB2IOCTLRequest()
        message['ctl_code'] = CtlCode.FSCTL_VALIDATE_NEGOTIATE_INFO
        message['file_id'] = b"\xff" * 16
        message['flags'] = IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL
        expected = b"\x39\x00" \
                   b"\x00\x00" \
                   b"\x04\x02\x14\x00" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x01\x00\x00\x00" \
                   b"\x00\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 56
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2IOCTLRequest()
        data = b"\x39\x00" \
               b"\x00\x00" \
               b"\x04\x02\x14\x00" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\x78\x00\x00\x00" \
               b"\x04\x00\x00\x00" \
               b"\x0c\x00\x00\x00" \
               b"\x78\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x0c\x00\x00\x00" \
               b"\x01\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x12\x13\x14\x15"
        actual.unpack(data)
        assert len(actual) == 60
        assert actual['structure_size'].get_value() == 57
        assert actual['reserved'].get_value() == 0
        assert actual['ctl_code'].get_value() == \
            CtlCode.FSCTL_VALIDATE_NEGOTIATE_INFO
        assert actual['file_id'].pack() == b"\xff" * 16
        assert actual['input_offset'].get_value() == 120
        assert actual['input_count'].get_value() == 4
        assert actual['max_input_response'].get_value() == 12
        assert actual['output_offset'].get_value() == 120
        assert actual['output_count'].get_value() == 0
        assert actual['max_output_response'].get_value() == 12
        assert actual['flags'].get_value() == IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL
        assert actual['reserved2'].get_value() == 0
        assert actual['buffer'].get_value() == b"\x12\x13\x14\x15"


class TestSMB2ValidateNegotiateInfoRequest(object):

    def test_create_message(self):
        message = SMB2ValidateNegotiateInfoRequest()
        message['capabilities'] = 8
        message['guid'] = b"\x11" * 16
        message['security_mode'] = 1
        message['dialect_count'] = 2
        message['dialects'] = [Dialects.SMB_2_0_2, Dialects.SMB_2_1_0]
        expected = b"\x08\x00\x00\x00" \
                   b"\x11\x11\x11\x11\x11\x11\x11\x11" \
                   b"\x11\x11\x11\x11\x11\x11\x11\x11" \
                   b"\x01\x00" \
                   b"\x02\x00" \
                   b"\x02\x02\x10\x02"
        actual = message.pack()
        assert len(message) == 28
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2ValidateNegotiateInfoRequest()
        data = b"\x08\x00\x00\x00" \
               b"\x11\x11\x11\x11\x11\x11\x11\x11" \
               b"\x11\x11\x11\x11\x11\x11\x11\x11" \
               b"\x01\x00" \
               b"\x02\x00" \
               b"\x02\x02\x10\x02"
        actual.unpack(data)
        assert len(actual) == 28
        assert actual['capabilities'].get_value() == 8
        assert actual['guid'].get_value() == uuid.UUID(bytes=b"\x11" * 16)
        assert actual['security_mode'].get_value() == 1
        assert actual['dialect_count'].get_value() == 2
        assert actual['dialects'][0] == 514
        assert actual['dialects'][1] == 528
        assert len(actual['dialects'].get_value()) == 2


class TestSMB2IOCTLResponse(object):

    def test_create_message(self):
        message = SMB2IOCTLResponse()
        message['ctl_code'] = CtlCode.FSCTL_VALIDATE_NEGOTIATE_INFO
        message['file_id'] = b"\xff" * 16
        message['input_offset'] = 0
        message['input_count'] = 0
        message['output_offset'] = 112
        message['output_count'] = 4
        message['flags'] = IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL
        message['buffer'] = b"\x20\x21\x22\x23"
        expected = b"\x31\x00\x00\x00" \
                   b"\x04\x02\x14\x00" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x70\x00\x00\x00" \
                   b"\x04\x00\x00\x00" \
                   b"\x01\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x20\x21\x22\x23"
        actual = message.pack()
        assert len(message) == 52
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2IOCTLResponse()
        data = b"\x31\x00\x00\x00" \
               b"\x04\x02\x14\x00" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x70\x00\x00\x00" \
               b"\x04\x00\x00\x00" \
               b"\x01\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x20\x21\x22\x23"
        actual.unpack(data)
        assert len(actual) == 52
        assert actual['structure_size'].get_value() == 49
        assert actual['reserved'].get_value() == 0
        assert actual['ctl_code'].get_value() == \
            CtlCode.FSCTL_VALIDATE_NEGOTIATE_INFO
        assert actual['file_id'].pack() == b"\xff" * 16
        assert actual['input_offset'].get_value() == 0
        assert actual['input_count'].get_value() == 0
        assert actual['output_offset'].get_value() == 112
        assert actual['output_count'].get_value() == 4
        assert actual['flags'].get_value() == IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL
        assert actual['reserved2'].get_value() == 0
        assert actual['buffer'].get_value() == b"\x20\x21\x22\x23"


class TestSMB2ValidateNegotiateInfoResponse(object):

    def test_create_message(self):
        message = SMB2ValidateNegotiateInfoResponse()
        message['capabilities'] = 8
        message['guid'] = b"\xff" * 16
        message['security_mode'] = 0
        message['dialect'] = Dialects.SMB_3_0_2
        expected = b"\x08\x00\x00\x00" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\x00\x00" \
                   b"\x02\x03"
        actual = message.pack()
        assert len(message) == 24
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2ValidateNegotiateInfoResponse()
        data = b"\x08\x00\x00\x00" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\x00\x00" \
               b"\x02\x03"
        actual.unpack(data)
        assert len(actual) == 24
        assert actual['capabilities'].get_value() == 8
        assert actual['guid'].get_value() == uuid.UUID(bytes=b"\xff" * 16)
        assert actual['security_mode'].get_value() == 0
        assert actual['dialect'].get_value() == Dialects.SMB_3_0_2
