from smbprotocol.connection import SecurityMode
from smbprotocol.session import SMB2Logoff, SMB2SessionSetupRequest, \
    SMB2SessionSetupResponse


class TestSMB2SessionSetupRequest(object):

    def test_create_message(self):
        message = SMB2SessionSetupRequest()
        message['security_mode'] = SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        message['buffer'] = b"\x01\x02\x03\x04"
        expected = b"\x19\x00" \
                   b"\x00" \
                   b"\x01" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x58\x00" \
                   b"\x04\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x01\x02\x03\x04"
        actual = message.pack()
        assert len(message) == 28
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2SessionSetupRequest()
        data = b"\x19\x00" \
               b"\x00" \
               b"\x01" \
               b"\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x58\x00" \
               b"\x04\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x01\x02\x03\x04"
        actual.unpack(data)
        assert len(actual) == 28
        assert actual['structure_size'].get_value() == 25
        assert actual['flags'].get_value() == 0
        assert actual['security_mode'].get_value() == 1
        assert actual['capabilities'].get_value() == 0
        assert actual['security_buffer_offset'].get_value() == 88
        assert actual['security_buffer_length'].get_value() == 4
        assert actual['previous_session_id'].get_value() == 0
        assert actual['buffer'].get_value() == b"\x01\x02\x03\x04"


class TestSMB2SessionSetupResponse(object):

    def test_create_message(self):
        message = SMB2SessionSetupResponse()
        message['session_flags'] = 1
        message['buffer'] = b"\x04\x03\x02\x01"
        expected = b"\x09\x00" \
                   b"\x01\x00" \
                   b"\x48\x00" \
                   b"\x04\x00" \
                   b"\x04\x03\x02\x01"
        actual = message.pack()
        assert len(message) == 12
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2SessionSetupResponse()
        data = b"\x09\x00" \
               b"\x01\x00" \
               b"\x48\x00" \
               b"\x04\x00" \
               b"\x04\x03\x02\x01"
        actual.unpack(data)
        assert len(actual) == 12
        assert actual['structure_size'].get_value() == 9
        assert actual['session_flags'].get_value() == 1
        assert actual['security_buffer_offset'].get_value() == 72
        assert actual['security_buffer_length'].get_value() == 4
        assert actual['buffer'].get_value() == b"\x04\x03\x02\x01"


class TestSMB2Logoff(object):

    def test_create_message(self):
        message = SMB2Logoff()
        expected = b"\x04\x00" \
                   b"\x00\x00"
        actual = message.pack()
        assert len(message) == 4
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2Logoff()
        data = b"\x04\x00" \
               b"\x00\x00"
        actual.unpack(data)
        assert len(actual) == 4
        assert actual['structure_size'].get_value() == 4
        assert actual['reserved'].get_value() == 0
