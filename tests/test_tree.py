from smbprotocol.tree import SMB2TreeConnectRequest, SMB2TreeConnectResponse, \
    SMB2TreeDisconnect


class TestSMB2TreeConnectRequest(object):

    def test_create_message(self):
        message = SMB2TreeConnectRequest()
        message['flags'] = 2
        message['buffer'] = "\\\\127.0.0.1\\c$".encode("utf-16-le")
        expected = b"\x09\x00" \
                   b"\x02\x00" \
                   b"\x48\x00" \
                   b"\x1c\x00" \
                   b"\x5c\x00\x5c\x00\x31\x00\x32\x00" \
                   b"\x37\x00\x2e\x00\x30\x00\x2e\x00" \
                   b"\x30\x00\x2e\x00\x31\x00\x5c\x00" \
                   b"\x63\x00\x24\x00"
        actual = message.pack()
        assert len(message) == 36
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2TreeConnectRequest()
        data = b"\x09\x00" \
               b"\x02\x00" \
               b"\x48\x00" \
               b"\x1c\x00" \
               b"\x5c\x00\x5c\x00\x31\x00\x32\x00" \
               b"\x37\x00\x2e\x00\x30\x00\x2e\x00" \
               b"\x30\x00\x2e\x00\x31\x00\x5c\x00" \
               b"\x63\x00\x24\x00"
        actual.unpack(data)
        assert len(actual) == 36
        assert actual['structure_size'].get_value() == 9
        assert actual['flags'].get_value() == 2
        assert actual['path_offset'].get_value() == 72
        assert actual['path_length'].get_value() == 28
        assert actual['buffer'].get_value() == "\\\\127.0.0.1\\c$"\
            .encode("utf-16-le")


class TestSMB2TreeConnectResponse(object):

    def test_create_message(self):
        message = SMB2TreeConnectResponse()
        message['share_type'] = 1
        message['share_flags'] = 2
        message['capabilities'] = 8
        message['maximal_access'] = 10
        expected = b"\x10\x00" \
                   b"\x01" \
                   b"\x00" \
                   b"\x02\x00\x00\x00" \
                   b"\x08\x00\x00\x00" \
                   b"\x0a\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 16
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2TreeConnectResponse()
        data = b"\x10\x00" \
               b"\x01" \
               b"\x00" \
               b"\x02\x00\x00\x00" \
               b"\x08\x00\x00\x00" \
               b"\x0a\x00\x00\x00"
        actual.unpack(data)
        assert len(actual) == 16
        assert actual['structure_size'].get_value() == 16
        assert actual['share_type'].get_value() == 1
        assert actual['reserved'].get_value() == 0
        assert actual['share_flags'].get_value() == 2
        assert actual['capabilities'].get_value() == 8
        assert actual['maximal_access'].get_value() == 10


class TestSMB2TreeDisconnect(object):

    def test_create_message(self):
        message = SMB2TreeDisconnect()
        expected = b"\x04\x00" \
                   b"\x00\x00"
        actual = message.pack()
        assert len(message) == 4
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2TreeDisconnect()
        data = b"\x04\x00" \
               b"\x00\x00"
        actual.unpack(data)
        assert len(actual) == 4
        assert actual['structure_size'].get_value() == 4
        assert actual['reserved'].get_value() == 0
