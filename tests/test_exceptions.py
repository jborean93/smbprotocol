from smbprotocol.exceptions import SMB2ErrorResponse


class TestSMB2ErrorResponse(object):

    def test_create_message_plain(self):
        # This is a plain error response without the error context response
        # data appended
        message = SMB2ErrorResponse()
        expected = b"\x09\x00" \
                   b"\x00" \
                   b"\x00" \
                   b"\x00\x00\x00\x00"
        actual = message.pack()
        assert len(actual) == 8
        assert actual == expected

    def test_parse_message_plain(self):
        actual = SMB2ErrorResponse()
        data = b"\x09\x00" \
               b"\x00" \
               b"\x00" \
               b"\x00\x00\x00\x00"
        actual.unpack(data)
        assert len(actual) == 8
        assert actual['structure_size'].get_value() == 9
        assert actual['error_context_count'].get_value() == 0
        assert actual['reserved'].get_value() == 0
        assert actual['byte_count'].get_value() == 0
        assert actual['error_data'].get_value() == []


# TODO: Once I get proper responses from the server
class TestSMB2ErrorContextResponse(object):

    def test_create_message(self):
        pass

    def test_parse_message(self):
        pass
