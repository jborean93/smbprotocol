# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from smbprotocol.header import (
    Commands,
    SMB2HeaderAsync,
    SMB2HeaderRequest,
    SMB2HeaderResponse,
)


class TestSMB2HeaderAsync:
    DATA = (
        b"\xfe\x53\x4d\x42"
        b"\x40\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x0c\x00"
        b"\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x01\x00\x00\x00\x00\x00\x00\x00"
        b"\x01\x02\x03\x04\x05\x06\x07\x08"
        b"\x0a\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
    )

    def test_create_message(self):
        header = SMB2HeaderAsync()
        header["command"] = Commands.SMB2_CANCEL
        header["message_id"] = 1
        header["async_id"] = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        header["session_id"] = 10
        actual = header.pack()
        assert len(header) == 64
        assert actual == self.DATA

    def test_parse_message(self):
        actual = SMB2HeaderAsync()
        assert actual.unpack(self.DATA + b"\x01\x02\x03\x04") == b""

        assert len(actual) == 68
        assert actual["protocol_id"].get_value() == b"\xfeSMB"
        assert actual["structure_size"].get_value() == 64
        assert actual["credit_charge"].get_value() == 0
        assert actual["channel_sequence"].get_value() == 0
        assert actual["reserved"].get_value() == 0
        assert actual["command"].get_value() == Commands.SMB2_CANCEL
        assert actual["credit_request"].get_value() == 0
        assert actual["flags"].get_value() == 0
        assert actual["next_command"].get_value() == 0
        assert actual["message_id"].get_value() == 1
        assert actual["async_id"].get_value() == 578437695752307201
        assert actual["session_id"].get_value() == 10
        assert actual["signature"].get_value() == b"\x00" * 16
        assert actual["data"].get_value() == b"\x01\x02\x03\x04"


class TestSMB2HeaderRequest:
    def test_create_message(self):
        header = SMB2HeaderRequest()
        header["command"] = Commands.SMB2_SESSION_SETUP
        header["message_id"] = 1
        header["process_id"] = 15
        header["session_id"] = 10
        expected = (
            b"\xfe\x53\x4d\x42"
            b"\x40\x00"
            b"\x00\x00"
            b"\x00\x00"
            b"\x00\x00"
            b"\x01\x00"
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x01\x00\x00\x00\x00\x00\x00\x00"
            b"\x0f\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x0a\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        actual = header.pack()
        assert len(header) == 64
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2HeaderRequest()
        data = (
            b"\xfe\x53\x4d\x42"
            b"\x40\x00"
            b"\x00\x00"
            b"\x00\x00"
            b"\x00\x00"
            b"\x01\x00"
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x01\x00\x00\x00\x00\x00\x00\x00"
            b"\x0f\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x0a\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x01\x02\x03\x04"
        )
        actual.unpack(data)
        assert len(actual) == 68
        assert actual["protocol_id"].get_value() == b"\xfeSMB"
        assert actual["structure_size"].get_value() == 64
        assert actual["credit_charge"].get_value() == 0
        assert actual["channel_sequence"].get_value() == 0
        assert actual["reserved"].get_value() == 0
        assert actual["command"].get_value() == Commands.SMB2_SESSION_SETUP
        assert actual["credit_request"].get_value() == 0
        assert actual["flags"].get_value() == 0
        assert actual["next_command"].get_value() == 0
        assert actual["message_id"].get_value() == 1
        assert actual["process_id"].get_value() == 15
        assert actual["tree_id"].get_value() == 0
        assert actual["session_id"].get_value() == 10
        assert actual["signature"].get_value() == b"\x00" * 16
        assert actual["data"].get_value() == b"\x01\x02\x03\x04"


class TestSMB2HeaderResponse:
    def test_create_message(self):
        header = SMB2HeaderResponse()
        header["command"] = Commands.SMB2_SESSION_SETUP
        header["message_id"] = 1
        header["session_id"] = 10
        expected = (
            b"\xfe\x53\x4d\x42"
            b"\x40\x00"
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x01\x00"
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x01\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x0a\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        actual = header.pack()
        assert len(header) == 64
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2HeaderResponse()
        data = (
            b"\xfe\x53\x4d\x42"
            b"\x40\x00"
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x01\x00"
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x01\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x0a\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x01\x02\x03\x04"
        )
        actual.unpack(data)
        assert len(actual) == 68
        assert actual["protocol_id"].get_value() == b"\xfeSMB"
        assert actual["structure_size"].get_value() == 64
        assert actual["credit_charge"].get_value() == 0
        assert actual["status"].get_value() == 0
        assert actual["command"].get_value() == Commands.SMB2_SESSION_SETUP
        assert actual["credit_response"].get_value() == 0
        assert actual["flags"].get_value() == 0
        assert actual["next_command"].get_value() == 0
        assert actual["message_id"].get_value() == 1
        assert actual["reserved"].get_value() == 0
        assert actual["tree_id"].get_value() == 0
        assert actual["session_id"].get_value() == 10
        assert actual["signature"].get_value() == b"\x00" * 16
        assert actual["data"].get_value() == b"\x01\x02\x03\x04"
