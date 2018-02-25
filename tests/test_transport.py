import errno
import socket

import pytest

from smbprotocol.transport import DirectTCPPacket, Tcp


class TestDirectTcpPacket(object):

    def test_create_message(self):
        message = DirectTCPPacket()
        message['smb2_message'] = b"\xfe\x53\x4d\x42"
        expected = b"\x00\x00\x00\x04" \
                   b"\xfe\x53\x4d\x42"

        actual = message.pack()
        assert len(message) == 8
        assert message['stream_protocol_length'].get_value() == 4
        assert actual == expected

    def test_parse_message(self):
        actual = DirectTCPPacket()
        data = b"\x00\x00\x00\x04" \
               b"\xfe\x53\x4d\x42"
        actual.unpack(data)
        assert len(actual) == 8
        assert actual['stream_protocol_length'].get_value() == 4
        assert isinstance(actual['smb2_message'].get_value(), bytes)

        actual_header = actual['smb2_message']
        assert len(actual_header) == 4
        assert actual_header.get_value() == b"\xfe\x53\x4d\x42"


class TestTcp(object):

    def test_normal_fail_message_too_big(self):
        tcp = Tcp("0.0.0.0", 0)
        with pytest.raises(ValueError) as exc:
            tcp.send(b"\x00" * 16777216)
        assert str(exc.value) == "Data to be sent over Direct TCP size " \
                                 "16777216 exceeds the max length allowed " \
                                 "16777215"

    def test_send_fail_non_blocking(self):
        # ensure it doesn't loop when a non blocking error is raised
        tcp = Tcp("0.0.0.0", 0)
        with pytest.raises(socket.error) as err:
            tcp.send(b"\x01\x02\x03\x04")
        assert err.value.errno == errno.ENOTCONN

    def test_recv_fail_non_blocking(self):
        # ensure it doesn't loop when a non blocking error is raised
        tcp = Tcp("0.0.0.0", 0)
        with pytest.raises(socket.error) as err:
            tcp._recv(10)
        assert err.value.errno == errno.ENOTCONN
