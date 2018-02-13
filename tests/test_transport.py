import time

import pytest

from smbprotocol.connection import Request
from smbprotocol.transport import DirectTCPPacket, Tcp

from .runner import socket_fake


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

    def test_normal_send_receive(self, socket_fake):
        request = Request(b"\x01\x02\x03\x04")

        tcp = Tcp(socket_fake[0], socket_fake[1])
        tcp.connect()
        tcp.send(request)
        try:
            resp = tcp.message_buffer.get(timeout=10)
            assert resp == b"\x05\x06\x07\x08"
        finally:
            tcp.disconnect()

    def test_broken_socket(self, socket_fake):
        # by sending a mismatched request the fake socket with shutdown their
        # end to replicate this scenario
        request = Request(b"\x11")

        tcp = Tcp(socket_fake[0], socket_fake[1])
        tcp.connect()
        tcp.send(request)
        time.sleep(1)  # give it some time before disconnecting
        tcp.disconnect()

    def test_normal_fail_message_too_big(self):
        request = Request(b"\x00" * 16777216)
        tcp = Tcp("0.0.0.0", 0)
        with pytest.raises(ValueError) as exc:
            tcp.send(request)
        assert str(exc.value) == "Data to be sent over Direct TCP size " \
                                 "16777216 exceeds the max length allowed " \
                                 "16777215"
