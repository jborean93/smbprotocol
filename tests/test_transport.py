# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import re
import socket
import struct
import threading
import time

import pytest

from smbprotocol.transport import DirectTCPPacket, Tcp


@pytest.fixture()
def server_tcp(request):
    server_func_name = "server_" + request.node.name
    server_func = globals().get(server_func_name)
    if not server_func:
        raise Exception("Test must have defined %s to run the server thread" % server_func_name)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)

        server_thread = threading.Thread(target=server_func, args=(sock,))
        server_thread.start()
        try:
            yield Tcp(*sock.getsockname())

        finally:
            server_thread.join()
    finally:
        sock.close()


class TestDirectTcpPacket:
    def test_create_message(self):
        message = DirectTCPPacket()
        message["smb2_message"] = b"\xfe\x53\x4d\x42"
        expected = b"\x00\x00\x00\x04" b"\xfe\x53\x4d\x42"

        actual = message.pack()
        assert len(message) == 8
        assert message["stream_protocol_length"].get_value() == 4
        assert actual == expected

    def test_parse_message(self):
        actual = DirectTCPPacket()
        data = b"\x00\x00\x00\x04" b"\xfe\x53\x4d\x42"
        actual.unpack(data)
        assert len(actual) == 8
        assert actual["stream_protocol_length"].get_value() == 4
        assert isinstance(actual["smb2_message"].get_value(), bytes)

        actual_header = actual["smb2_message"]
        assert len(actual_header) == 4
        assert actual_header.get_value() == b"\xfe\x53\x4d\x42"


class TestTcp:
    def test_normal_fail_message_too_big(self):
        tcp = Tcp("0.0.0.0", 0)
        tcp.connected = True
        with pytest.raises(ValueError) as exc:
            tcp.send(b"\x00" * 16777216)
        assert (
            str(exc.value) == "Data to be sent over Direct TCP size "
            "16777216 exceeds the max length allowed "
            "16777215"
        )

    def test_invalid_host(self):
        """
        Raises ValueError when failing to connect to the remote server.

        The error message contains the low-level OS error details.
        """
        tcp = Tcp("fake-host", 445)
        # We just check for OSError marker, as the actual error message
        # might be different based on current OS.
        with pytest.raises(ValueError, match=r"Failed to connect to 'fake-host:445': \[Errno .*"):
            tcp.connect()


def test_small_recv(server_tcp):
    server_tcp.connect()
    server_tcp.send(b"\x00")

    actual = server_tcp.recv(10)

    server_tcp.send(b"\x00")

    assert actual == b"\x01\x02\x03\x04"


def server_test_small_recv(server):
    # I'm not sure how else to test this but it seems like the small sleeps is enough for the client recv() to read it
    # in the chunks we send.
    sock = server.accept()[0]
    try:
        sock.recv(5)

        b_len = struct.pack(">I", 4)

        sock.send(b_len[:2])
        time.sleep(0.1)
        sock.send(b_len[2:])

        sock.send(b"\x01\x02")
        time.sleep(0.1)
        sock.send(b"\x03\x04")

        sock.recv(5)

    finally:
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()


def test_recv_timeout(server_tcp):
    server_tcp.connect()

    with pytest.raises(TimeoutError):
        server_tcp.recv(1)

    server_tcp.send(b"\x00")


def server_test_recv_timeout(server):
    sock = server.accept()[0]
    try:
        sock.recv(5)

    finally:
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()


def test_recv_closed(server_tcp):
    server_tcp.connect()
    actual = server_tcp.recv(10)
    assert actual == b""
    assert server_tcp.connected is False


def server_test_recv_closed(server):
    sock = server.accept()[0]
    try:
        time.sleep(1)

    finally:
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()


def test_recv_closed_client(server_tcp):
    server_tcp.connect()
    recv_res = []

    def recv():
        recv_res.append(server_tcp.recv(5))

    client_recv_t = threading.Thread(target=recv)
    client_recv_t.start()

    server_tcp.close()
    client_recv_t.join()
    assert recv_res == [b""]


def server_test_recv_closed_client(server):
    sock = server.accept()[0]
    sock.recv(1)
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()
