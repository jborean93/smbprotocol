# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import errno
import logging
import select
import socket
import struct
import threading
import timeit
from collections import OrderedDict

from smbprotocol.structure import BytesField, IntField, Structure

log = logging.getLogger(__name__)


class DirectTCPPacket(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.1 Transport
    The Directory TCP transport packet header MUST have the following
    structure.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                (
                    "stream_protocol_length",
                    IntField(
                        size=4,
                        little_endian=False,
                        default=lambda s: len(s["smb2_message"]),
                    ),
                ),
                (
                    "smb2_message",
                    BytesField(
                        size=lambda s: s["stream_protocol_length"].get_value(),
                    ),
                ),
            ]
        )
        super().__init__()


class Tcp:
    MAX_SIZE = 16777215

    def __init__(self, server, port, timeout=None):
        self.server = server
        self.port = port
        self.timeout = timeout
        self.connected = False
        self._sock = None
        self._sock_lock = threading.Lock()
        self._close_lock = threading.Lock()

    def connect(self):
        with self._sock_lock:
            if not self.connected:
                log.info("Connecting to DirectTcp socket")
                try:
                    self._sock = socket.create_connection((self.server, self.port), timeout=self.timeout)
                except (OSError, socket.gaierror) as err:
                    raise ValueError(f"Failed to connect to '{self.server}:{self.port}'") from err
                self._sock.settimeout(None)  # Make sure the socket is in blocking mode.
                self.connected = True

    def close(self):
        with self._sock_lock:
            if self.connected:
                log.info("Disconnecting DirectTcp socket")

                # Sending shutdown first will tell the recv thread (for both select and recv) that the socket has data
                # which returns b'' meaning it was closed.
                try:
                    self._sock.shutdown(socket.SHUT_RDWR)
                except OSError as e:  # pragma: no cover
                    # Avoid collecting coverage here to avoid CI failing due to race condition differences
                    if e.errno != errno.ENOTCONN:
                        raise

                # This is even more special, we cannot close the socket if we are in the middle of a select or recv().
                # Doing so causes either a timeout (bad!) or bad fd descriptor (somewhat bad). By shutting down the
                # socket first then waiting until recv() has exited the critical select/recv section we can ensure we
                # gracefully handle client side socket closures both here and our recv thread without any extra waits
                # or exceptions.
                with self._close_lock:
                    self._sock.close()
                    self.connected = False

    def send(self, header):
        b_msg = header
        data_length = len(b_msg)
        if data_length > self.MAX_SIZE:
            raise ValueError(
                f"Data to be sent over Direct TCP size {data_length} exceeds the max length allowed {self.MAX_SIZE}"
            )

        tcp_packet = DirectTCPPacket()
        tcp_packet["smb2_message"] = b_msg

        data = tcp_packet.pack()

        with self._sock_lock:
            while data:
                sent = self._sock.send(data)
                data = data[sent:]

    def recv(self, timeout):
        # We don't need a lock for recv as the receiver is called from 1 thread.
        b_packet_size, timeout = self._recv(4, timeout)
        if not b_packet_size:
            return b""

        packet_size = struct.unpack(">L", b_packet_size)[0]

        return self._recv(packet_size, timeout)[0]

    def _recv(self, length, timeout):
        buffer = bytearray(length)
        offset = 0
        while offset < length:
            read_len = length - offset
            log.debug(f"Socket recv({read_len}) (total {length})")

            start_time = timeit.default_timer()

            with self._close_lock:
                if not self.connected:
                    # The socket was closed - need the no cover to avoid CI failing on race condition differences
                    return None, timeout  # pragma: no cover

                read = select.select([self._sock], [], [], max(timeout, 1))[0]
                timeout = timeout - (timeit.default_timer() - start_time)
                if not read:
                    log.debug("Socket recv(%s) timed out")
                    raise TimeoutError()

                try:
                    b_data = self._sock.recv(read_len)
                except OSError as e:
                    # Windows will raise this error if the socket has been shutdown, Linux return returns an empty byte
                    # string so we just replicate that.
                    if e.errno not in [errno.ESHUTDOWN, errno.ECONNRESET]:
                        # Avoid collecting coverage here to avoid CI failing due to race condition differences
                        raise  # pragma: no cover
                    b_data = b""

            read_len = len(b_data)
            log.debug(f"Socket recv() returned {read_len} bytes (total {length})")

            if read_len == 0:
                self.close()
                return None, timeout  # The socket has been shutdown

            buffer[offset : offset + read_len] = b_data
            offset += read_len

        return bytes(buffer), timeout
