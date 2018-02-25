import errno
import logging
import socket
import struct
import threading

from smbprotocol.structure import BytesField, IntField, Structure

try:
    from collections import OrderedDict
except ImportError:  # pragma: no cover
    from ordereddict import OrderedDict

log = logging.getLogger(__name__)


class DirectTCPPacket(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.1 Transport
    The Directory TCP transport packet header MUST have the following
    structure.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('stream_protocol_length', IntField(
                size=4,
                little_endian=False,
                default=lambda s: len(s['smb2_message']),
            )),
            ('smb2_message', BytesField(
                size=lambda s: s['stream_protocol_length'].get_value(),
            )),
        ])
        super(DirectTCPPacket, self).__init__()


class Tcp(object):

    MAX_SIZE = 16777215

    def __init__(self, server, port):
        log.info("Setting up DirectTcp connection on %s:%d" % (server, port))
        self.server = server
        self.port = port

        # used in multithreading processes to ensure send and recv isn't run at
        # the same time
        self.send_lock = threading.Lock()
        self.recv_lock = threading.Lock()

        self._connected = False
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self):
        if not self._connected:
            log.info("Connecting to DirectTcp socket")
            self._sock.connect((self.server, self.port))
            self._sock.setblocking(0)
            self._connected = True

    def disconnect(self):
        if self._connected:
            log.info("Disconnecting DirectTcp socket")
            self._sock.close()
            self._connected = False

    def send(self, request):
        data_length = len(request)
        if data_length > self.MAX_SIZE:
            raise ValueError("Data to be sent over Direct TCP size %d exceeds "
                             "the max length allowed %d"
                             % (data_length, self.MAX_SIZE))

        tcp_packet = DirectTCPPacket()
        tcp_packet['smb2_message'] = request
        data = tcp_packet.pack()

        self.send_lock.acquire()
        try:
            while data:
                sent = 0
                try:
                    sent = self._sock.send(data)
                except socket.error as err:
                    if err.errno not in [errno.EAGAIN, errno.EWOULDBLOCK]:
                        raise err
                data = data[sent:]
        finally:
            self.send_lock.release()

    def receive(self):
        # receive first 4 bytes that contain the size of the packet, return
        # None if no data is available, Connection handles this scenario
        self.recv_lock.acquire()
        try:
            packet_size_bytes = self._recv(4)
            if packet_size_bytes is None:
                return

            packet_size_int = struct.unpack(">L", packet_size_bytes)[0]
            # we know there is 4 bytes so need to wait for the full stream to
            # return before releasing the lock
            buffer = self._recv(packet_size_int, wait=True)
        finally:
            self.recv_lock.release()
        return buffer

    def _recv(self, buffer, wait=False):
        # will attempt to retrieve the data in the recv buffer based on the
        # buffer size or return None if nothing available
        bytes = b""
        while len(bytes) < buffer:
            try:
                data = self._sock.recv(buffer - len(bytes))
                bytes += data
            except socket.error as err:
                if err.errno not in [errno.EAGAIN, errno.EWOULDBLOCK]:
                    raise err
                # this was the first request so return None
                elif bytes == b"" and not wait:
                    return None
                # we started getting data and there is still some remaining
                # so try again
        return bytes
