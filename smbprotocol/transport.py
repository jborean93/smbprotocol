import logging
import socket
import struct

from multiprocessing.dummy import Process, Queue

from smbprotocol.messages import DirectTCPPacket, SMB2PacketHeader, \
    SMB2TransformHeader

log = logging.getLogger(__name__)


class Tcp(object):

    MAX_SIZE = 16777215

    def __init__(self, server, port):
        log.info("Setting up DirectTcp connection on %s:%d" % (server, port))
        self.message_buffer = Queue()
        self.server = server
        self.port = port

        self._connected = False
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener = Process(target=self._listen,
                                 args=(self._sock, self.message_buffer))

    def connect(self):
        if not self._connected:
            log.info("Connecting to DirectTcp socket")
            self._sock.connect((self.server, self.port))
            self._connected = True

        if not self._listener.is_alive():
            log.info("Setting up DirectTcp listener")
            self._listener.start()

    def disconnect(self):
        if self._connected:
            log.info("Disconnecting DirectTcp socket")
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                # socket has already been shutdown
                pass
            self._listener.join()
            self._sock.close()
            self._connected = False

    def send(self, request):
        data_length = len(request.message)
        if data_length > self.MAX_SIZE:
            raise ValueError("Data to be sent over Direct TCP %d exceeds max "
                             "length allowed %d"
                             % (data_length, self.MAX_SIZE))

        tcp_packet = DirectTCPPacket()
        tcp_packet['smb2_message'] = request.message
        data = tcp_packet.pack()
        self._sock.send(data)

    @staticmethod
    def _listen(sock, message_buffer):
        """
        Runs in a thread and is constantly reading from the socket receive
        buffer and adding each message to the queue. Very little error handling
        and message parsing is done in this process as it happens
        asynchronously to the main process

        :param sock: The socket to read from
        :param message_buffer: A queue used to store the incoming messages for
            Connection to read from
        """
        while True:
            packet_size_bytes = sock.recv(4)
            # the socket was closed so exit the loop
            if not packet_size_bytes:
                break

            packet_size_int = struct.unpack(">L", packet_size_bytes)[0]
            buffer = sock.recv(packet_size_int)

            if buffer[:4] == b"\xfeSMB":
                header = SMB2PacketHeader()
            elif buffer[:4] == b"\xfdSMB":
                header = SMB2TransformHeader()
            else:
                # not a valid message so we need to break - validation happens
                # when messages are read from the queue
                message_buffer.put(buffer)
                break
            header.unpack(buffer)
            message_buffer.put(header)
