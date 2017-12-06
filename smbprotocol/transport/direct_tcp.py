import socket

from smbprotocol.messages import DirectTCPPacket


class DirectTcp(object):

    MAX_SIZE = 16777215
    BUFFER = 1024

    def __init__(self, server, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._is_connected = False
        self.server = server
        self.port = port

    def connect(self):
        if self._is_connected is False:
            self.sock.connect((self.server, self.port))
            self._is_connected = True

    def disconnect(self):
        if self._is_connected is True:
            self.sock.close()

    def send(self, request):
        self.connect()
        tcp_packet = self._pack_data(request.message)
        self.sock.send(tcp_packet)

    def recv(self):
        tcp_packet = self.sock.recv(self.BUFFER)
        try:
            data = self._unpack_data(tcp_packet)
        except Exception as exc:
            raise Exception("Expecting SMB2 Packet Header in server response "
                            "and could not unpack data: %s" % str(exc))
        return data

    def _pack_data(self, data):
        data_length = len(data)
        if data_length > self.MAX_SIZE:
            raise ValueError("Data to be sent over Direct TCP %d exceeds max "
                             "length allowed %d"
                             % (data_length, self.MAX_SIZE))

        tcp_packet = DirectTCPPacket()
        tcp_packet['smb2_message'] = data.pack()

        return tcp_packet.pack()

    def _unpack_data(self, data):
        tcp_packet = DirectTCPPacket()
        tcp_packet.unpack(data)

        return tcp_packet['smb2_message'].pack()
