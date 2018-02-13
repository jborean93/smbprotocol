import binascii
import os
import socket
import struct
from multiprocessing.dummy import Process

import pytest

from smbprotocol.connection import NtStatus, SMB2PacketHeader
from smbprotocol.exceptions import SMB2ErrorContextResponse, SMB2ErrorResponse


class MockSocket(object):

    def __init__(self, class_name, function_name):
        self.iterator = 1
        self.id = "%s-%s" % (class_name, function_name)

        pdir = os.path.dirname(os.path.realpath(__file__))
        self.response_path = os.path.join(pdir, "test_responses", self.id)

        if not os.path.exists(self.response_path):
            raise Exception("The response path %s does not exist, cannot "
                            "create TCP server" % self.response_path)

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("localhost", 0))
        self.address = self._sock.getsockname()

        self._listener = Process(target=self._listen)

    def start(self):
        if not self._listener.is_alive():
            self._listener.start()

    def stop(self):
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            # socket is still running initial listen, need to create a single
            # connection so it can continue and finally exit
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(self.address)
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        self._listener.join()

    def _listen(self):
        self._sock.listen(5)
        while True:
            connection, client_address = self._sock.accept()
            packet_size_bytes = connection.recv(4)

            # socket was shutdown so let's exit
            if packet_size_bytes == b"":
                break

            # otherwise unpack the packet and verify it matches the request
            packet_size = struct.unpack(">L", packet_size_bytes)[0]
            actual_req = connection.recv(packet_size)
            actual_req = packet_size_bytes + actual_req

            req_path = os.path.join(self.response_path,
                                    "%d-request" % self.iterator)
            res_path = os.path.join(self.response_path,
                                    "%d-response" % self.iterator)

            # check that the req and res path's are actually valid
            if not os.path.exists(req_path):
                raise Exception("The expected request path %s does not exist"
                                % req_path)

            expected_req = open(req_path, "r").read().replace(" ", "")
            if binascii.unhexlify(expected_req) == actual_req:
                if not os.path.exists(res_path):
                    raise Exception("The expected response path %s does not "
                                    "exist" % res_path)
                response = open(res_path, "r").read()
                response = binascii.unhexlify(response.replace(" ", ""))
            else:
                # TODO: send an actual SMBErrorResponse message with error
                # details
                raise Exception("Invalid request found")

            connection.send(response)
            self.iterator += 1
        self._sock.close()

    def _create_smb_error_message(self, request, message):
        # TODO: how do I deal with encryption and signatures, need to mock
        # export session key function
        # get message ID from request header
        command = 0
        message_id = 0
        session_id = 0
        tree_id = 0

        header = SMB2PacketHeader()
        header['status'] = NtStatus.STATUS_INVALID_PARAMETER
        header['command'] = command
        header['message_id'] = message_id
        header['session_id'] = session_id
        header['tree_id'] = tree_id

        error_response = SMB2ErrorResponse()
        header['data'] = error_response

        return header.pack()


@pytest.fixture(scope="function")
def socket_fake(request):
    class_name = request.keywords.node.cls.__name__
    function_name = request.keywords.node.name
    sock = MockSocket(class_name, function_name)
    sock.start()
    yield sock.address
    sock.stop()
