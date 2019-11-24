# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import logging
import select
import socket
import struct
import threading

from collections import (
    OrderedDict,
)

from smbprotocol.structure import (
    BytesField,
    IntField,
    Structure,
)

try:
    from queue import Queue
except ImportError:  # pragma: no cover
    from Queue import Queue

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


def socket_connect(func):
    def wrapped(self, *args, **kwargs):
        if not self._connected:
            log.info("Connecting to DirectTcp socket")
            try:
                self._sock = socket.create_connection((self.server, self.port), timeout=self.timeout)
            except (OSError, socket.gaierror) as err:
                raise ValueError("Failed to connect to '%s:%s': %s" % (self.server, self.port, str(err)))
            self._sock.settimeout(None)  # Make sure the socket is in blocking mode.

            self._t_recv = threading.Thread(target=self.recv_thread, name="recv-%s:%s" % (self.server, self.port))
            self._t_recv.daemon = True
            self._t_recv.start()
            self._connected = True

        func(self, *args, **kwargs)

    return wrapped


class Tcp(object):

    MAX_SIZE = 16777215

    def __init__(self, server, port, recv_queue, timeout=None):
        self.server = server
        self.port = port
        self.timeout = timeout
        self._connected = False
        self._sock = None
        self._recv_queue = recv_queue
        self._t_recv = None

    def close(self):
        if self._connected:
            log.info("Disconnecting DirectTcp socket")
            # Send a shutdown to the socket so the select returns and wait until the thread is closed before actually
            # closing the socket.
            self._connected = False
            self._sock.shutdown(socket.SHUT_RDWR)
            self._t_recv.join()
            self._sock.close()

    @socket_connect
    def send(self, header):
        b_msg = header
        data_length = len(b_msg)
        if data_length > self.MAX_SIZE:
            raise ValueError("Data to be sent over Direct TCP size %d exceeds the max length allowed %d"
                             % (data_length, self.MAX_SIZE))

        tcp_packet = DirectTCPPacket()
        tcp_packet['smb2_message'] = b_msg

        data = tcp_packet.pack()
        while data:
            sent = self._sock.send(data)
            data = data[sent:]

    def recv_thread(self):
        try:
            while True:
                select.select([self._sock], [], [])
                b_packet_size = self._sock.recv(4)
                if b_packet_size == b"":
                    return

                packet_size = struct.unpack(">L", b_packet_size)[0]
                b_data = bytearray()
                bytes_read = 0
                while bytes_read < packet_size:
                    b_fragment = self._sock.recv(packet_size - bytes_read)
                    b_data.extend(b_fragment)
                    bytes_read += len(b_fragment)

                self._recv_queue.put(bytes(b_data))
        except Exception as e:
            # Log a warning if the exception was raised while we were connected and not just some weird platform-ism
            # exception when reading from a closed socket.
            if self._connected:
                log.warning("Uncaught exception in socket recv thread: %s" % e)
            return
        finally:
            # Make sure we close the message processing thread in connection.py
            self._recv_queue.put(None)
