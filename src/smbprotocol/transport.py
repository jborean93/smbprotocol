# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import logging
import socket
import struct
import threading
import timeit
import typing as t

from smbprotocol._transport._socket_helper import (
    CancelledError,
    SocketCancellationToken,
    SocketHelper,
)

log = logging.getLogger(__name__)


class SMBProtocol:
    def connection_made(self, transport: SMBTransport) -> None:
        ...

    def connection_closed(self, exc: t.Optional[Exception]) -> None:
        ...

    def data_received(self, data: bytes) -> None:
        ...


class SMBTransport:
    def close(self) -> None:
        ...

    def write(self, data: bytes) -> None:
        ...


class Tcp:
    MAX_SIZE = 16777215

    def __init__(
        self,
        host: str,
        port: int,
    ) -> None:
        self.host = host
        self.port = port
        self._cancel_token = SocketCancellationToken()
        self._sock = t.Optional[SocketHelper] = None
        self._send_lock = threading.Lock()

    def connect(
        self,
        timeout: float = 0,
    ) -> None:
        if self._sock:
            return

        try:
            self._sock = SocketHelper.create_connection(
                (self.host, self.port),
                self._cancel_token,
                timeout=timeout,
            )
        except OSError as e:
            raise ValueError(f"Failed to connect to '{self.host}:{self.port}': {e}") from e

    def close(self) -> None:
        if not self._sock:
            return

        self._cancel_token.cancel()
        self._sock.shutdown(socket.SHUT_RDWR)
        self._sock.close()
        self._sock = None

    def send(self, data: bytes) -> None:
        data_len = len(data)

        if data_len > self.MAX_SIZE:
            raise ValueError(
                f"Data to be sent over Direct TCP size {data_len} exceeds the max length allowed {self.MAX_SIZE}"
            )

        with self._send_lock:
            self._sock.send(data_len.to_bytes(4, byteorder="big") + data, self._cancel_token)

    def recv(self, timeout: float) -> bytes:
        start_time = timeit.default_timer()
        b_packet_len = self._sock.recv(4, self._cancel_token, timeout=timeout)

        timeout = timeout - (timeit.default_timer() - start_time)
        packet_len = struct.unpack(">L", b_packet_len)[0]
        return self._sock.recv(packet_len, self._cancel_token, timeout=timeout)

    def _get_socket(self) -> SocketHelper:
        if not self._sock:
            raise Exception("")

        return self._sock
