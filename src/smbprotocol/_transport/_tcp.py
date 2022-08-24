# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import contextlib
import logging
import select
import socket
import struct
import threading
import typing as t

from ._base import SMBProtocol, SMBTransport

log = logging.getLogger(__name__)


class TcpTransport(SMBTransport):

    MAX_SIZE = 16777215

    def __init__(
        self,
        connection_addr: str,
        sock: socket.socket,
        protocol: SMBProtocol,
    ) -> None:
        self._cancel_token = SocketCancellationToken()
        self._protocol = protocol
        self._recv_thread = threading.Thread(target=self._recv, name=f"tcp-recv-{connection_addr}")
        self._sock = SocketHelper(sock)
        self._send_lock = threading.Lock()

        self._recv_thread.start()

    @classmethod
    def create(
        cls,
        host: str,
        port: int,
        timeout: float,
        protocol: SMBProtocol,
    ) -> SMBTransport:
        try:
            sock = socket.create_connection((host, port), timeout=timeout if timeout else None)
        except OSError as e:
            raise ValueError(f"Failed to connect to '{host}:{port}': {e}") from e

        transport = TcpTransport(f"{host}:{port}", sock, protocol)
        protocol.connection_made(transport)
        return transport

    def close(self) -> None:
        self._cancel_token.cancel()
        self._sock.shutdown(socket.SHUT_RDWR)
        self._sock.close()
        self._recv_thread.join()

    def write(self, data: bytes) -> None:
        data_len = len(data)

        if data_len > self.MAX_SIZE:
            raise ValueError(
                f"Data to be sent over Direct TCP size {data_len} exceeds the max length allowed {self.MAX_SIZE}"
            )

        with self._send_lock:
            self._sock.send(data_len.to_bytes(4, byteorder="big") + data, self._cancel_token)

    def _recv(self) -> bytes:
        while True:
            try:
                # To avoid the server sending a FIN and closing the connection
                # an SMB echo is requested every 10 minutes. A brief test shows
                # Windows kills a connection at ~16 minutes so 10 minutes is
                # safe enough for no activity.
                # https://github.com/jborean93/smbprotocol/issues/31.
                b_packet_len = self._sock.recv(4, self._cancel_token, timeout=600.0)
                if not b_packet_len:
                    break

                packet_len = struct.unpack(">L", b_packet_len)[0]
                b_data = self._sock.recv(packet_len, self._cancel_token)
                self._protocol.data_received(b_data)
            except TimeoutError:
                self._protocol.echo()
            except CancelledError:
                break
            except Exception as e:
                self._protocol.connection_closed(e)
                return

        self._protocol.connection_closed(None)


class SocketHelper:
    def __init__(
        self,
        sock: socket.socket,
    ) -> None:
        self._sock = sock

    def close(self) -> None:
        self._sock.close()

    def recv(
        self,
        n: int,
        cancel_token: SocketCancellationToken,
        timeout: float = 0,
    ) -> bytes:
        buffer = bytearray(n)
        view = memoryview(buffer)
        read = 0

        while read < n:
            data_read = cancel_token.recv_into(self._sock, view[read:], n - read, timeout=timeout)
            read += data_read

            # On a socket shutdown 0 bytes will be read.
            if data_read == 0:
                break

        data = bytes(buffer[:read])
        return data

    def send(
        self,
        data: bytes,
        cancel_token: SocketCancellationToken,
    ) -> None:
        cancel_token.sendall(self._sock, data)

    def shutdown(
        self,
        how: int,
    ) -> None:
        try:
            self._sock.shutdown(how)
        except OSError:
            pass


class SocketCancellationToken:
    def __init__(self) -> None:
        self._cancel_funcs: t.Dict[int, t.Callable[[], None]] = {}
        self._cancel_id = 0
        self._cancelled = False
        self._lock = threading.Lock()

    def recv_into(
        self,
        sock: socket.socket,
        buffer: t.Union[bytearray, memoryview],
        n: int,
        timeout: float = 0,
    ) -> int:
        if timeout == 0:
            timeout = None

        with self._with_cancel(lambda: sock.shutdown(socket.SHUT_RD)):
            read_fds = select.select([sock], [], [], timeout)[0]
            if not read_fds:
                raise TimeoutError()

            res = sock.recv_into(buffer, n)
            if self._cancelled:
                raise CancelledError()

            return res

    def sendall(
        self,
        sock: socket.socket,
        data: bytes,
    ) -> None:
        with self._with_cancel(lambda: sock.shutdown(socket.SHUT_WR)):
            try:
                sock.sendall(data)
            except OSError:
                if not self._cancelled:
                    raise

            if self._cancelled:
                raise CancelledError()

    def cancel(self) -> None:
        with self._lock:
            self._cancelled = True

            for func in list(self._cancel_funcs.values()):
                func()

            self._cancel_funcs = {}

    @contextlib.contextmanager
    def _with_cancel(
        self,
        cancel_func: t.Callable[[], None],
    ) -> t.Generator[None, None, None]:
        with self._lock:
            if self._cancelled:
                raise CancelledError()

            cancel_id = self._cancel_id
            self._cancel_id += 1
            self._cancel_funcs[cancel_id] = cancel_func

        try:
            yield

        finally:
            with self._lock:
                self._cancel_funcs.pop(cancel_id, None)


class CancelledError(Exception):
    def __init__(self, msg: t.Optional[str] = None):
        super().__init__(msg or "Socket operation has been cancelled")
