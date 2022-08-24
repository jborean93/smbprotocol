# -*- coding: utf-8 -*-
# Copyright: (c) 2022, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import typing as t


class SMBProtocol:
    def connection_made(
        self,
        transport: SMBTransport,
    ) -> None:
        """A connection has been made.

        Called when the connection has been made and is connected to the target.
        Provides the transport that the connection was made through.

        Args:
            transport: The transport that made the connection.
        """

    def connection_closed(
        self,
        exc: t.Optional[Exception],
    ) -> None:
        """A connection has been closed.

        Called when the connection has been closed or dropped. The exc argument
        will be set if the close was due to an error occurring.

        Args:
            exc: The exception if the close was due to an error.
        """

    def data_received(
        self,
        data: bytes,
    ) -> None:
        """Data has been received.

        Called when data has been received on the connection.

        Args:
            data: The raw SMB bytes that were received.
        """

    def echo(self) -> None:
        """An SMB echo is requested to keep the connection alive."""


class SMBTransport:
    @classmethod
    def create(
        cls,
        host: str,
        port: int,
        timeout: float,
        protocol: SMBProtocol,
    ) -> SMBTransport:
        """Creates an instance of the connection.

        Creates an instance of the connection using the arguments specified.

        Args:
            host: The hostname to connect to.
            port: The port to connect to.
            timeout: The connection timeout.
            protocol: The SMBProtocol to associate with the transport.
        """
        raise NotImplementedError()

    def close(self) -> None:
        """Closes the transport.

        Closes the transport and shuts down and connections to the peer.
        """
        raise NotImplementedError()

    def write(
        self,
        data: bytes,
    ) -> None:
        """Write data to send.

        Sends the data to the peer through the current transport.

        Args:
            data: The data to write, this should be the SMB header and payload
                to write.
        """
        raise NotImplementedError()
