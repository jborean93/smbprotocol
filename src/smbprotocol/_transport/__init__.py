# -*- coding: utf-8 -*-
# Copyright: (c) 2022, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import typing as t

from ._base import SMBProtocol, SMBTransport
from ._tcp import TcpTransport


def create_connection(
    host: str,
    port: int,
    protocol_factory: t.Callable[[], SMBProtocol],
    timeout: float = 0,
) -> t.Tuple[SMBProtocol, SMBTransport]:
    """Open connection to host specified.

    Opens a connection to the host specified through a direct socket connection.
    This may support different transports in the future, like QUIC, but
    currently only SMB over TCP (port 445) is implemented.

    Args:
        host: The hostname/IP to connect to.
        port: The port to connect to over TCP.
        protocol_factory: Factory method to create the protocol instance.
        timeout: The connection timeout, 0 is no connection timeout.

    Returns:
        tuple[SMBProtocol, SMBTransport]: A tuple that is the protocol and
        transport instance of the connection.
    """

    proto = protocol_factory()
    transport = TcpTransport.create(host, port, timeout, proto)

    return proto, transport


__all__ = [
    "SMBProtocol",
    "SMBTransport",
    "create_connection",
]
