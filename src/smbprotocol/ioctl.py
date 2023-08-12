# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import binascii
import socket
from collections import OrderedDict

from smbprotocol import Dialects
from smbprotocol.connection import Capabilities, SecurityMode
from smbprotocol.header import Commands
from smbprotocol.structure import (
    BytesField,
    EnumField,
    FlagField,
    IntField,
    ListField,
    Structure,
    StructureField,
    UuidField,
)


class CtlCode:
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.31 SMB2 IOCTL Request CtlCode
    The control code of the FSCTL_IOCTL method.
    """

    FSCTL_DFS_GET_REFERRALS = 0x00060194
    FSCTL_PIPE_PEEK = 0x0011400C
    FSCTL_PIPE_WAIT = 0x00110018
    FSCTL_PIPE_TRANSCEIVE = 0x0011C017
    FSCTL_SRV_COPYCHUNK = 0x001440F2
    FSCTL_SRV_ENUMERATE_SNAPSHOTS = 0x00144064
    FSCTL_SRV_REQUEST_RESUME_KEY = 0x00140078
    FSCTL_SRV_READ_HASH = 0x001441BB
    FSCTL_SRV_COPYCHUNK_WRITE = 0x001480F2
    FSCTL_LMR_REQUEST_RESILIENCY = 0x001401D4
    FSCTL_QUERY_NETWORK_INTERFACE_INFO = 0x001401FC
    FSCTL_SET_REPARSE_POINT = 0x000900A4
    FSCTL_GET_REPARSE_POINT = 0x000900A8
    FSCTL_DELETE_REPARSE_POINT = 0x000900AC
    FSCTL_CREATE_OR_GET_OBJECT_ID = 0x000900C0
    FSCTL_SET_SPARSE = 0x000900C4
    FSCTL_QUERY_ALLOCATED_RANGES = 0x000940CF
    FSCTL_DFS_GET_REFERRALS_EX = 0x000601B0
    FSCTL_SET_ZERO_DATA = 0x000980C8
    FSCTL_FILE_LEVEL_TRIM = 0x00098208
    FSCTL_VALIDATE_NEGOTIATE_INFO = 0x00140204


class IOCTLFlags:
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.31 SMB2 IOCTL Request Flags
    A flag that indicates how to process the operation
    """

    SMB2_0_IOCTL_IS_IOCTL = 0x00000000
    SMB2_0_IOCTL_IS_FSCTL = 0x00000001


class HashVersion:
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.31.2 SRV_READ_HASH Request HashVersion
    The version number of the algorithm used to create the Content Information.
    """

    SRV_HASH_VER_1 = 0x00000001
    SRV_HASH_VER_2 = 0x00000002


class HashRetrievalType:
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.31.2 SRV_READ_HASH Request HashRetrievalType
    Indicates the nature of the Offset field in am SMB2SrvReadHashRequest
    packet.
    """

    SRV_HASH_RETRIEVE_HASH_BASED = 0x00000001
    SRV_HASH_RETRIEVE_FILE_BASED = 0x00000002


class IfCapability:
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.32.5 NETWORK_INTERFACE_INFO Response Capability
    The capabilities of the network interface
    """

    RSS_CAPABLE = 0x00000001
    RDMA_CAPABLE = 0x00000002


class SockAddrFamily:
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.32.5.1 SOCKADDR_STORAGE Family
    The address family of the socket.
    """

    INTER_NETWORK = 0x0002
    INTER_NETWORK_V6 = 0x0017


class SMB2IOCTLRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.31 SMB2 IOCTL Request
    Send by the client to issue an implementation-specific file system control
    or device control command across the network.
    """

    COMMAND = Commands.SMB2_IOCTL

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("structure_size", IntField(size=2, default=57)),
                ("reserved", IntField(size=2, default=0)),
                (
                    "ctl_code",
                    EnumField(
                        size=4,
                        enum_type=CtlCode,
                    ),
                ),
                ("file_id", BytesField(size=16)),
                ("input_offset", IntField(size=4, default=lambda s: self._buffer_offset_value(s))),
                (
                    "input_count",
                    IntField(
                        size=4,
                        default=lambda s: len(s["buffer"]),
                    ),
                ),
                ("max_input_response", IntField(size=4)),
                ("output_offset", IntField(size=4, default=lambda s: self._buffer_offset_value(s))),
                ("output_count", IntField(size=4, default=0)),
                ("max_output_response", IntField(size=4)),
                (
                    "flags",
                    EnumField(
                        size=4,
                        enum_type=IOCTLFlags,
                    ),
                ),
                ("reserved2", IntField(size=4, default=0)),
                ("buffer", BytesField(size=lambda s: s["input_count"].get_value())),
            ]
        )
        super().__init__()

    def _buffer_offset_value(self, structure):
        # The offset from the beginning of the SMB2 header to the value of the
        # buffer, 0 if no buffer is set
        if len(structure["buffer"]) > 0:
            header_size = 64
            request_size = structure["structure_size"].get_value()
            return header_size + request_size - 1
        else:
            return 0


class SMB2SrvCopyChunkCopy(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.31.1 SRV_COPYCHUNK_COPY
    Sent in an SMB2 IOCTL Request by the client to initiate a server-side copy
    of data.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("source_key", BytesField(size=24)),
                ("chunk_count", IntField(size=4, default=lambda s: len(s["chunks"].get_value()))),
                ("reserved", IntField(size=4)),
                (
                    "chunks",
                    ListField(
                        size=lambda s: s["chunk_count"].get_value() * 24,
                        list_count=lambda s: s["chunk_count"].get_value(),
                        list_type=StructureField(size=24, structure_type=SMB2SrvCopyChunk),
                    ),
                ),
            ]
        )
        super().__init__()


class SMB2SrvCopyChunk(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.31.1.1 SRC_COPYCHUNK
    Packet sent in the Chunks array of an SRC_COPY_CHUNK_COPY packet to
    describe an individual data range to copy.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("source_offset", IntField(size=8)),
                ("target_offset", IntField(size=8)),
                ("length", IntField(size=4)),
                ("reserved", IntField(size=4)),
            ]
        )
        super().__init__()


class SMB2SrvReadHashRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.31.2 SRC_READ_HASH Request
    Sent by the client in an SMB2 IOCTL Request to retrieve data from the
    Content Information File associated with a specified file.
    Not valid for the SMB 2.0.2 dialect.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("hash_type", IntField(size=4, default=1)),  # SRV_HASH_TYPE_PEER_DIST
                ("hash_version", EnumField(size=4, enum_type=HashVersion)),
                ("hash_retrieval_type", EnumField(size=4, enum_type=HashRetrievalType)),
                ("length", IntField(size=4)),
                ("offset", IntField(size=8)),
            ]
        )
        super().__init__()


class SMB2SrvNetworkResiliencyRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.31.3 NETWORK_RESILIENCY_REQUEST Request
    Sent by the client to request resiliency for a specified open file.
    Not valid for the SMB 2.0.2 dialect.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                # timeout is in milliseconds
                ("timeout", IntField(size=4)),
                ("reserved", IntField(size=4)),
            ]
        )
        super().__init__()


class SMB2ValidateNegotiateInfoRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.31.4 VALIDATE_NEGOTIATE_INFO Request
    Packet sent to the server to request validation of a previous SMB 2
    NEGOTIATE request.
    Only valid for the SMB 3.0 and 3.0.2 dialects.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                (
                    "capabilities",
                    FlagField(
                        size=4,
                        flag_type=Capabilities,
                    ),
                ),
                ("guid", UuidField()),
                (
                    "security_mode",
                    EnumField(
                        size=2,
                        enum_type=SecurityMode,
                    ),
                ),
                ("dialect_count", IntField(size=2, default=lambda s: len(s["dialects"].get_value()))),
                (
                    "dialects",
                    ListField(
                        size=lambda s: s["dialect_count"].get_value() * 2,
                        list_count=lambda s: s["dialect_count"].get_value(),
                        list_type=EnumField(size=2, enum_type=Dialects),
                    ),
                ),
            ]
        )
        super().__init__()


class SMB2IOCTLResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.32 SMB2 IOCTL Response
    Sent by the server to transmit the results of a client SMB2 IOCTL Request.
    """

    COMMAND = Commands.SMB2_IOCTL

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("structure_size", IntField(size=2, default=49)),
                ("reserved", IntField(size=2, default=0)),
                (
                    "ctl_code",
                    EnumField(
                        size=4,
                        enum_type=CtlCode,
                    ),
                ),
                ("file_id", BytesField(size=16)),
                ("input_offset", IntField(size=4)),
                ("input_count", IntField(size=4)),
                ("output_offset", IntField(size=4)),
                ("output_count", IntField(size=4)),
                ("flags", IntField(size=4, default=0)),
                ("reserved2", IntField(size=4, default=0)),
                (
                    "buffer",
                    BytesField(
                        size=lambda s: s["output_count"].get_value(),
                    ),
                ),
            ]
        )
        super().__init__()


class SMB2SrvCopyChunkResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.32.1 SRV_COPYCHUNK_RESPONSE
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("chunks_written", IntField(size=4)),
                ("chunk_bytes_written", IntField(size=4)),
                ("total_bytes_written", IntField(size=4)),
            ]
        )
        super().__init__()


class SMB2SrvSnapshotArray(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.32.2 SRV_SNAPSHOT_ARRAY
    Sent by the server in response to an SMB2IOCTLResponse for the
    FSCTL_SRV_ENUMERATE_SNAPSHOTS request.
    """

    def __init__(self):
        # TODO: validate this further when working with actual snapshots
        self.fields = OrderedDict(
            [
                ("number_of_snapshots", IntField(size=4)),
                ("number_of_snapshots_returned", IntField(size=4)),
                ("snapshot_array_size", IntField(size=4)),
                ("snapshots", BytesField()),
            ]
        )
        super().__init__()


class SMB2SrvRequestResumeKey(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.32.3 SRV_REQUEST_RESUME_KEY Response
    Sent by the server in response to an SMB2IOCTLResponse for the
    FSCTL_SRV_REQUEST_RESUME_KEY request.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("resume_key", BytesField(size=24)),
                (
                    "context_length",
                    IntField(
                        size=4,
                        default=lambda s: len(s["context"]),
                    ),
                ),
                (
                    "context",
                    BytesField(
                        size=lambda s: s["context_length"].get_value(),
                    ),
                ),
            ]
        )
        super().__init__()


class SMB2NetworkInterfaceInfo(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.32.5 NETWORK_INTERFACE_INFO Response
    The NETWORK_INTERFACE_INFO returned to the client in an SMB2IOCTLResposne
    for the FSCTL_QUERY_NETWORK_INTERFACE_INFO.

    Use the pack_multiple and unpack_multiple to handle multiple interfaces
    that are returned in the SMB2IOCTLResponse
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                # 0 if no more network interfaces
                ("next", IntField(size=4)),
                ("if_index", IntField(size=4)),
                ("capability", FlagField(size=4, flag_type=IfCapability)),
                ("reserved", IntField(size=4)),
                ("link_speed", IntField(size=8)),
                ("sock_addr_storage", StructureField(size=128, structure_type=SockAddrStorage)),
            ]
        )
        super().__init__()

    @staticmethod
    def pack_multiple(messages):
        """
        Packs a list of SMB2NetworkInterfaceInfo messages and set's the next
        value accordingly. The byte value returned is then attached to the
        SMBIOCTLResponse message.

        :param messages: List of SMB2NetworkInterfaceInfo messages
        :return: bytes of the packed messages
        """
        data = b""
        msg_count = len(messages)
        for i, msg in enumerate(messages):
            if i == msg_count - 1:
                msg["next"] = 0
            else:
                msg["next"] = 152
            data += msg.pack()
        return data

    @staticmethod
    def unpack_multiple(data):
        """
        Get's a list of SMB2NetworkInterfaceInfo messages from the byte value
        passed in. This is the raw buffer value that is set on the
        SMB2IOCTLResponse message.

        :param data: bytes of the messages
        :return: List of SMB2NetworkInterfaceInfo messages
        """
        chunks = []
        while data:
            info = SMB2NetworkInterfaceInfo()
            data = info.unpack(data)
            chunks.append(info)

        return chunks


class SockAddrStorage(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.32.5.1 SOCKADDR_STORAGE
    Socket Address information.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("family", EnumField(size=2, enum_type=SockAddrFamily)),
                (
                    "buffer",
                    StructureField(
                        size=lambda s: self._get_buffer_size(s),
                        structure_type=lambda s: self._get_buffer_structure_type(s),
                    ),
                ),
                (
                    "reserved",
                    BytesField(
                        size=lambda s: self._get_reserved_size(s),
                        default=lambda s: b"\x00" * self._get_reserved_size(s),
                    ),
                ),
            ]
        )
        super().__init__()

    def _get_buffer_size(self, structure):
        if structure["family"].get_value() == SockAddrFamily.INTER_NETWORK:
            return 14
        else:
            return 26

    def _get_buffer_structure_type(self, structure):
        if structure["family"].get_value() == SockAddrFamily.INTER_NETWORK:
            return SockAddrIn
        else:
            return SockAddrIn6

    def _get_reserved_size(self, structure):
        if structure["family"].get_value() == SockAddrFamily.INTER_NETWORK:
            return 112
        else:
            return 100


class SockAddrIn(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.32.5.1.1 SOCKADDR_IN
    Socket address information for an IPv4 address
    """

    def __init__(self):
        self.fields = OrderedDict(
            [("port", IntField(size=2)), ("ipv4_address", BytesField(size=4)), ("reserved", IntField(size=8))]
        )
        super().__init__()

    def get_ipaddress(self):
        addr_bytes = self["ipv4_address"].get_value()
        return socket.inet_ntoa(addr_bytes)

    def set_ipaddress(self, address):
        # set's the ipv4 address field from the address string passed in, this
        # needs to be the full ipv4 address including periods, e.g.
        # 192.168.1.1
        addr_bytes = socket.inet_aton(address)
        self["ipv4_address"].set_value(addr_bytes)


class SockAddrIn6(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.32.5.1.2 SOCKADDR_IN6
    Socket address information for an IPv6 address
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("port", IntField(size=2)),
                ("flow_info", IntField(size=4)),
                ("ipv6_address", BytesField(size=16)),
                ("scope_id", IntField(size=4)),
            ]
        )
        super().__init__()

    def get_ipaddress(self):
        # get's the full IPv6 Address, note this is the full address and has
        # not been concatenated
        addr_bytes = self["ipv6_address"].get_value()
        address = binascii.hexlify(addr_bytes).decode("utf-8")
        return ":".join([address[i : i + 4] for i in range(0, len(address), 4)])

    def set_ipaddress(self, address):
        # set's the ipv6_address field from the address passed in, note this
        # needs to be the full ipv6 address,
        # e.g. fe80:0000:0000:0000:0000:0000:0000:0000 and not any short form
        address = address.replace(":", "")
        if len(address) != 32:
            raise ValueError("When setting an IPv6 address, it must be in the full form without concatenation")
        self["ipv6_address"].set_value(binascii.unhexlify(address))


class SMB2ValidateNegotiateInfoResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.32.6 VALIDATE_NEGOTIATE_INFO Response
    Packet sent by the server on a request validation of SMB 2 negotiate
    request.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                (
                    "capabilities",
                    FlagField(
                        size=4,
                        flag_type=Capabilities,
                    ),
                ),
                ("guid", UuidField()),
                ("security_mode", EnumField(size=2, enum_type=SecurityMode, enum_strict=False)),
                ("dialect", EnumField(size=2, enum_type=Dialects)),
            ]
        )
        super().__init__()
