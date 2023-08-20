# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import uuid

import pytest

from smbprotocol import Dialects
from smbprotocol.ioctl import (
    CtlCode,
    HashRetrievalType,
    HashVersion,
    IfCapability,
    IOCTLFlags,
    SMB2IOCTLRequest,
    SMB2IOCTLResponse,
    SMB2NetworkInterfaceInfo,
    SMB2SrvCopyChunk,
    SMB2SrvCopyChunkCopy,
    SMB2SrvCopyChunkResponse,
    SMB2SrvNetworkResiliencyRequest,
    SMB2SrvReadHashRequest,
    SMB2SrvRequestResumeKey,
    SMB2SrvSnapshotArray,
    SMB2ValidateNegotiateInfoRequest,
    SMB2ValidateNegotiateInfoResponse,
    SockAddrFamily,
    SockAddrIn,
    SockAddrIn6,
    SockAddrStorage,
)


class TestSMB2IOCTLRequest:
    def test_create_message(self):
        message = SMB2IOCTLRequest()
        message["ctl_code"] = CtlCode.FSCTL_VALIDATE_NEGOTIATE_INFO
        message["file_id"] = b"\xff" * 16
        message["max_input_response"] = 12
        message["max_output_response"] = 12
        message["flags"] = IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL
        message["buffer"] = b"\x12\x13\x14\x15"
        expected = (
            b"\x39\x00"
            b"\x00\x00"
            b"\x04\x02\x14\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x78\x00\x00\x00"
            b"\x04\x00\x00\x00"
            b"\x0c\x00\x00\x00"
            b"\x78\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x0c\x00\x00\x00"
            b"\x01\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x12\x13\x14\x15"
        )
        actual = message.pack()
        assert len(message) == 60
        assert actual == expected

    def test_create_message_no_buffer(self):
        message = SMB2IOCTLRequest()
        message["ctl_code"] = CtlCode.FSCTL_VALIDATE_NEGOTIATE_INFO
        message["file_id"] = b"\xff" * 16
        message["flags"] = IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL
        expected = (
            b"\x39\x00"
            b"\x00\x00"
            b"\x04\x02\x14\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x01\x00\x00\x00"
            b"\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 56
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2IOCTLRequest()
        data = (
            b"\x39\x00"
            b"\x00\x00"
            b"\x04\x02\x14\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x78\x00\x00\x00"
            b"\x04\x00\x00\x00"
            b"\x0c\x00\x00\x00"
            b"\x78\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x0c\x00\x00\x00"
            b"\x01\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x12\x13\x14\x15"
        )
        actual.unpack(data)
        assert len(actual) == 60
        assert actual["structure_size"].get_value() == 57
        assert actual["reserved"].get_value() == 0
        assert actual["ctl_code"].get_value() == CtlCode.FSCTL_VALIDATE_NEGOTIATE_INFO
        assert actual["file_id"].pack() == b"\xff" * 16
        assert actual["input_offset"].get_value() == 120
        assert actual["input_count"].get_value() == 4
        assert actual["max_input_response"].get_value() == 12
        assert actual["output_offset"].get_value() == 120
        assert actual["output_count"].get_value() == 0
        assert actual["max_output_response"].get_value() == 12
        assert actual["flags"].get_value() == IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL
        assert actual["reserved2"].get_value() == 0
        assert actual["buffer"].get_value() == b"\x12\x13\x14\x15"


class TestSMB2SrvCopyChunkCopy:
    def test_create_message(self):
        chunk1 = SMB2SrvCopyChunk()
        chunk1["source_offset"] = 0
        chunk1["target_offset"] = 10
        chunk1["length"] = 10

        chunk2 = SMB2SrvCopyChunk()
        chunk2["source_offset"] = 10
        chunk2["target_offset"] = 20
        chunk2["length"] = 10

        message = SMB2SrvCopyChunkCopy()
        message["source_key"] = b"\x11" * 24
        message["chunks"] = [chunk1, chunk2]

        expected = (
            b"\x11\x11\x11\x11\x11\x11\x11\x11"
            b"\x11\x11\x11\x11\x11\x11\x11\x11"
            b"\x11\x11\x11\x11\x11\x11\x11\x11"
            b"\x02\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x0a\x00\x00\x00\x00\x00\x00\x00"
            b"\x0a\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x0a\x00\x00\x00\x00\x00\x00\x00"
            b"\x14\x00\x00\x00\x00\x00\x00\x00"
            b"\x0a\x00\x00\x00"
            b"\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 80
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2SrvCopyChunkCopy()
        data = (
            b"\x11\x11\x11\x11\x11\x11\x11\x11"
            b"\x11\x11\x11\x11\x11\x11\x11\x11"
            b"\x11\x11\x11\x11\x11\x11\x11\x11"
            b"\x02\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x0a\x00\x00\x00\x00\x00\x00\x00"
            b"\x0a\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x0a\x00\x00\x00\x00\x00\x00\x00"
            b"\x14\x00\x00\x00\x00\x00\x00\x00"
            b"\x0a\x00\x00\x00"
            b"\x00\x00\x00\x00"
        )
        actual.unpack(data)
        assert len(actual) == 80
        assert actual["source_key"].get_value() == b"\x11" * 24
        assert actual["chunk_count"].get_value() == 2
        assert actual["reserved"].get_value() == 0
        assert len(actual["chunks"].get_value()) == 2
        chunk1 = actual["chunks"][0]
        assert chunk1["source_offset"].get_value() == 0
        assert chunk1["target_offset"].get_value() == 10
        assert chunk1["length"].get_value() == 10
        assert chunk1["reserved"].get_value() == 0
        chunk2 = actual["chunks"][1]
        assert chunk2["source_offset"].get_value() == 10
        assert chunk2["target_offset"].get_value() == 20
        assert chunk2["length"].get_value() == 10
        assert chunk2["reserved"].get_value() == 0


class TestSMB2SrvCopyChunk:
    def test_create_message(self):
        message = SMB2SrvCopyChunk()
        message["source_offset"] = 1234
        message["target_offset"] = 5678
        message["length"] = 10
        expected = (
            b"\xd2\x04\x00\x00\x00\x00\x00\x00"
            b"\x2e\x16\x00\x00\x00\x00\x00\x00"
            b"\x0a\x00\x00\x00"
            b"\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 24
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2SrvCopyChunk()
        data = (
            b"\xd2\x04\x00\x00\x00\x00\x00\x00"
            b"\x2e\x16\x00\x00\x00\x00\x00\x00"
            b"\x0a\x00\x00\x00"
            b"\x00\x00\x00\x00"
        )
        actual.unpack(data)
        assert len(actual) == 24
        assert actual["source_offset"].get_value() == 1234
        assert actual["target_offset"].get_value() == 5678
        assert actual["length"].get_value() == 10
        assert actual["reserved"].get_value() == 0


class TestSMB2SrcReadHashRequest:
    def test_create_message(self):
        message = SMB2SrvReadHashRequest()
        message["hash_version"] = HashVersion.SRV_HASH_VER_2
        message["hash_retrieval_type"] = HashRetrievalType.SRV_HASH_RETRIEVE_FILE_BASED
        message["length"] = 10
        message["offset"] = 10
        expected = (
            b"\x01\x00\x00\x00"
            b"\x02\x00\x00\x00"
            b"\x02\x00\x00\x00"
            b"\x0a\x00\x00\x00"
            b"\x0a\x00\x00\x00\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 24
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2SrvReadHashRequest()
        data = (
            b"\x01\x00\x00\x00"
            b"\x02\x00\x00\x00"
            b"\x02\x00\x00\x00"
            b"\x0a\x00\x00\x00"
            b"\x0a\x00\x00\x00\x00\x00\x00\x00"
        )
        actual.unpack(data)
        assert len(actual) == 24
        assert actual["hash_type"].get_value() == 1
        assert actual["hash_version"].get_value() == HashVersion.SRV_HASH_VER_2
        assert actual["hash_retrieval_type"].get_value() == HashRetrievalType.SRV_HASH_RETRIEVE_FILE_BASED
        assert actual["length"].get_value() == 10
        assert actual["offset"].get_value() == 10


class TestSMB2SrvNetworkResiliencyRequest:
    def test_create_message(self):
        message = SMB2SrvNetworkResiliencyRequest()
        message["timeout"] = 100
        expected = b"\x64\x00\x00\x00" b"\x00\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 8
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2SrvNetworkResiliencyRequest()
        data = b"\x64\x00\x00\x00" b"\x00\x00\x00\x00"
        actual.unpack(data)
        assert len(actual) == 8
        assert actual["timeout"].get_value() == 100
        assert actual["reserved"].get_value() == 0


class TestSMB2ValidateNegotiateInfoRequest:
    def test_create_message(self):
        message = SMB2ValidateNegotiateInfoRequest()
        message["capabilities"] = 8
        message["guid"] = b"\x11" * 16
        message["security_mode"] = 1
        message["dialect_count"] = 2
        message["dialects"] = [Dialects.SMB_2_0_2, Dialects.SMB_2_1_0]
        expected = (
            b"\x08\x00\x00\x00"
            b"\x11\x11\x11\x11\x11\x11\x11\x11"
            b"\x11\x11\x11\x11\x11\x11\x11\x11"
            b"\x01\x00"
            b"\x02\x00"
            b"\x02\x02\x10\x02"
        )
        actual = message.pack()
        assert len(message) == 28
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2ValidateNegotiateInfoRequest()
        data = (
            b"\x08\x00\x00\x00"
            b"\x11\x11\x11\x11\x11\x11\x11\x11"
            b"\x11\x11\x11\x11\x11\x11\x11\x11"
            b"\x01\x00"
            b"\x02\x00"
            b"\x02\x02\x10\x02"
        )
        actual.unpack(data)
        assert len(actual) == 28
        assert actual["capabilities"].get_value() == 8
        assert actual["guid"].get_value() == uuid.UUID(bytes=b"\x11" * 16)
        assert actual["security_mode"].get_value() == 1
        assert actual["dialect_count"].get_value() == 2
        assert actual["dialects"][0] == 514
        assert actual["dialects"][1] == 528
        assert len(actual["dialects"].get_value()) == 2


class TestSMB2IOCTLResponse:
    def test_create_message(self):
        message = SMB2IOCTLResponse()
        message["ctl_code"] = CtlCode.FSCTL_VALIDATE_NEGOTIATE_INFO
        message["file_id"] = b"\xff" * 16
        message["input_offset"] = 0
        message["input_count"] = 0
        message["output_offset"] = 112
        message["output_count"] = 4
        message["flags"] = IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL
        message["buffer"] = b"\x20\x21\x22\x23"
        expected = (
            b"\x31\x00\x00\x00"
            b"\x04\x02\x14\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x70\x00\x00\x00"
            b"\x04\x00\x00\x00"
            b"\x01\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x20\x21\x22\x23"
        )
        actual = message.pack()
        assert len(message) == 52
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2IOCTLResponse()
        data = (
            b"\x31\x00\x00\x00"
            b"\x04\x02\x14\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x70\x00\x00\x00"
            b"\x04\x00\x00\x00"
            b"\x01\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x20\x21\x22\x23"
        )
        actual.unpack(data)
        assert len(actual) == 52
        assert actual["structure_size"].get_value() == 49
        assert actual["reserved"].get_value() == 0
        assert actual["ctl_code"].get_value() == CtlCode.FSCTL_VALIDATE_NEGOTIATE_INFO
        assert actual["file_id"].pack() == b"\xff" * 16
        assert actual["input_offset"].get_value() == 0
        assert actual["input_count"].get_value() == 0
        assert actual["output_offset"].get_value() == 112
        assert actual["output_count"].get_value() == 4
        assert actual["flags"].get_value() == IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL
        assert actual["reserved2"].get_value() == 0
        assert actual["buffer"].get_value() == b"\x20\x21\x22\x23"


class TestSMB2SrvCopyChunkResponse:
    def test_create_message(self):
        message = SMB2SrvCopyChunkResponse()
        message["chunks_written"] = 2
        message["chunk_bytes_written"] = 10
        message["total_bytes_written"] = 10
        expected = b"\x02\x00\x00\x00" b"\x0a\x00\x00\x00" b"\x0a\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 12
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2SrvCopyChunkResponse()
        data = b"\x02\x00\x00\x00" b"\x0a\x00\x00\x00" b"\x0a\x00\x00\x00"
        actual.unpack(data)
        assert len(actual) == 12
        assert actual["chunks_written"].get_value() == 2
        assert actual["chunk_bytes_written"].get_value() == 10
        assert actual["total_bytes_written"].get_value() == 10


class TestSMB2SrvSnapshotArray:
    def test_create_message(self):
        message = SMB2SrvSnapshotArray()
        message["snapshot_array_size"] = 2
        message["snapshots"] = b"\x00\x00\x00\x00"
        expected = b"\x00\x00\x00\x00" b"\x00\x00\x00\x00" b"\x02\x00\x00\x00" b"\x00\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 16
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2SrvSnapshotArray()
        data = b"\x00\x00\x00\x00" b"\x00\x00\x00\x00" b"\x02\x00\x00\x00" b"\x00\x00\x00\x00"
        actual.unpack(data)
        assert len(actual) == 16
        assert actual["number_of_snapshots"].get_value() == 0
        assert actual["number_of_snapshots_returned"].get_value() == 0
        assert actual["snapshot_array_size"].get_value() == 2
        assert actual["snapshots"].get_value() == b"\x00\x00\x00\x00"


class TestSMB2SrvRequestResumeKey:
    def test_create_message(self):
        message = SMB2SrvRequestResumeKey()
        message["resume_key"] = b"\xff" * 24
        expected = (
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 28
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2SrvRequestResumeKey()
        data = (
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x00\x00\x00\x00"
        )
        actual.unpack(data)
        assert len(actual) == 28
        assert actual["resume_key"].get_value() == b"\xff" * 24
        assert actual["context_length"].get_value() == 0


class TestSMB2NetworkInterfaceInfo:
    def test_create_message(self):
        addr1 = SockAddrIn()
        addr1.set_ipaddress("10.0.2.15")
        sock_addr1 = SockAddrStorage()
        sock_addr1["family"] = SockAddrFamily.INTER_NETWORK
        sock_addr1["buffer"] = addr1
        msg1 = SMB2NetworkInterfaceInfo()
        msg1["if_index"] = 2
        msg1["link_speed"] = 1000000000
        msg1["sock_addr_storage"] = sock_addr1

        addr2 = SockAddrIn6()
        addr2.set_ipaddress("fe80:0000:0000:0000:894a:2dbc:1d9c:2da1")
        sock_addr2 = SockAddrStorage()
        sock_addr2["family"] = SockAddrFamily.INTER_NETWORK_V6
        sock_addr2["buffer"] = addr2
        msg2 = SMB2NetworkInterfaceInfo()
        msg2["if_index"] = 4
        msg2["capability"].set_flag(IfCapability.RSS_CAPABLE)
        msg2["link_speed"] = 1000000
        msg2["sock_addr_storage"] = sock_addr2

        expected = (
            b"\x98\x00\x00\x00"
            b"\x02\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\xca\x9a\x3b\x00\x00\x00\x00"
            b"\x02\x00"
            b"\x00\x00"
            b"\x0a\x00\x02\x0f"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        expected += b"\x00" * 112
        expected += (
            b"\x00\x00\x00\x00"
            b"\x04\x00\x00\x00"
            b"\x01\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x40\x42\x0f\x00\x00\x00\x00\x00"
            b"\x17\x00"
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xfe\x80\x00\x00\x00\x00\x00\x00"
            b"\x89\x4a\x2d\xbc\x1d\x9c\x2d\xa1"
            b"\x00\x00\x00\x00"
        )
        expected += b"\x00" * 100
        actual = SMB2NetworkInterfaceInfo.pack_multiple([msg1, msg2])
        assert len(msg1) == 152
        assert len(msg2) == 152
        assert actual == expected

    def test_parse_message(self):
        data = (
            b"\x98\x00\x00\x00"
            b"\x02\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\xca\x9a\x3b\x00\x00\x00\x00"
            b"\x02\x00"
            b"\x00\x00"
            b"\x0a\x00\x02\x0f"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        data += b"\x00" * 112
        data += (
            b"\x00\x00\x00\x00"
            b"\x04\x00\x00\x00"
            b"\x01\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x40\x42\x0f\x00\x00\x00\x00\x00"
            b"\x17\x00"
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xfe\x80\x00\x00\x00\x00\x00\x00"
            b"\x89\x4a\x2d\xbc\x1d\x9c\x2d\xa1"
            b"\x00\x00\x00\x00"
        )
        data += b"\x00" * 100
        actual = SMB2NetworkInterfaceInfo.unpack_multiple(data)
        assert len(actual) == 2
        assert len(actual[0]) == 152
        assert len(actual[1]) == 152

        assert actual[0]["next"].get_value() == 152
        assert actual[0]["if_index"].get_value() == 2
        assert actual[0]["capability"].get_value() == 0
        assert actual[0]["reserved"].get_value() == 0
        assert actual[0]["link_speed"].get_value() == 1000000000
        actual_sock1 = actual[0]["sock_addr_storage"].get_value()
        assert actual_sock1["family"].get_value() == SockAddrFamily.INTER_NETWORK

        assert actual[1]["next"].get_value() == 0
        assert actual[1]["if_index"].get_value() == 4
        assert actual[1]["capability"].get_value() == IfCapability.RSS_CAPABLE
        assert actual[1]["reserved"].get_value() == 0
        assert actual[1]["link_speed"].get_value() == 1000000
        actual_sock2 = actual[1]["sock_addr_storage"].get_value()
        assert actual_sock2["family"].get_value() == SockAddrFamily.INTER_NETWORK_V6


class TestSockAddrStorage:
    def test_create_message_ipv4(self):
        message = SockAddrStorage()
        message["family"] = SockAddrFamily.INTER_NETWORK
        sock_addr = SockAddrIn()
        sock_addr.set_ipaddress("10.0.2.15")
        message["buffer"] = sock_addr
        expected = b"\x02\x00" b"\x00\x00" b"\x0a\x00\x02\x0f" b"\x00\x00\x00\x00\x00\x00\x00\x00"
        expected += b"\x00" * 112
        actual = message.pack()
        assert len(message) == 128
        assert actual == expected

    def test_create_message_ipv6(self):
        message = SockAddrStorage()
        message["family"] = SockAddrFamily.INTER_NETWORK_V6
        sock_addr = SockAddrIn6()
        sock_addr.set_ipaddress("fe80:0000:0000:0000:894a:2dbc:1d9c:2da1")
        message["buffer"] = sock_addr
        expected = (
            b"\x17\x00"
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xfe\x80\x00\x00\x00\x00\x00\x00"
            b"\x89\x4a\x2d\xbc\x1d\x9c\x2d\xa1"
            b"\x00\x00\x00\x00"
        )
        expected += b"\x00" * 100
        actual = message.pack()
        assert len(message) == 128
        assert actual == expected

    def test_parse_message_ipv4(self):
        actual = SockAddrStorage()
        data = b"\x02\x00" b"\x00\x00" b"\x0a\x00\x02\x0f" b"\x00\x00\x00\x00\x00\x00\x00\x00"
        data += b"\x00" * 112
        actual.unpack(data)
        assert len(actual) == 128
        assert actual["family"].get_value() == SockAddrFamily.INTER_NETWORK
        sock_addr = actual["buffer"].get_value()
        assert isinstance(sock_addr, SockAddrIn)
        assert sock_addr.get_ipaddress() == "10.0.2.15"

    def test_parse_message_ipv6(self):
        actual = SockAddrStorage()
        data = (
            b"\x17\x00"
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xfe\x80\x00\x00\x00\x00\x00\x00"
            b"\x89\x4a\x2d\xbc\x1d\x9c\x2d\xa1"
            b"\x00\x00\x00\x00"
        )
        data += b"\x00" * 100
        actual.unpack(data)
        assert len(actual) == 128
        assert actual["family"].get_value() == SockAddrFamily.INTER_NETWORK_V6
        sock_addr = actual["buffer"].get_value()
        assert isinstance(sock_addr, SockAddrIn6)
        assert sock_addr.get_ipaddress() == "fe80:0000:0000:0000:894a:2dbc:1d9c:2da1"


class TestSockAddrIn:
    def test_create_message(self):
        message = SockAddrIn()
        message.set_ipaddress("10.0.2.15")
        expected = b"\x00\x00" b"\x0a\x00\x02\x0f" b"\x00\x00\x00\x00\x00\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 14
        assert actual == expected

    def test_create_message_subnet(self):
        message = SockAddrIn()
        message.set_ipaddress("255.255.255.255")
        expected = b"\x00\x00" b"\xff\xff\xff\xff" b"\x00\x00\x00\x00\x00\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 14
        assert actual == expected

    def test_parse_message(self):
        actual = SockAddrIn()
        data = b"\x00\x00" b"\x0a\x00\x02\x0f" b"\x00\x00\x00\x00\x00\x00\x00\x00"
        actual.unpack(data)
        assert len(actual) == 14
        assert actual["port"].get_value() == 0
        assert actual["ipv4_address"].get_value() == b"\x0a\x00\x02\x0f"
        assert actual["reserved"].get_value() == 0
        assert actual.get_ipaddress() == "10.0.2.15"


class TestSockAddrIn6:
    def test_create_message(self):
        message = SockAddrIn6()
        message.set_ipaddress("fe80:0000:0000:0000:894a:2dbc:1d9c:2da1")
        expected = (
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xfe\x80\x00\x00\x00\x00\x00\x00"
            b"\x89\x4a\x2d\xbc\x1d\x9c\x2d\xa1"
            b"\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 26
        assert actual == expected

    def test_set_ipaddress_invalid_format(self):
        message = SockAddrIn6()
        with pytest.raises(ValueError) as exc:
            message.set_ipaddress("fe80::894a:2dbc:1d9c:2da1")
        assert str(exc.value) == "When setting an IPv6 address, it must be in the full form without concatenation"

    def test_parse_message(self):
        actual = SockAddrIn6()
        data = (
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xfe\x80\x00\x00\x00\x00\x00\x00"
            b"\x89\x4a\x2d\xbc\x1d\x9c\x2d\xa1"
            b"\x00\x00\x00\x00"
        )
        actual.unpack(data)
        assert len(actual) == 26
        assert actual["port"].get_value() == 0
        assert actual["flow_info"].get_value() == 0
        assert (
            actual["ipv6_address"].get_value() == b"\xfe\x80\x00\x00\x00\x00\x00\x00"
            b"\x89\x4a\x2d\xbc\x1d\x9c\x2d\xa1"
        )
        assert actual["scope_id"].get_value() == 0
        assert actual.get_ipaddress() == "fe80:0000:0000:0000:894a:2dbc:1d9c:2da1"


class TestSMB2ValidateNegotiateInfoResponse:
    def test_create_message(self):
        message = SMB2ValidateNegotiateInfoResponse()
        message["capabilities"] = 8
        message["guid"] = b"\xff" * 16
        message["security_mode"] = 0
        message["dialect"] = Dialects.SMB_3_0_2
        expected = (
            b"\x08\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x00\x00"
            b"\x02\x03"
        )
        actual = message.pack()
        assert len(message) == 24
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2ValidateNegotiateInfoResponse()
        data = (
            b"\x08\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x00\x00"
            b"\x02\x03"
        )
        actual.unpack(data)
        assert len(actual) == 24
        assert actual["capabilities"].get_value() == 8
        assert actual["guid"].get_value() == uuid.UUID(bytes=b"\xff" * 16)
        assert actual["security_mode"].get_value() == 0
        assert actual["dialect"].get_value() == Dialects.SMB_3_0_2
