# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import re
import uuid
from datetime import datetime, timezone

import pytest

from smbprotocol.create_contexts import (
    CreateContextName,
    DurableHandleFlags,
    LeaseRequestFlags,
    LeaseResponseFlags,
    LeaseState,
    SMB2CreateAllocationSize,
    SMB2CreateAppInstanceId,
    SMB2CreateAppInstanceVersion,
    SMB2CreateContextRequest,
    SMB2CreateDurableHandleReconnect,
    SMB2CreateDurableHandleReconnectV2,
    SMB2CreateDurableHandleRequest,
    SMB2CreateDurableHandleRequestV2,
    SMB2CreateDurableHandleResponse,
    SMB2CreateDurableHandleResponseV2,
    SMB2CreateEABuffer,
    SMB2CreateQueryMaximalAccessRequest,
    SMB2CreateQueryMaximalAccessResponse,
    SMB2CreateQueryOnDiskIDResponse,
    SMB2CreateRequestLease,
    SMB2CreateRequestLeaseV2,
    SMB2CreateResponseLease,
    SMB2CreateResponseLeaseV2,
    SMB2CreateTimewarpToken,
    SMB2SVHDXOpenDeviceContextRequest,
    SMB2SVHDXOpenDeviceContextResponse,
    SMB2SVHDXOpenDeviceContextV2Request,
    SMB2SVHDXOpenDeviceContextV2Response,
    SVHDXOriginatorFlags,
)
from smbprotocol.header import NtStatus


class TestCreateContextName:
    def test_get_response_known(self):
        name = CreateContextName.SMB2_CREATE_QUERY_ON_DISK_ID
        actual = CreateContextName.get_response_structure(name)
        assert isinstance(actual, SMB2CreateQueryOnDiskIDResponse)

    def test_get_response_unknown(self):
        name = CreateContextName.SMB2_CREATE_EA_BUFFER
        expected = None
        actual = CreateContextName.get_response_structure(name)
        assert actual == expected


class TestSMB2CreateContextName:
    def test_create_message(self):
        ea_buffer1 = SMB2CreateEABuffer()
        ea_buffer1["ea_name"] = "Authors\x00".encode("ascii")
        ea_buffer1["ea_value"] = b"Jordan Borean"

        ea_buffer2 = SMB2CreateEABuffer()
        ea_buffer2["ea_name"] = "Title\x00".encode("ascii")
        ea_buffer2["ea_value"] = b"Jordan Borean Title"

        ea_buffers = SMB2CreateContextRequest()
        ea_buffers["buffer_name"] = CreateContextName.SMB2_CREATE_EA_BUFFER
        ea_buffers["buffer_data"] = SMB2CreateEABuffer.pack_multiple([ea_buffer1, ea_buffer2])

        alloc_size = SMB2CreateAllocationSize()
        alloc_size["allocation_size"] = 1024

        alloc_size_context = SMB2CreateContextRequest()
        alloc_size_context["buffer_name"] = CreateContextName.SMB2_CREATE_ALLOCATION_SIZE
        alloc_size_context["buffer_data"] = alloc_size

        query_disk = SMB2CreateContextRequest()
        query_disk["buffer_name"] = CreateContextName.SMB2_CREATE_QUERY_ON_DISK_ID

        expected = (
            b"\x60\x00\x00\x00"
            b"\x10\x00"
            b"\x04\x00"
            b"\x00\x00"
            b"\x18\x00"
            b"\x41\x00\x00\x00"
            b"\x45\x78\x74\x41"
            b"\x00\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x00"
            b"\x07"
            b"\x0d\x00"
            b"\x41\x75\x74\x68\x6f\x72\x73\x00"
            b"\x4a\x6f\x72\x64\x61\x6e\x20\x42"
            b"\x6f\x72\x65\x61\x6e"
            b"\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x05"
            b"\x13\x00"
            b"\x54\x69\x74\x6c\x65\x00"
            b"\x4a\x6f\x72\x64\x61\x6e\x20\x42"
            b"\x6f\x72\x65\x61\x6e\x20\x54\x69"
            b"\x74\x6c\x65"
            b"\x00\x00\x00\x00\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x10\x00"
            b"\x04\x00"
            b"\x00\x00"
            b"\x18\x00"
            b"\x08\x00\x00\x00"
            b"\x41\x6c\x53\x69"
            b"\x00\x00\x00\x00"
            b"\x00\x04\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x10\x00"
            b"\x04\x00"
            b"\x00\x00"
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x51\x46\x69\x64"
            b"\x00\x00\x00\x00"
        )

        actual = SMB2CreateContextRequest.pack_multiple([ea_buffers, alloc_size_context, query_disk])

        # now has padding on the end
        assert len(ea_buffers) == 96
        assert len(alloc_size_context) == 32
        assert len(query_disk) == 24
        assert actual == expected

    def test_pack_multiple_raw_context(self):
        alloc_size = SMB2CreateAllocationSize()
        alloc_size["allocation_size"] = 1024

        expected = (
            b"\x00\x00\x00\x00"
            b"\x10\x00"
            b"\x04\x00"
            b"\x00\x00"
            b"\x18\x00"
            b"\x08\x00\x00\x00"
            b"\x41\x6c\x53\x69"
            b"\x00\x00\x00\x00"
            b"\x00\x04\x00\x00\x00\x00\x00\x00"
        )
        actual = SMB2CreateContextRequest.pack_multiple([alloc_size])
        assert actual == expected

    def test_pack_multiple_bad_message(self):
        expected = (
            "Invalid context message, must be either a SMB2CreateContextRequest or a predefined structure "
            "object with NAME defined."
        )
        with pytest.raises(ValueError, match=re.escape(expected)):
            SMB2CreateContextRequest.pack_multiple([b"\x00"])

    def test_parse_message(self):
        actual1 = SMB2CreateContextRequest()
        actual2 = SMB2CreateContextRequest()
        actual3 = SMB2CreateContextRequest()
        data = (
            b"\x60\x00\x00\x00"
            b"\x10\x00"
            b"\x04\x00"
            b"\x00\x00"
            b"\x18\x00"
            b"\x41\x00\x00\x00"
            b"\x45\x78\x74\x41"
            b"\x00\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x00"
            b"\x07"
            b"\x0d\x00"
            b"\x41\x75\x74\x68\x6f\x72\x73\x00"
            b"\x4a\x6f\x72\x64\x61\x6e\x20\x42"
            b"\x6f\x72\x65\x61\x6e"
            b"\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x05"
            b"\x13\x00"
            b"\x54\x69\x74\x6c\x65\x00"
            b"\x4a\x6f\x72\x64\x61\x6e\x20\x42"
            b"\x6f\x72\x65\x61\x6e\x20\x54\x69"
            b"\x74\x6c\x65"
            b"\x00\x00\x00\x00\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x10\x00"
            b"\x04\x00"
            b"\x00\x00"
            b"\x18\x00"
            b"\x08\x00\x00\x00"
            b"\x41\x6c\x53\x69"
            b"\x00\x00\x00\x00"
            b"\x00\x04\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x10\x00"
            b"\x04\x00"
            b"\x00\x00"
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x51\x46\x69\x64"
            b"\x00\x00\x00\x00"
        )
        data = actual1.unpack(data)
        data = actual2.unpack(data)
        data = actual3.unpack(data)
        assert data == b""

        assert len(actual1) == 96
        assert actual1["next"].get_value() == 96
        assert actual1["name_offset"].get_value() == 16
        assert actual1["name_length"].get_value() == 4
        assert actual1["reserved"].get_value() == 0
        assert actual1["data_offset"].get_value() == 24
        assert actual1["data_length"].get_value() == 65
        assert actual1["buffer_name"].get_value() == b"\x45\x78\x74\x41"
        assert actual1["padding"].get_value() == b"\x00\x00\x00\x00"

        ea_buffer_data = actual1["buffer_data"].get_value()
        actual_ea_buffer1 = SMB2CreateEABuffer()
        actual_ea_buffer2 = SMB2CreateEABuffer()
        ea_buffer_data = actual_ea_buffer1.unpack(ea_buffer_data)
        ea_buffer_data = actual_ea_buffer2.unpack(ea_buffer_data)
        assert ea_buffer_data == b""
        assert len(actual_ea_buffer1) == 32
        assert actual_ea_buffer1["next_entry_offset"].get_value() == 32
        assert actual_ea_buffer1["flags"].get_value() == 0
        assert actual_ea_buffer1["ea_name_length"].get_value() == 7
        assert actual_ea_buffer1["ea_value_length"].get_value() == 13
        assert actual_ea_buffer1["ea_name"].get_value() == "Authors\x00".encode("ascii")
        assert actual_ea_buffer1["ea_value"].get_value() == b"Jordan Borean"
        assert actual_ea_buffer1["padding"].get_value() == b"\x00\x00\x00"
        assert len(actual_ea_buffer2) == 33
        assert actual_ea_buffer2["next_entry_offset"].get_value() == 0
        assert actual_ea_buffer2["flags"].get_value() == 0
        assert actual_ea_buffer2["ea_name_length"].get_value() == 5
        assert actual_ea_buffer2["ea_value_length"].get_value() == 19
        assert actual_ea_buffer2["ea_name"].get_value() == "Title\x00".encode("ascii")
        assert actual_ea_buffer2["ea_value"].get_value() == b"Jordan Borean Title"
        assert actual_ea_buffer2["padding"].get_value() == b""

        assert actual1["padding2"].get_value() == b"\x00" * 7

        assert len(actual2) == 32
        assert actual2["next"].get_value() == 32
        assert actual2["name_offset"].get_value() == 16
        assert actual2["name_length"].get_value() == 4
        assert actual2["reserved"].get_value() == 0
        assert actual2["data_offset"].get_value() == 24
        assert actual2["data_length"].get_value() == 8
        assert actual2["buffer_name"].get_value() == b"\x41\x6c\x53\x69"
        assert actual2["padding"].get_value() == b"\x00\x00\x00\x00"
        alloc_data = actual2["buffer_data"].get_value()
        alloc = SMB2CreateAllocationSize()
        alloc_data = alloc.unpack(alloc_data)
        assert alloc_data == b""
        assert alloc["allocation_size"].get_value() == 1024
        assert actual2["padding2"].get_value() == b""

        assert len(actual3) == 24
        assert actual3["next"].get_value() == 0
        assert actual3["name_offset"].get_value() == 16
        assert actual3["name_length"].get_value() == 4
        assert actual3["reserved"].get_value() == 0
        assert actual3["data_offset"].get_value() == 0
        assert actual3["data_length"].get_value() == 0
        assert actual3["buffer_name"].get_value() == b"\x51\x46\x69\x64"
        assert actual3["padding"].get_value() == b""
        assert actual3["buffer_data"].get_value() == b""
        assert actual3["padding2"].get_value() == b"\x00\x00\x00\x00"

    def test_get_context_data_known(self):
        message = SMB2CreateContextRequest()
        data = (
            b"\x00\x00\x00\x00"
            b"\x10\x00"
            b"\x04\x00"
            b"\x00\x00"
            b"\x18\x00"
            b"\x20\x00\x00\x00"
            b"\x51\x46\x69\x64"
            b"\x00\x00\x00\x00"
            b"\xed\x5a\x00\x00\x00\x00\x99\x00"
            b"\x30\x50\xd7\xd8\x04\x82\xff\xff"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        message.unpack(data)
        actual = message.get_context_data()
        assert isinstance(actual, SMB2CreateQueryOnDiskIDResponse)
        assert actual["disk_file_id"].get_value() == 43065671436753645
        assert actual["volume_id"].get_value() == 18446605556062310448
        assert actual["reserved"].get_value() == b"\x00" * 16

    def test_get_context_data_unknown(self):
        message = SMB2CreateContextRequest()
        data = (
            b"\x00\x00\x00\x00"
            b"\x10\x00"
            b"\x04\x00"
            b"\x00\x00"
            b"\x18\x00"
            b"\x04\x00\x00\x00"
            b"\x45\x78\x74\x41"
            b"\x00\x00\x00\x00"
            b"\x20\x00\x00\x00"
        )
        message.unpack(data)
        actual = message.get_context_data()
        assert actual == b"\x20\x00\x00\x00"


class TestSMB2CreateEABuffer:
    def test_create_message(self):
        msg1 = SMB2CreateEABuffer()
        msg1["ea_name"] = "Authors\x00".encode("ascii")
        msg1["ea_value"] = b"Jordan Borean"

        msg2 = SMB2CreateEABuffer()
        msg2["ea_name"] = "Title\x00".encode("ascii")
        msg2["ea_value"] = b"Jordan Borean Title"

        expected = (
            b"\x20\x00\x00\x00"
            b"\x00"
            b"\x07"
            b"\x0d\x00"
            b"\x41\x75\x74\x68\x6f\x72\x73\x00"
            b"\x4a\x6f\x72\x64\x61\x6e\x20\x42"
            b"\x6f\x72\x65\x61\x6e"
            b"\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x05"
            b"\x13\x00"
            b"\x54\x69\x74\x6c\x65\x00"
            b"\x4a\x6f\x72\x64\x61\x6e\x20\x42"
            b"\x6f\x72\x65\x61\x6e\x20\x54\x69"
            b"\x74\x6c\x65"
        )

        # size of msg1 won't have any padding as we haven't set the next offset
        assert len(msg1) == 29
        assert len(msg2) == 33

        # size of the padding changes in this argument as we add multiple
        # together
        actual = SMB2CreateEABuffer.pack_multiple([msg1, msg2])
        assert len(msg1) == 32
        assert len(msg2) == 33
        assert actual == expected

    def test_parse_message(self):
        actual1 = SMB2CreateEABuffer()
        actual2 = SMB2CreateEABuffer()
        data = (
            b"\x20\x00\x00\x00"
            b"\x00"
            b"\x07"
            b"\x0d\x00"
            b"\x41\x75\x74\x68\x6f\x72\x73\x00"
            b"\x4a\x6f\x72\x64\x61\x6e\x20\x42"
            b"\x6f\x72\x65\x61\x6e"
            b"\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x05"
            b"\x13\x00"
            b"\x54\x69\x74\x6c\x65\x00"
            b"\x4a\x6f\x72\x64\x61\x6e\x20\x42"
            b"\x6f\x72\x65\x61\x6e\x20\x54\x69"
            b"\x74\x6c\x65"
        )
        data = actual1.unpack(data)
        data = actual2.unpack(data)
        assert len(actual1) == 32
        assert actual1["next_entry_offset"].get_value() == 32
        assert actual1["flags"].get_value() == 0
        assert actual1["ea_name_length"].get_value() == 7
        assert actual1["ea_value_length"].get_value() == 13
        assert actual1["ea_name"].get_value() == "Authors\x00".encode("ascii")
        assert actual1["ea_value"].get_value() == b"Jordan Borean"
        assert actual1["padding"].get_value() == b"\x00\x00\x00"
        assert len(actual2) == 33
        assert actual2["next_entry_offset"].get_value() == 0
        assert actual2["flags"].get_value() == 0
        assert actual2["ea_name_length"].get_value() == 5
        assert actual2["ea_value_length"].get_value() == 19
        assert actual2["ea_name"].get_value() == "Title\x00".encode("ascii")
        assert actual2["ea_value"].get_value() == b"Jordan Borean Title"
        assert actual2["padding"].get_value() == b""


class TestSMB2CreateDurableHandleRequest:
    def test_create_message(self):
        message = SMB2CreateDurableHandleRequest()
        expected = b"\x00" * 16
        actual = message.pack()
        assert len(message) == 16
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CreateDurableHandleRequest()
        data = b"\x00" * 16
        data = actual.unpack(data)
        assert len(actual) == 16
        assert data == b""
        assert actual["durable_request"].get_value() == b"\x00" * 16


class TestSMB2CreateDurableHandleResponse:
    def test_create_message(self):
        message = SMB2CreateDurableHandleResponse()
        expected = b"\x00" * 8
        actual = message.pack()
        assert len(message) == 8
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CreateDurableHandleResponse()
        data = b"\x00" * 8
        data = actual.unpack(data)
        assert len(actual) == 8
        assert data == b""
        assert actual["reserved"].get_value() == 0


class TestSMB2CreateDurableHandleReconnect:
    def test_create_message(self):
        message = SMB2CreateDurableHandleReconnect()
        message["data"] = b"\xff" * 16
        expected = b"\xff" * 16
        actual = message.pack()
        assert len(message) == 16
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CreateDurableHandleReconnect()
        data = b"\xff" * 16
        data = actual.unpack(data)
        assert len(actual) == 16
        assert data == b""
        assert actual["data"].pack() == b"\xff" * 16


class TestSMB2CreateQueryMaximalAccessRequest:
    def test_create_message(self):
        message = SMB2CreateQueryMaximalAccessRequest()
        message["timestamp"] = datetime.fromtimestamp(0, timezone.utc)
        expected = b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
        actual = message.pack()
        assert len(message) == 8
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CreateQueryMaximalAccessRequest()
        data = b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
        data = actual.unpack(data)
        assert len(actual) == 8
        assert data == b""
        assert actual["timestamp"].get_value() == datetime.fromtimestamp(0, timezone.utc)


class TestSMB2CreateQueryMaximalAccessResponse:
    def test_create_message(self):
        message = SMB2CreateQueryMaximalAccessResponse()
        message["maximal_access"] = 2032127
        expected = b"\x00\x00\x00\x00" b"\xff\x01\x1f\x00"
        actual = message.pack()
        assert len(message) == 8
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CreateQueryMaximalAccessResponse()
        data = b"\x00\x00\x00\x00" b"\xff\x01\x1f\x00"
        data = actual.unpack(data)
        assert len(actual) == 8
        assert data == b""
        assert actual["query_status"].get_value() == NtStatus.STATUS_SUCCESS
        assert actual["maximal_access"].get_value() == 2032127


class TestSMB2CreateAllocationSize:
    def test_create_message(self):
        message = SMB2CreateAllocationSize()
        message["allocation_size"] = 1024
        expected = b"\x00\x04\x00\x00\x00\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 8
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CreateAllocationSize()
        data = b"\x00\x04\x00\x00\x00\x00\x00\x00"
        data = actual.unpack(data)
        assert len(actual) == 8
        assert data == b""
        assert actual["allocation_size"].get_value() == 1024


class TestSMB2CreateTimewarpToken:
    def test_create_message(self):
        message = SMB2CreateTimewarpToken()
        message["timestamp"] = datetime.fromtimestamp(0, timezone.utc)
        expected = b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
        actual = message.pack()
        assert len(message) == 8
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CreateTimewarpToken()
        data = b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
        data = actual.unpack(data)
        assert len(actual) == 8
        assert data == b""
        assert actual["timestamp"].get_value() == datetime.fromtimestamp(0, timezone.utc)


class TestSMB2CreateRequestLease:
    def test_create_message(self):
        message = SMB2CreateRequestLease()
        message["lease_key"] = b"\xff" * 16
        message["lease_state"].set_flag(LeaseState.SMB2_LEASE_HANDLE_CACHING)
        message["lease_duration"] = 10
        expected = (
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x02\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x0a\x00\x00\x00\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 32
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CreateRequestLease()
        data = (
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x02\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x0a\x00\x00\x00\x00\x00\x00\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 32
        assert data == b""
        assert actual["lease_key"].get_value() == b"\xff" * 16
        assert actual["lease_state"].get_value() == LeaseState.SMB2_LEASE_HANDLE_CACHING
        assert actual["lease_flags"].get_value() == 0
        assert actual["lease_duration"].get_value() == 10


class TestSMB2CreateResponseLease:
    def test_create_message(self):
        message = SMB2CreateResponseLease()
        message["lease_key"] = b"\xff" * 16
        message["lease_state"].set_flag(LeaseState.SMB2_LEASE_HANDLE_CACHING)
        message["lease_flags"].set_flag(LeaseResponseFlags.SMB2_LEASE_FLAG_BREAK_IN_PROGRESS)
        message["lease_duration"] = 12
        expected = (
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x02\x00\x00\x00"
            b"\x02\x00\x00\x00"
            b"\x0c\x00\x00\x00\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 32
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CreateResponseLease()
        data = (
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x02\x00\x00\x00"
            b"\x02\x00\x00\x00"
            b"\x0c\x00\x00\x00\x00\x00\x00\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 32
        assert data == b""
        assert actual["lease_key"].get_value() == b"\xff" * 16
        assert actual["lease_state"].get_value() == LeaseState.SMB2_LEASE_HANDLE_CACHING
        assert actual["lease_flags"].get_value() == LeaseResponseFlags.SMB2_LEASE_FLAG_BREAK_IN_PROGRESS
        assert actual["lease_duration"].get_value() == 12


class TestSMB2CreateQueryOnDiskIDResponse:
    def test_create_message(self):
        message = SMB2CreateQueryOnDiskIDResponse()
        message["disk_file_id"] = 43065671436753645
        message["volume_id"] = 18446605556062310448
        expected = (
            b"\xed\x5a\x00\x00\x00\x00\x99\x00"
            b"\x30\x50\xd7\xd8\x04\x82\xff\xff"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 32
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CreateQueryOnDiskIDResponse()
        data = (
            b"\xed\x5a\x00\x00\x00\x00\x99\x00"
            b"\x30\x50\xd7\xd8\x04\x82\xff\xff"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 32
        assert data == b""
        assert actual["disk_file_id"].get_value() == 43065671436753645
        assert actual["volume_id"].get_value() == 18446605556062310448
        assert actual["reserved"].get_value() == b"\x00" * 16


class TestSMB2CreateRequestLeaseV2:
    def test_create_message(self):
        message = SMB2CreateRequestLeaseV2()
        message["lease_key"] = b"\xff" * 16
        message["lease_state"] = LeaseState.SMB2_LEASE_READ_CACHING
        message["lease_flags"] = LeaseRequestFlags.SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET
        message["lease_duration"] = 10
        message["parent_lease_key"] = b"\xee" * 16
        message["epoch"] = b"\xdd" * 2
        expected = (
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x01\x00\x00\x00"
            b"\x04\x00\x00\x00"
            b"\x0a\x00\x00\x00\x00\x00\x00\x00"
            b"\xee\xee\xee\xee\xee\xee\xee\xee"
            b"\xee\xee\xee\xee\xee\xee\xee\xee"
            b"\xdd\xdd"
            b"\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 52
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CreateRequestLeaseV2()
        data = (
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x01\x00\x00\x00"
            b"\x04\x00\x00\x00"
            b"\x0a\x00\x00\x00\x00\x00\x00\x00"
            b"\xee\xee\xee\xee\xee\xee\xee\xee"
            b"\xee\xee\xee\xee\xee\xee\xee\xee"
            b"\xdd\xdd"
            b"\x00\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 52
        assert data == b""
        assert actual["lease_key"].get_value() == b"\xff" * 16
        assert actual["lease_state"].get_value() == LeaseState.SMB2_LEASE_READ_CACHING
        assert actual["lease_flags"].get_value() == LeaseRequestFlags.SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET
        assert actual["lease_duration"].get_value() == 10
        assert actual["parent_lease_key"].get_value() == b"\xee" * 16
        assert actual["epoch"].get_value() == b"\xdd" * 2
        assert actual["reserved"].get_value() == 0


class TestSMB2CreateResponseLeaseV2:
    def test_create_message(self):
        message = SMB2CreateResponseLeaseV2()
        message["lease_key"] = b"\xff" * 16
        message["lease_state"] = LeaseState.SMB2_LEASE_READ_CACHING
        message["flags"] = LeaseRequestFlags.SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET
        message["lease_duration"] = 10
        message["parent_lease_key"] = b"\xee" * 16
        message["epoch"] = 100
        expected = (
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x01\x00\x00\x00"
            b"\x04\x00\x00\x00"
            b"\x0a\x00\x00\x00\x00\x00\x00\x00"
            b"\xee\xee\xee\xee\xee\xee\xee\xee"
            b"\xee\xee\xee\xee\xee\xee\xee\xee"
            b"\x64\x00"
            b"\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 52
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CreateResponseLeaseV2()
        data = (
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x01\x00\x00\x00"
            b"\x04\x00\x00\x00"
            b"\x0a\x00\x00\x00\x00\x00\x00\x00"
            b"\xee\xee\xee\xee\xee\xee\xee\xee"
            b"\xee\xee\xee\xee\xee\xee\xee\xee"
            b"\x64\x00"
            b"\x00\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 52
        assert data == b""
        assert actual["lease_key"].get_value() == b"\xff" * 16
        assert actual["lease_state"].get_value() == LeaseState.SMB2_LEASE_READ_CACHING
        assert actual["flags"].get_value() == LeaseRequestFlags.SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET
        assert actual["lease_duration"].get_value() == 10
        assert actual["parent_lease_key"].get_value() == b"\xee" * 16
        assert actual["epoch"].get_value() == 100
        assert actual["reserved"].get_value() == 0


class TestSMB2CreateDurableHandleRequestV2:
    def test_create_message(self):
        message = SMB2CreateDurableHandleRequestV2()
        message["timeout"] = 100
        message["flags"] = DurableHandleFlags.SMB2_DHANDLE_FLAG_PERSISTENT
        message["create_guid"] = b"\xff" * 16
        expected = (
            b"\x64\x00\x00\x00"
            b"\x02\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
        )
        actual = message.pack()
        assert len(message) == 32
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CreateDurableHandleRequestV2()
        data = (
            b"\x64\x00\x00\x00"
            b"\x02\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
        )
        data = actual.unpack(data)
        assert len(actual) == 32
        assert data == b""
        assert actual["timeout"].get_value() == 100
        assert actual["flags"].get_value() == DurableHandleFlags.SMB2_DHANDLE_FLAG_PERSISTENT
        assert actual["reserved"].get_value() == 0
        assert actual["create_guid"].get_value() == uuid.UUID(bytes=b"\xff" * 16)


class TestSMB2CreateDurableHandleReconnectV2:
    def test_create_message(self):
        message = SMB2CreateDurableHandleReconnectV2()
        message["file_id"] = b"\xff" * 16
        message["create_guid"] = b"\xee" * 16
        message["flags"] = DurableHandleFlags.SMB2_DHANDLE_FLAG_PERSISTENT
        expected = (
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xee\xee\xee\xee\xee\xee\xee\xee"
            b"\xee\xee\xee\xee\xee\xee\xee\xee"
            b"\x02\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 36
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CreateDurableHandleReconnectV2()
        data = (
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xee\xee\xee\xee\xee\xee\xee\xee"
            b"\xee\xee\xee\xee\xee\xee\xee\xee"
            b"\x02\x00\x00\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 36
        assert data == b""
        assert actual["file_id"].pack() == b"\xff" * 16
        assert actual["create_guid"].get_value() == uuid.UUID(bytes=b"\xee" * 16)
        assert actual["flags"].get_value() == DurableHandleFlags.SMB2_DHANDLE_FLAG_PERSISTENT


class TestSMB2CreateDurableHandleResponseV2:
    def test_create_message(self):
        message = SMB2CreateDurableHandleResponseV2()
        message["timeout"] = 10
        expected = b"\x0a\x00\x00\x00" b"\x00\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 8
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CreateDurableHandleResponseV2()
        data = b"\x0a\x00\x00\x00" b"\x00\x00\x00\x00"
        data = actual.unpack(data)
        assert len(actual) == 8
        assert data == b""
        assert actual["timeout"].get_value() == 10
        assert actual["flags"].get_value() == 0


class TestSMB2CreateAppInstanceId:
    def test_create_message(self):
        message = SMB2CreateAppInstanceId()
        message["app_instance_id"] = b"\xff" * 16
        expected = b"\x14\x00" b"\x00\x00" b"\xff\xff\xff\xff\xff\xff\xff\xff" b"\xff\xff\xff\xff\xff\xff\xff\xff"
        actual = message.pack()
        assert len(message) == 20
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CreateAppInstanceId()
        data = b"\x14\x00" b"\x00\x00" b"\xff\xff\xff\xff\xff\xff\xff\xff" b"\xff\xff\xff\xff\xff\xff\xff\xff"
        data = actual.unpack(data)
        assert len(actual) == 20
        assert data == b""
        assert actual["structure_size"].get_value() == 20
        assert actual["reserved"].get_value() == 0
        assert actual["app_instance_id"].get_value() == b"\xff" * 16


class TestSMB2SVHDXOpenDeviceContextRequest:
    def test_create_message(self):
        message = SMB2SVHDXOpenDeviceContextRequest()
        message["initiator_id"] = b"\xff" * 16
        message["originator_flags"] = SVHDXOriginatorFlags.SVHDX_ORIGINATOR_VHDMP
        message["open_request_id"] = 5
        message["initiator_host_name"] = "hostname".encode("utf-16-le")
        expected = (
            b"\x01\x00\x00\x00"
            b"\x01"
            b"\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x04\x00\x00\x00"
            b"\x05\x00\x00\x00\x00\x00\x00\x00"
            b"\x10\x00"
            b"\x68\x00\x6f\x00\x73\x00\x74\x00"
            b"\x6e\x00\x61\x00\x6d\x00\x65\x00"
        )
        actual = message.pack()
        assert len(message) == 54
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2SVHDXOpenDeviceContextRequest()
        data = (
            b"\x01\x00\x00\x00"
            b"\x01"
            b"\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x04\x00\x00\x00"
            b"\x05\x00\x00\x00\x00\x00\x00\x00"
            b"\x10\x00"
            b"\x68\x00\x6f\x00\x73\x00\x74\x00"
            b"\x6e\x00\x61\x00\x6d\x00\x65\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 54
        assert data == b""
        assert actual["version"].get_value() == 1
        assert actual["has_initiator_id"].get_value()
        assert actual["reserved"].get_value() == b"\x00\x00\x00"
        assert actual["initiator_id"].get_value() == uuid.UUID(bytes=b"\xff" * 16)
        assert actual["originator_flags"].get_value() == SVHDXOriginatorFlags.SVHDX_ORIGINATOR_VHDMP
        assert actual["open_request_id"].get_value() == 5
        assert actual["initiator_host_name_length"].get_value() == 16
        assert actual["initiator_host_name"].get_value() == "hostname".encode("utf-16-le")


class TestSMB2SVHDXOpenDeviceContextResponse:
    def test_create_message(self):
        message = SMB2SVHDXOpenDeviceContextResponse()
        message["initiator_id"] = b"\xff" * 16
        message["open_request_id"] = 20
        message["initiator_host_name"] = "hostname".encode("utf-16-le")
        expected = (
            b"\x01\x00\x00\x00"
            b"\x01"
            b"\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x14\x00\x00\x00\x00\x00\x00\x00"
            b"\x10\x00"
            b"\x68\x00\x6f\x00\x73\x00\x74\x00"
            b"\x6e\x00\x61\x00\x6d\x00\x65\x00"
        )
        actual = message.pack()
        assert len(message) == 58
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2SVHDXOpenDeviceContextResponse()
        data = (
            b"\x01\x00\x00\x00"
            b"\x01"
            b"\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x14\x00\x00\x00\x00\x00\x00\x00"
            b"\x10\x00"
            b"\x68\x00\x6f\x00\x73\x00\x74\x00"
            b"\x6e\x00\x61\x00\x6d\x00\x65\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 58
        assert data == b""
        assert actual["version"].get_value() == 1
        assert actual["has_initiator_id"].get_value()
        assert actual["reserved"].get_value() == b"\x00\x00\x00"
        assert actual["initiator_id"].get_value() == uuid.UUID(bytes=b"\xff" * 16)
        assert actual["flags"].get_value() == 0
        assert actual["originator_flags"].get_value() == 0
        assert actual["open_request_id"].get_value() == 20
        assert actual["initiator_host_name_length"].get_value() == 16
        assert actual["initiator_host_name"].get_value() == "hostname".encode("utf-16-le")


class TestSMB2SVHDXOpenDeviceContextV2Request:
    def test_create_message(self):
        message = SMB2SVHDXOpenDeviceContextV2Request()
        message["initiator_id"] = b"\xff" * 16
        message["originator_flags"] = SVHDXOriginatorFlags.SVHDX_ORIGINATOR_VHDMP
        message["open_request_id"] = 5
        message["initiator_host_name"] = "hostname".encode("utf-16-le")
        expected = (
            b"\x02\x00\x00\x00"
            b"\x01"
            b"\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x04\x00\x00\x00"
            b"\x05\x00\x00\x00\x00\x00\x00\x00"
            b"\x10\x00"
            b"\x68\x00\x6f\x00\x73\x00\x74\x00"
            b"\x6e\x00\x61\x00\x6d\x00\x65\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 78
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2SVHDXOpenDeviceContextV2Request()
        data = (
            b"\x02\x00\x00\x00"
            b"\x01"
            b"\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x04\x00\x00\x00"
            b"\x05\x00\x00\x00\x00\x00\x00\x00"
            b"\x10\x00"
            b"\x68\x00\x6f\x00\x73\x00\x74\x00"
            b"\x6e\x00\x61\x00\x6d\x00\x65\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 78
        assert data == b""
        assert actual["version"].get_value() == 2
        assert actual["has_initiator_id"].get_value()
        assert actual["reserved"].get_value() == b"\x00\x00\x00"
        assert actual["initiator_id"].get_value() == uuid.UUID(bytes=b"\xff" * 16)
        assert actual["originator_flags"].get_value() == SVHDXOriginatorFlags.SVHDX_ORIGINATOR_VHDMP
        assert actual["open_request_id"].get_value() == 5
        assert actual["initiator_host_name_length"].get_value() == 16
        assert actual["initiator_host_name"].get_value() == "hostname".encode("utf-16-le")
        assert actual["virtual_disk_properties_initialized"].get_value() == 0
        assert actual["server_service_version"].get_value() == 0
        assert actual["virtual_sector_size"].get_value() == 0
        assert actual["physical_sector_size"].get_value() == 0
        assert actual["virtual_size"].get_value() == 0


class TestSMB2SVHDXOpenDeviceContextV2Response:
    def test_create_message(self):
        message = SMB2SVHDXOpenDeviceContextV2Response()
        message["initiator_id"] = b"\xff" * 16
        message["open_request_id"] = 20
        message["initiator_host_name"] = "hostname".encode("utf-16-le")
        expected = (
            b"\x02\x00\x00\x00"
            b"\x01"
            b"\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x14\x00\x00\x00\x00\x00\x00\x00"
            b"\x10\x00"
            b"\x68\x00\x6f\x00\x73\x00\x74\x00"
            b"\x6e\x00\x61\x00\x6d\x00\x65\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 82
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2SVHDXOpenDeviceContextV2Response()
        data = (
            b"\x02\x00\x00\x00"
            b"\x01"
            b"\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x14\x00\x00\x00\x00\x00\x00\x00"
            b"\x10\x00"
            b"\x68\x00\x6f\x00\x73\x00\x74\x00"
            b"\x6e\x00\x61\x00\x6d\x00\x65\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 82
        assert data == b""
        assert actual["version"].get_value() == 2
        assert actual["has_initiator_id"].get_value()
        assert actual["reserved"].get_value() == b"\x00\x00\x00"
        assert actual["initiator_id"].get_value() == uuid.UUID(bytes=b"\xff" * 16)
        assert actual["flags"].get_value() == 0
        assert actual["originator_flags"].get_value() == 0
        assert actual["open_request_id"].get_value() == 20
        assert actual["initiator_host_name_length"].get_value() == 16
        assert actual["initiator_host_name"].get_value() == "hostname".encode("utf-16-le")
        assert actual["virtual_disk_properties_initialized"].get_value() == 0
        assert actual["server_service_version"].get_value() == 0
        assert actual["virtual_sector_size"].get_value() == 0
        assert actual["physical_sector_size"].get_value() == 0
        assert actual["virtual_size"].get_value() == 0


class TestSMB2CreateAppInstanceVersion:
    def test_create_message(self):
        message = SMB2CreateAppInstanceVersion()
        message["app_instance_version_high"] = 10
        message["app_instance_version_low"] = 10
        expected = (
            b"\x18\x00"
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x0a\x00\x00\x00\x00\x00\x00\x00"
            b"\x0a\x00\x00\x00\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 24
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CreateAppInstanceVersion()
        data = (
            b"\x18\x00"
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x0a\x00\x00\x00\x00\x00\x00\x00"
            b"\x0a\x00\x00\x00\x00\x00\x00\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 24
        assert data == b""
        assert actual["structure_size"].get_value() == 24
        assert actual["reserved"].get_value() == 0
        assert actual["padding"].get_value() == 0
        assert actual["app_instance_version_high"].get_value() == 10
        assert actual["app_instance_version_low"].get_value() == 10
