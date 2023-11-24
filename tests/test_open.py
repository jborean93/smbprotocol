# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os
import time
import uuid
from datetime import datetime, timezone

import pytest

from smbprotocol import Dialects
from smbprotocol.connection import Connection
from smbprotocol.create_contexts import (
    CreateContextName,
    SMB2CreateAllocationSize,
    SMB2CreateContextRequest,
    SMB2CreateQueryMaximalAccessRequest,
    SMB2CreateQueryMaximalAccessResponse,
    SMB2CreateQueryOnDiskIDResponse,
    SMB2CreateRequestLease,
    SMB2CreateRequestLeaseV2,
    SMB2CreateResponseLease,
    SMB2CreateResponseLeaseV2,
    SMB2CreateTimewarpToken,
)
from smbprotocol.exceptions import EndOfFile, SMBException, SMBUnsupportedFeature
from smbprotocol.file_info import (
    FileAttributes,
    FileEndOfFileInformation,
    FileFullEaInformation,
    FileInformationClass,
    FileNamesInformation,
    FileStandardInformation,
)
from smbprotocol.open import (
    CloseFlags,
    CreateAction,
    CreateDisposition,
    CreateOptions,
    DirectoryAccessMask,
    FileFlags,
    FilePipePrinterAccessMask,
    ImpersonationLevel,
    InfoType,
    Open,
    ReadWriteChannel,
    RequestedOplockLevel,
    ShareAccess,
    SMB2CloseRequest,
    SMB2CloseResponse,
    SMB2CreateRequest,
    SMB2CreateResponse,
    SMB2FlushRequest,
    SMB2FlushResponse,
    SMB2QueryDirectoryRequest,
    SMB2QueryDirectoryResponse,
    SMB2QueryInfoRequest,
    SMB2QueryInfoResponse,
    SMB2ReadRequest,
    SMB2ReadResponse,
    SMB2SetInfoRequest,
    SMB2SetInfoResponse,
    SMB2WriteRequest,
    SMB2WriteResponse,
)
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect


class TestSMB2CreateRequest:
    def test_create_message(self):
        timewarp_token = SMB2CreateTimewarpToken()
        timewarp_token["timestamp"] = datetime.fromtimestamp(0, timezone.utc)
        timewarp_context = SMB2CreateContextRequest()
        timewarp_context["buffer_name"] = CreateContextName.SMB2_CREATE_TIMEWARP_TOKEN
        timewarp_context["buffer_data"] = timewarp_token

        message = SMB2CreateRequest()
        message["impersonation_level"] = ImpersonationLevel.Impersonation
        message["desired_access"] = FilePipePrinterAccessMask.GENERIC_READ
        message["file_attributes"] = FileAttributes.FILE_ATTRIBUTE_NORMAL
        message["share_access"] = ShareAccess.FILE_SHARE_READ
        message["create_disposition"] = CreateDisposition.FILE_OPEN
        message["create_options"] = CreateOptions.FILE_NON_DIRECTORY_FILE
        message["buffer_path"] = r"\\server\share".encode("utf-16-le")
        message["buffer_contexts"] = [timewarp_context]
        expected = (
            b"\x39\x00"
            b"\x00"
            b"\x00"
            b"\x02\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x80"
            b"\x80\x00\x00\x00"
            b"\x01\x00\x00\x00"
            b"\x01\x00\x00\x00"
            b"\x40\x00\x00\x00"
            b"\x78\x00"
            b"\x1c\x00"
            b"\x98\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x5c\x00\x5c\x00\x73\x00\x65\x00"
            b"\x72\x00\x76\x00\x65\x00\x72\x00"
            b"\x5C\x00\x73\x00\x68\x00\x61\x00"
            b"\x72\x00\x65\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x10\x00"
            b"\x04\x00"
            b"\x00\x00"
            b"\x18\x00"
            b"\x08\x00\x00\x00"
            b"\x54\x57\x72\x70"
            b"\x00\x00\x00\x00"
            b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
        )
        actual = message.pack()
        assert len(message) == 120
        assert actual == expected

    def test_create_message_no_contexts(self):
        message = SMB2CreateRequest()
        message["impersonation_level"] = ImpersonationLevel.Impersonation
        message["desired_access"] = FilePipePrinterAccessMask.GENERIC_READ
        message["file_attributes"] = FileAttributes.FILE_ATTRIBUTE_NORMAL
        message["share_access"] = ShareAccess.FILE_SHARE_READ
        message["create_disposition"] = CreateDisposition.FILE_OPEN
        message["create_options"] = CreateOptions.FILE_NON_DIRECTORY_FILE
        message["buffer_path"] = r"\\server\share".encode("utf-16-le")
        expected = (
            b"\x39\x00"
            b"\x00"
            b"\x00"
            b"\x02\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x80"
            b"\x80\x00\x00\x00"
            b"\x01\x00\x00\x00"
            b"\x01\x00\x00\x00"
            b"\x40\x00\x00\x00"
            b"\x78\x00"
            b"\x1c\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x5c\x00\x5c\x00\x73\x00\x65\x00"
            b"\x72\x00\x76\x00\x65\x00\x72\x00"
            b"\x5C\x00\x73\x00\x68\x00\x61\x00"
            b"\x72\x00\x65\x00"
        )
        actual = message.pack()
        assert len(message) == 84
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CreateRequest()
        data = (
            b"\x39\x00"
            b"\x00"
            b"\x00"
            b"\x02\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x80"
            b"\x80\x00\x00\x00"
            b"\x01\x00\x00\x00"
            b"\x01\x00\x00\x00"
            b"\x40\x00\x00\x00"
            b"\x78\x00"
            b"\x1c\x00"
            b"\x98\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x5c\x00\x5c\x00\x73\x00\x65\x00"
            b"\x72\x00\x76\x00\x65\x00\x72\x00"
            b"\x5C\x00\x73\x00\x68\x00\x61\x00"
            b"\x72\x00\x65\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x10\x00"
            b"\x04\x00"
            b"\x00\x00"
            b"\x18\x00"
            b"\x08\x00\x00\x00"
            b"\x54\x57\x72\x70"
            b"\x00\x00\x00\x00"
            b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
        )
        data = actual.unpack(data)
        assert len(actual) == 120
        assert data == b""
        assert actual["structure_size"].get_value() == 57
        assert actual["security_flags"].get_value() == 0
        assert actual["requested_oplock_level"].get_value() == 0
        assert actual["impersonation_level"].get_value() == ImpersonationLevel.Impersonation
        assert actual["smb_create_flags"].get_value() == 0
        assert actual["reserved"].get_value() == 0
        assert actual["desired_access"].get_value() == FilePipePrinterAccessMask.GENERIC_READ
        assert actual["file_attributes"].get_value() == FileAttributes.FILE_ATTRIBUTE_NORMAL
        assert actual["share_access"].get_value() == ShareAccess.FILE_SHARE_READ
        assert actual["create_disposition"].get_value() == CreateDisposition.FILE_OPEN
        assert actual["create_options"].get_value() == CreateOptions.FILE_NON_DIRECTORY_FILE
        assert actual["name_offset"].get_value() == 120
        assert actual["name_length"].get_value() == 28
        assert actual["create_contexts_offset"].get_value() == 152
        assert actual["create_contexts_length"].get_value() == 32
        assert actual["buffer_path"].get_value() == r"\\server\share".encode("utf-16-le")
        assert actual["padding"].get_value() == b"\x00\x00\x00\x00"

        contexts = actual["buffer_contexts"].get_value()
        assert isinstance(contexts, list)
        timewarp_context = contexts[0]
        assert timewarp_context["next"].get_value() == 0
        assert timewarp_context["name_offset"].get_value() == 16
        assert timewarp_context["name_length"].get_value() == 4
        assert timewarp_context["reserved"].get_value() == 0
        assert timewarp_context["data_offset"].get_value() == 24
        assert timewarp_context["data_length"].get_value() == 8
        assert timewarp_context["buffer_name"].get_value() == CreateContextName.SMB2_CREATE_TIMEWARP_TOKEN
        assert timewarp_context["padding"].get_value() == b"\x00\x00\x00\x00"
        assert timewarp_context["buffer_data"].get_value() == b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
        assert timewarp_context["padding2"].get_value() == b""

    def test_parse_message_no_contexts(self):
        actual = SMB2CreateRequest()
        data = (
            b"\x39\x00"
            b"\x00"
            b"\x00"
            b"\x02\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x80"
            b"\x80\x00\x00\x00"
            b"\x01\x00\x00\x00"
            b"\x01\x00\x00\x00"
            b"\x40\x00\x00\x00"
            b"\x78\x00"
            b"\x1c\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x5c\x00\x5c\x00\x73\x00\x65\x00"
            b"\x72\x00\x76\x00\x65\x00\x72\x00"
            b"\x5C\x00\x73\x00\x68\x00\x61\x00"
            b"\x72\x00\x65\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 84
        assert data == b""
        assert actual["structure_size"].get_value() == 57
        assert actual["security_flags"].get_value() == 0
        assert actual["requested_oplock_level"].get_value() == 0
        assert actual["impersonation_level"].get_value() == ImpersonationLevel.Impersonation
        assert actual["smb_create_flags"].get_value() == 0
        assert actual["reserved"].get_value() == 0
        assert actual["desired_access"].get_value() == FilePipePrinterAccessMask.GENERIC_READ
        assert actual["file_attributes"].get_value() == FileAttributes.FILE_ATTRIBUTE_NORMAL
        assert actual["share_access"].get_value() == ShareAccess.FILE_SHARE_READ
        assert actual["create_disposition"].get_value() == CreateDisposition.FILE_OPEN
        assert actual["create_options"].get_value() == CreateOptions.FILE_NON_DIRECTORY_FILE
        assert actual["name_offset"].get_value() == 120
        assert actual["name_length"].get_value() == 28
        assert actual["create_contexts_offset"].get_value() == 0
        assert actual["create_contexts_length"].get_value() == 0
        assert actual["buffer_path"].get_value() == r"\\server\share".encode("utf-16-le")
        assert actual["padding"].get_value() == b""
        assert actual["buffer_contexts"].get_value() == []


class TestSMB2CreateResponse:
    def test_create_message(self):
        message = SMB2CreateResponse()
        message["flag"] = FileFlags.SMB2_CREATE_FLAG_REPARSEPOINT
        message["create_action"] = CreateAction.FILE_CREATED
        message["creation_time"] = datetime.fromtimestamp(1024, timezone.utc)
        message["last_access_time"] = datetime.fromtimestamp(2048, timezone.utc)
        message["last_write_time"] = datetime.fromtimestamp(3072, timezone.utc)
        message["change_time"] = datetime.fromtimestamp(4096, timezone.utc)
        message["allocation_size"] = 10
        message["end_of_file"] = 20
        message["file_attributes"] = FileAttributes.FILE_ATTRIBUTE_ARCHIVE
        message["file_id"] = b"\xff" * 16

        timewarp_token = SMB2CreateTimewarpToken()
        timewarp_token["timestamp"] = datetime.fromtimestamp(0, timezone.utc)
        timewarp_context = SMB2CreateContextRequest()
        timewarp_context["buffer_name"] = CreateContextName.SMB2_CREATE_TIMEWARP_TOKEN
        timewarp_context["buffer_data"] = timewarp_token
        message["buffer"] = [timewarp_context]
        expected = (
            b"\x59\x00"
            b"\x00"
            b"\x01"
            b"\x02\x00\x00\x00"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\xf2\x99\xe3\xb1\x9d\x01"
            b"\x00\x80\x4c\xfc\xe5\xb1\x9d\x01"
            b"\x00\x80\xa6\x5e\xe8\xb1\x9d\x01"
            b"\x0a\x00\x00\x00\x00\x00\x00\x00"
            b"\x14\x00\x00\x00\x00\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x98\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x10\x00"
            b"\x04\x00"
            b"\x00\x00"
            b"\x18\x00"
            b"\x08\x00\x00\x00"
            b"\x54\x57\x72\x70"
            b"\x00\x00\x00\x00"
            b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
        )
        actual = message.pack()
        assert len(message) == 120
        assert actual == expected

    def test_create_message_no_contexts(self):
        message = SMB2CreateResponse()
        message["flag"] = FileFlags.SMB2_CREATE_FLAG_REPARSEPOINT
        message["create_action"] = CreateAction.FILE_CREATED
        message["creation_time"] = datetime.fromtimestamp(1024, timezone.utc)
        message["last_access_time"] = datetime.fromtimestamp(2048, timezone.utc)
        message["last_write_time"] = datetime.fromtimestamp(3072, timezone.utc)
        message["change_time"] = datetime.fromtimestamp(4096, timezone.utc)
        message["allocation_size"] = 10
        message["end_of_file"] = 20
        message["file_attributes"] = FileAttributes.FILE_ATTRIBUTE_ARCHIVE
        message["file_id"] = b"\xff" * 16
        expected = (
            b"\x59\x00"
            b"\x00"
            b"\x01"
            b"\x02\x00\x00\x00"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\xf2\x99\xe3\xb1\x9d\x01"
            b"\x00\x80\x4c\xfc\xe5\xb1\x9d\x01"
            b"\x00\x80\xa6\x5e\xe8\xb1\x9d\x01"
            b"\x0a\x00\x00\x00\x00\x00\x00\x00"
            b"\x14\x00\x00\x00\x00\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 88
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CreateResponse()
        data = (
            b"\x59\x00"
            b"\x00"
            b"\x01"
            b"\x02\x00\x00\x00"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\xf2\x99\xe3\xb1\x9d\x01"
            b"\x00\x80\x4c\xfc\xe5\xb1\x9d\x01"
            b"\x00\x80\xa6\x5e\xe8\xb1\x9d\x01"
            b"\x0a\x00\x00\x00\x00\x00\x00\x00"
            b"\x14\x00\x00\x00\x00\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x98\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x10\x00"
            b"\x04\x00"
            b"\x00\x00"
            b"\x18\x00"
            b"\x08\x00\x00\x00"
            b"\x54\x57\x72\x70"
            b"\x00\x00\x00\x00"
            b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
        )
        data = actual.unpack(data)
        assert len(actual) == 120
        assert data == b""
        assert actual["structure_size"].get_value() == 89
        assert actual["oplock_level"].get_value() == 0
        assert actual["flag"].get_value() == FileFlags.SMB2_CREATE_FLAG_REPARSEPOINT
        assert actual["create_action"].get_value() == CreateAction.FILE_CREATED
        assert actual["creation_time"].get_value() == datetime.fromtimestamp(1024, timezone.utc)
        assert actual["last_access_time"].get_value() == datetime.fromtimestamp(2048, timezone.utc)
        assert actual["last_write_time"].get_value() == datetime.fromtimestamp(3072, timezone.utc)
        assert actual["change_time"].get_value() == datetime.fromtimestamp(4096, timezone.utc)
        assert actual["allocation_size"].get_value() == 10
        assert actual["end_of_file"].get_value() == 20
        assert actual["file_attributes"].get_value() == FileAttributes.FILE_ATTRIBUTE_ARCHIVE
        assert actual["reserved2"].get_value() == 0
        assert actual["file_id"].pack() == b"\xff" * 16
        assert actual["create_contexts_offset"].get_value() == 152
        assert actual["create_contexts_length"].get_value() == 32

        contexts = actual["buffer"].get_value()
        assert isinstance(contexts, list)
        timewarp_context = contexts[0]
        assert timewarp_context["next"].get_value() == 0
        assert timewarp_context["name_offset"].get_value() == 16
        assert timewarp_context["name_length"].get_value() == 4
        assert timewarp_context["reserved"].get_value() == 0
        assert timewarp_context["data_offset"].get_value() == 24
        assert timewarp_context["data_length"].get_value() == 8
        assert timewarp_context["buffer_name"].get_value() == CreateContextName.SMB2_CREATE_TIMEWARP_TOKEN
        assert timewarp_context["padding"].get_value() == b"\x00\x00\x00\x00"
        assert timewarp_context["buffer_data"].get_value() == b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
        assert timewarp_context["padding2"].get_value() == b""

    def test_parse_message_no_contexts(self):
        actual = SMB2CreateResponse()
        data = (
            b"\x59\x00"
            b"\x00"
            b"\x01"
            b"\x02\x00\x00\x00"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\xf2\x99\xe3\xb1\x9d\x01"
            b"\x00\x80\x4c\xfc\xe5\xb1\x9d\x01"
            b"\x00\x80\xa6\x5e\xe8\xb1\x9d\x01"
            b"\x0a\x00\x00\x00\x00\x00\x00\x00"
            b"\x14\x00\x00\x00\x00\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 88
        assert data == b""
        assert actual["structure_size"].get_value() == 89
        assert actual["oplock_level"].get_value() == 0
        assert actual["flag"].get_value() == FileFlags.SMB2_CREATE_FLAG_REPARSEPOINT
        assert actual["create_action"].get_value() == CreateAction.FILE_CREATED
        assert actual["creation_time"].get_value() == datetime.fromtimestamp(1024, timezone.utc)
        assert actual["last_access_time"].get_value() == datetime.fromtimestamp(2048, timezone.utc)
        assert actual["last_write_time"].get_value() == datetime.fromtimestamp(3072, timezone.utc)
        assert actual["change_time"].get_value() == datetime.fromtimestamp(4096, timezone.utc)
        assert actual["allocation_size"].get_value() == 10
        assert actual["end_of_file"].get_value() == 20
        assert actual["file_attributes"].get_value() == FileAttributes.FILE_ATTRIBUTE_ARCHIVE
        assert actual["reserved2"].get_value() == 0
        assert actual["file_id"].pack() == b"\xff" * 16
        assert actual["create_contexts_offset"].get_value() == 0
        assert actual["create_contexts_length"].get_value() == 0
        assert actual["buffer"].get_value() == []


class TestSMB2CloseRequest:
    def test_create_message(self):
        message = SMB2CloseRequest()
        message["flags"].set_flag(CloseFlags.SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB)
        message["file_id"] = b"\xff" * 16
        expected = (
            b"\x18\x00"
            b"\x01\x00"
            b"\x00\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
        )
        actual = message.pack()
        assert len(actual) == 24
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CloseRequest()
        data = (
            b"\x18\x00"
            b"\x01\x00"
            b"\x00\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
        )
        actual.unpack(data)
        assert len(actual) == 24
        assert actual["structure_size"].get_value() == 24
        assert actual["flags"].get_value() == CloseFlags.SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB
        assert actual["reserved"].get_value() == 0
        assert actual["file_id"].get_value() == b"\xff" * 16


class TestSMB2CloseResponse:
    def test_create_message(self):
        message = SMB2CloseResponse()
        message["creation_time"] = datetime.fromtimestamp(0, timezone.utc)
        message["last_access_time"] = datetime.fromtimestamp(0, timezone.utc)
        message["last_write_time"] = datetime.fromtimestamp(0, timezone.utc)
        message["change_time"] = datetime.fromtimestamp(0, timezone.utc)
        expected = (
            b"\x3c\x00"
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x80\x3E\xD5\xDE\xB1\x9D\x01"
            b"\x00\x80\x3E\xD5\xDE\xB1\x9D\x01"
            b"\x00\x80\x3E\xD5\xDE\xB1\x9D\x01"
            b"\x00\x80\x3E\xD5\xDE\xB1\x9D\x01"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(actual) == 60
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CloseResponse()
        data = (
            b"\x3c\x00"
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x80\x3E\xD5\xDE\xB1\x9D\x01"
            b"\x00\x80\x3E\xD5\xDE\xB1\x9D\x01"
            b"\x00\x80\x3E\xD5\xDE\xB1\x9D\x01"
            b"\x00\x80\x3E\xD5\xDE\xB1\x9D\x01"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
        )
        actual.unpack(data)
        assert len(actual) == 60
        assert actual["structure_size"].get_value() == 60
        assert actual["flags"].get_value() == 0
        assert actual["reserved"].get_value() == 0
        assert actual["creation_time"].get_value() == datetime.fromtimestamp(0, timezone.utc)
        assert actual["last_access_time"].get_value() == datetime.fromtimestamp(0, timezone.utc)
        assert actual["last_write_time"].get_value() == datetime.fromtimestamp(0, timezone.utc)
        assert actual["change_time"].get_value() == datetime.fromtimestamp(0, timezone.utc)
        assert actual["allocation_size"].get_value() == 0
        assert actual["end_of_file"].get_value() == 0
        assert actual["file_attributes"].get_value() == 0


class TestSMB2FlushRequest:
    def test_create_message(self):
        message = SMB2FlushRequest()
        message["file_id"] = b"\xff" * 16
        expected = (
            b"\x18\x00"
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
        )
        actual = message.pack()
        assert len(message) == 24
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2FlushRequest()
        data = (
            b"\x18\x00"
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
        )
        actual.unpack(data)
        assert len(actual) == 24
        assert actual["structure_size"].get_value() == 24
        assert actual["reserved1"].get_value() == 0
        assert actual["reserved2"].get_value() == 0
        assert actual["file_id"].pack() == b"\xff" * 16


class TestSMB2FlushResponse:
    def test_create_message(self):
        message = SMB2FlushResponse()
        expected = b"\x04\x00" b"\x00\x00"
        actual = message.pack()
        assert len(message) == 4
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2FlushResponse()
        data = b"\x04\x00" b"\x00\x00"
        actual.unpack(data)
        assert len(actual) == 4
        assert actual["structure_size"].get_value() == 4
        assert actual["reserved"].get_value() == 0


class TestSMB2ReadRequest:
    def test_create_message(self):
        message = SMB2ReadRequest()
        message["padding"] = b"\x50"
        message["length"] = 1024
        message["offset"] = 0
        message["file_id"] = b"\xff" * 16
        message["remaining_bytes"] = 0
        expected = (
            b"\x31\x00"
            b"\x50"
            b"\x00"
            b"\x00\x04\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00"
            b"\x00\x00"
            b"\x00"
        )
        actual = message.pack()
        assert len(message) == 49
        assert actual == expected

    def test_create_message_channel_info(self):
        message = SMB2ReadRequest()
        message["padding"] = b"\x50"
        message["length"] = 1024
        message["offset"] = 0
        message["file_id"] = b"\xff" * 16
        message["channel"].set_flag(ReadWriteChannel.SMB2_CHANNEL_RDMA_V1)
        message["remaining_bytes"] = 0
        message["buffer"] = b"\x00" * 16
        expected = (
            b"\x31\x00"
            b"\x50"
            b"\x00"
            b"\x00\x04\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x00\x00\x00\x00"
            b"\x01\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x70\x00"
            b"\x10\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 64
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2ReadRequest()
        data = (
            b"\x31\x00"
            b"\x50"
            b"\x00"
            b"\x00\x04\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00"
            b"\x00\x00"
            b"\x00"
        )
        actual.unpack(data)
        assert len(actual) == 49
        assert actual["structure_size"].get_value() == 49
        assert actual["padding"].get_value() == 80
        assert actual["flags"].get_value() == 0
        assert actual["length"].get_value() == 1024
        assert actual["offset"].get_value() == 0
        assert actual["file_id"].pack() == b"\xff" * 16
        assert actual["minimum_count"].get_value() == 0
        assert actual["channel"].get_value() == 0
        assert actual["remaining_bytes"].get_value() == 0
        assert actual["read_channel_info_offset"].get_value() == 0
        assert actual["read_channel_info_length"].get_value() == 0
        assert actual["buffer"].get_value() == b"\x00"

    def test_parse_message_channel_info(self):
        actual = SMB2ReadRequest()
        data = (
            b"\x31\x00"
            b"\x50"
            b"\x00"
            b"\x00\x04\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x00\x00\x00\x00"
            b"\x01\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x70\x00"
            b"\x10\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
        )
        actual.unpack(data)
        assert len(actual) == 64
        assert actual["structure_size"].get_value() == 49
        assert actual["padding"].get_value() == 80
        assert actual["flags"].get_value() == 0
        assert actual["length"].get_value() == 1024
        assert actual["offset"].get_value() == 0
        assert actual["file_id"].pack() == b"\xff" * 16
        assert actual["minimum_count"].get_value() == 0
        assert actual["channel"].get_value() == ReadWriteChannel.SMB2_CHANNEL_RDMA_V1
        assert actual["remaining_bytes"].get_value() == 0
        assert actual["read_channel_info_offset"].get_value() == 112
        assert actual["read_channel_info_length"].get_value() == 16
        assert actual["buffer"].get_value() == b"\x00" * 16


class TestSMB2ReadResponse:
    def test_create_message(self):
        message = SMB2ReadResponse()
        message["data_offset"] = 80
        message["data_length"] = 4
        message["buffer"] = b"\x01\x02\x03\x04"
        expected = (
            b"\x11\x00" b"\x50" b"\x00" b"\x04\x00\x00\x00" b"\x00\x00\x00\x00" b"\x00\x00\x00\x00" b"\x01\x02\x03\x04"
        )
        actual = message.pack()
        assert len(message) == 20
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2ReadResponse()
        data = (
            b"\x11\x00" b"\x50" b"\x00" b"\x04\x00\x00\x00" b"\x00\x00\x00\x00" b"\x00\x00\x00\x00" b"\x01\x02\x03\x04"
        )
        actual.unpack(data)
        assert len(actual) == 20
        assert actual["structure_size"].get_value() == 17
        assert actual["data_offset"].get_value() == 80
        assert actual["reserved"].get_value() == 0
        assert actual["data_length"].get_value() == 4
        assert actual["data_remaining"].get_value() == 0
        assert actual["reserved2"].get_value() == 0
        assert actual["buffer"].get_value() == b"\x01\x02\x03\x04"


class TestSMB2WriteRequest:
    def test_create_message(self):
        message = SMB2WriteRequest()
        message["offset"] = 131072
        message["file_id"] = b"\xff" * 16
        message["channel"].set_flag(ReadWriteChannel.SMB2_CHANNEL_NONE)
        message["remaining_bytes"] = 0
        message["buffer"] = b"\x01\x02\x03\x04"
        expected = (
            b"\x31\x00"
            b"\x70\x00"
            b"\x04\x00\x00\x00"
            b"\x00\x00\x02\x00\x00\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00"
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x01\x02\x03\x04"
        )
        actual = message.pack()
        assert len(message) == 52
        assert actual == expected

    def test_create_message_channel_info(self):
        message = SMB2WriteRequest()
        message["offset"] = 131072
        message["file_id"] = b"\xff" * 16
        message["channel"].set_flag(ReadWriteChannel.SMB2_CHANNEL_RDMA_V1)
        message["remaining_bytes"] = 0
        message["buffer"] = b"\x01\x02\x03\x04"
        message["buffer_channel_info"] = b"\x00" * 16
        expected = (
            b"\x31\x00"
            b"\x70\x00"
            b"\x04\x00\x00\x00"
            b"\x00\x00\x02\x00\x00\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x01\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x74\x00"
            b"\x10\x00"
            b"\x00\x00\x00\x00"
            b"\x01\x02\x03\x04"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 68
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2WriteRequest()
        data = (
            b"\x31\x00"
            b"\x70\x00"
            b"\x04\x00\x00\x00"
            b"\x00\x00\x02\x00\x00\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00"
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x01\x02\x03\x04"
        )
        actual.unpack(data)
        assert len(actual) == 52
        assert actual["structure_size"].get_value() == 49
        assert actual["data_offset"].get_value() == 112
        assert actual["length"].get_value() == 4
        assert actual["offset"].get_value() == 131072
        assert actual["file_id"].pack() == b"\xff" * 16
        assert actual["channel"].get_value() == 0
        assert actual["remaining_bytes"].get_value() == 0
        assert actual["write_channel_info_offset"].get_value() == 0
        assert actual["write_channel_info_length"].get_value() == 0
        assert actual["flags"].get_value() == 0
        assert actual["buffer"].get_value() == b"\x01\x02\x03\x04"
        assert actual["buffer_channel_info"].get_value() == b""

    def test_parse_message_channel_info(self):
        actual = SMB2WriteRequest()
        data = (
            b"\x31\x00"
            b"\x70\x00"
            b"\x04\x00\x00\x00"
            b"\x00\x00\x02\x00\x00\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x74\x00"
            b"\x10\x00"
            b"\x00\x00\x00\x00"
            b"\x01\x02\x03\x04"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
        )
        actual.unpack(data)
        assert len(actual) == 68
        assert actual["structure_size"].get_value() == 49
        assert actual["data_offset"].get_value() == 112
        assert actual["length"].get_value() == 4
        assert actual["offset"].get_value() == 131072
        assert actual["file_id"].pack() == b"\xff" * 16
        assert actual["channel"].get_value() == 0
        assert actual["remaining_bytes"].get_value() == 0
        assert actual["write_channel_info_offset"].get_value() == 116
        assert actual["write_channel_info_length"].get_value() == 16
        assert actual["flags"].get_value() == 0
        assert actual["buffer"].get_value() == b"\x01\x02\x03\x04"
        assert actual["buffer_channel_info"].get_value() == b"\x00" * 16


class TestSMB2WriteResponse:
    def test_create_message(self):
        message = SMB2WriteResponse()
        message["count"] = 58040
        expected = b"\x11\x00" b"\x00\x00" b"\xb8\xe2\x00\x00" b"\x00\x00\x00\x00" b"\x00\x00" b"\x00\x00"
        actual = message.pack()
        assert len(message) == 16
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2WriteResponse()
        data = b"\x11\x00" b"\x00\x00" b"\xb8\xe2\x00\x00" b"\x00\x00\x00\x00" b"\x00\x00" b"\x00\x00"
        actual.unpack(data)
        assert len(actual) == 16
        assert actual["structure_size"].get_value() == 17
        assert actual["reserved"].get_value() == 0
        assert actual["count"].get_value() == 58040
        assert actual["remaining"].get_value() == 0
        assert actual["write_channel_info_offset"].get_value() == 0
        assert actual["write_channel_info_length"].get_value() == 0


class TestSMB2QueryDirectoryRequest:
    def test_create_message(self):
        message = SMB2QueryDirectoryRequest()
        message["file_information_class"] = FileInformationClass.FILE_NAMES_INFORMATION
        message["file_id"] = b"\xB6\x73\xE4\x65\x00\x00\x00\x00" b"\x68\xBD\xA1\xCE\x00\x00\x00\x00"
        message["output_buffer_length"] = 65536
        message["buffer"] = "*".encode("utf-16-le")
        expected = (
            b"\x21\x00"
            b"\x0C"
            b"\x00"
            b"\x00\x00\x00\x00"
            b"\xB6\x73\xE4\x65\x00\x00\x00\x00"
            b"\x68\xBD\xA1\xCE\x00\x00\x00\x00"
            b"\x60\x00"
            b"\x02\x00"
            b"\x00\x00\x01\x00"
            b"\x2A\x00"
        )
        actual = message.pack()
        assert len(message) == 34
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2QueryDirectoryRequest()
        data = (
            b"\x21\x00"
            b"\x0C"
            b"\x00"
            b"\x00\x00\x00\x00"
            b"\xB6\x73\xE4\x65\x00\x00\x00\x00"
            b"\x68\xBD\xA1\xCE\x00\x00\x00\x00"
            b"\x60\x00"
            b"\x02\x00"
            b"\x00\x00\x01\x00"
            b"\x2A\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 34
        assert data == b""
        assert actual["structure_size"].get_value() == 33
        assert actual["file_information_class"].get_value() == FileInformationClass.FILE_NAMES_INFORMATION
        assert actual["flags"].get_value() == 0
        assert actual["file_index"].get_value() == 0
        assert actual["file_id"].get_value() == b"\xB6\x73\xE4\x65\x00\x00\x00\x00" b"\x68\xBD\xA1\xCE\x00\x00\x00\x00"
        assert actual["file_name_offset"].get_value() == 96
        assert actual["file_name_length"].get_value() == 2
        assert actual["output_buffer_length"].get_value() == 65536
        assert actual["buffer"].get_value().decode("utf-16-le") == "*"


class TestSMB2QueryDirectoryResponse:
    def test_create_message(self):
        message = SMB2QueryDirectoryResponse()
        message["buffer"] = b"\x10\x00\x00\x00\x00\x00\x00\x00" b"\x02\x00\x00\x00\x2E\x00\x00\x00"
        expected = (
            b"\x09\x00"
            b"\x48\x00"
            b"\x10\x00\x00\x00"
            b"\x10\x00\x00\x00\x00\x00\x00\x00"
            b"\x02\x00\x00\x00\x2E\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 24
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2QueryDirectoryResponse()
        data = (
            b"\x09\x00"
            b"\x48\x00"
            b"\x10\x00\x00\x00"
            b"\x10\x00\x00\x00\x00\x00\x00\x00"
            b"\x02\x00\x00\x00\x2E\x00\x00\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 24
        assert data == b""
        assert actual["structure_size"].get_value() == 9
        assert actual["output_buffer_offset"].get_value() == 72
        assert actual["output_buffer_length"].get_value() == 16
        assert actual["buffer"].get_value() == b"\x10\x00\x00\x00\x00\x00\x00\x00" b"\x02\x00\x00\x00\x2E\x00\x00\x00"


class TestSMB2QueryInfoRequest:
    DATA = (
        b"\x29\x00"
        b"\x01"
        b"\x00"
        b"\x00\x00\x00\x00"
        b"\x68\x00"
        b"\x00\x00"
        b"\x04\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x01\x00\x00\x00"
        b"\xff\xff\xff\xff\xff\xff\xff\xff"
        b"\xff\xff\xff\xff\xff\xff\xff\xff"
        b"\x01\x02\x03\x04"
    )

    def test_create_message(self):
        message = SMB2QueryInfoRequest()
        message["info_type"] = 1
        message["flags"] = 1
        message["file_id"] = b"\xff" * 16
        message["buffer"] = b"\x01\x02\x03\x04"

        actual = message.pack()
        assert len(message) == 44
        assert actual == self.DATA

    def test_parse_message(self):
        actual = SMB2QueryInfoRequest()
        data = actual.unpack(self.DATA)

        assert len(actual) == 44
        assert data == b""

        assert actual["structure_size"].get_value() == 41
        assert actual["info_type"].get_value() == 1
        assert actual["file_info_class"].get_value() == 0
        assert actual["output_buffer_length"].get_value() == 0
        assert actual["input_buffer_offset"].get_value() == 104
        assert actual["reserved"].get_value() == 0
        assert actual["input_buffer_length"].get_value() == 4
        assert actual["additional_information"].get_value() == 0
        assert actual["flags"].get_value() == 1
        assert actual["file_id"].get_value() == b"\xff" * 16
        assert actual["buffer"].get_value() == b"\x01\x02\x03\x04"


class TestSMB2QueryInfoResponse:
    def test_create_message(self):
        message = SMB2QueryInfoResponse()
        message["buffer"] = b"\x01\x02\x03\x04"
        expected = b"\x09\x00" b"\x48\x00" b"\x04\x00\x00\x00" b"\x01\x02\x03\x04"

        actual = message.pack()
        assert len(message) == 12
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2QueryInfoResponse()
        data = b"\x09\x00" b"\x48\x00" b"\x04\x00\x00\x00" b"\x01\x02\x03\x04"
        data = actual.unpack(data)
        assert len(actual) == 12
        assert data == b""

        assert actual["structure_size"].get_value() == 9
        assert actual["output_buffer_offset"].get_value() == 72
        assert actual["output_buffer_length"].get_value() == 4
        assert actual["buffer"].get_value() == b"\x01\x02\x03\x04"

    def test_unpack_multiple_ea_response(self):
        data = (
            b"\x14\x00\x00\x00"
            b"\x00"
            b"\x04"
            b"\x04\x00"
            b"\x43\x41\x46\xe9\x00"
            b"\x63\x61\x66\xe9"
            b"\x00\x00\x00"
            b"\x10\x00\x00\x00"
            b"\x00"
            b"\x03"
            b"\x04\x00"
            b"\x41\x42\x43\x00"
            b"\x64\x65\x66\x67"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x0d"
            b"\x04\x00"
            b"\x45\x4e\x44\x20\x41\x54\x54\x52"
            b"\x49\x42\x55\x54\x45\x00"
            b"\x00\x01\x02\x03"
        )

        message = SMB2QueryInfoResponse()
        message["buffer"] = data
        actual = message.parse_buffer(FileFullEaInformation)

        assert len(actual) == 3

        assert actual[0]["next_entry_offset"].get_value() == 20
        assert actual[0]["flags"].get_value() == 0
        assert actual[0]["ea_name_length"].get_value() == 4
        assert actual[0]["ea_value_length"].get_value() == 4
        assert actual[0]["ea_name"].get_value() == b"\x43\x41\x46\xe9"
        assert actual[0]["ea_value"].get_value() == b"\x63\x61\x66\xe9"

        assert actual[1]["next_entry_offset"].get_value() == 16
        assert actual[1]["flags"].get_value() == 0
        assert actual[1]["ea_name_length"].get_value() == 3
        assert actual[1]["ea_value_length"].get_value() == 4
        assert actual[1]["ea_name"].get_value() == b"\x41\x42\x43"
        assert actual[1]["ea_value"].get_value() == b"\x64\x65\x66\x67"

        assert actual[2]["next_entry_offset"].get_value() == 0
        assert actual[2]["flags"].get_value() == 0
        assert actual[2]["ea_name_length"].get_value() == 13
        assert actual[2]["ea_value_length"].get_value() == 4
        assert actual[2]["ea_name"].get_value() == b"\x45\x4e\x44\x20\x41\x54\x54\x52" b"\x49\x42\x55\x54\x45"
        assert actual[2]["ea_value"].get_value() == b"\x00\x01\x02\x03"


class TestSMB2SetInfoRequest:
    def test_create_message(self):
        message = SMB2SetInfoRequest()
        message["info_type"] = 1
        message["file_info_class"] = 1
        message["file_id"] = b"\xff" * 16
        message["buffer"] = b"\x01\x02\x03\x04"
        expected = (
            b"\x21\x00"
            b"\x01"
            b"\x01"
            b"\x04\x00\x00\x00"
            b"\x60\x00"
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x01\x02\x03\x04"
        )

        actual = message.pack()
        assert len(message) == 36
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2SetInfoRequest()
        data = (
            b"\x21\x00"
            b"\x01"
            b"\x01"
            b"\x04\x00\x00\x00"
            b"\x60\x00"
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x01\x02\x03\x04"
        )
        data = actual.unpack(data)
        assert len(actual) == 36
        assert data == b""

        assert actual["structure_size"].get_value() == 33
        assert actual["info_type"].get_value() == 1
        assert actual["file_info_class"].get_value() == 1
        assert actual["buffer_length"].get_value() == 4
        assert actual["buffer_offset"].get_value() == 96
        assert actual["reserved"].get_value() == 0
        assert actual["additional_information"].get_value() == 0
        assert actual["file_id"].get_value() == b"\xff" * 16
        assert actual["buffer"].get_value() == b"\x01\x02\x03\x04"


class TestSMB2SetInfoResponse:
    def test_create_message(self):
        message = SMB2SetInfoResponse()
        expected = b"\x02\x00"

        actual = message.pack()
        assert len(message) == 2
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2SetInfoResponse()
        data = b"\x02\x00"
        data = actual.unpack(data)
        assert len(actual) == 2
        assert data == b""

        assert actual["structure_size"].get_value() == 2


class TestOpen:
    # basic file open tests for each dialect
    def test_dialect_2_0_2(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_2_0_2)
        session = Session(connection, smb_real[0], smb_real[1], False)
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "file.txt")
        try:
            session.connect()
            tree.connect()

            out_cont = open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            assert out_cont is None
            assert open.allocation_size == 0
            assert open.create_action in [CreateAction.FILE_CREATED, CreateAction.FILE_OVERWRITTEN]
            assert isinstance(open.change_time, datetime)
            assert open.create_disposition is None
            assert open.create_options is None
            assert isinstance(open.creation_time, datetime)
            assert open.desired_access is None
            assert not open.durable
            assert open.durable_timeout is None
            assert open.end_of_file == 0
            assert open.file_attributes == 32
            assert isinstance(open.file_id, bytes)
            assert open.file_name == "file.txt"
            assert open.is_persistent is None
            assert isinstance(open.last_access_time, datetime)
            assert open.last_disconnect_time == 0
            assert isinstance(open.last_write_time, datetime)
            assert open.operation_buckets == []
            assert open.oplock_level == 0
            assert not open.resilient_handle
            assert not open.resilient_timeout
            assert open.share_mode is None
        finally:
            connection.disconnect(True)

    def test_dialect_2_1_0(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_2_1_0)
        session = Session(connection, smb_real[0], smb_real[1], False)
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "file.txt")
        try:
            session.connect()
            tree.connect()

            out_cont = open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            assert out_cont is None
            assert open.allocation_size == 0
            assert open.create_action in [CreateAction.FILE_CREATED, CreateAction.FILE_OVERWRITTEN]
            assert isinstance(open.change_time, datetime)
            assert open.create_disposition is None
            assert open.create_options is None
            assert isinstance(open.creation_time, datetime)
            assert open.desired_access is None
            assert not open.durable
            assert open.durable_timeout is None
            assert open.end_of_file == 0
            assert open.file_attributes == 32
            assert isinstance(open.file_id, bytes)
            assert open.file_name == "file.txt"
            assert open.is_persistent is None
            assert isinstance(open.last_access_time, datetime)
            assert open.last_disconnect_time == 0
            assert isinstance(open.last_write_time, datetime)
            assert open.operation_buckets == []
            assert open.oplock_level == 0
            assert not open.resilient_handle
            assert not open.resilient_timeout
            assert open.share_mode is None
        finally:
            connection.disconnect(True)

    def test_dialect_3_0_0(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_0_0)
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "file.txt")
        try:
            session.connect()
            tree.connect()

            out_cont = open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            assert out_cont is None
            assert open.allocation_size == 0
            assert open.create_action in [CreateAction.FILE_CREATED, CreateAction.FILE_OVERWRITTEN]
            assert isinstance(open.change_time, datetime)
            assert open.create_disposition is CreateDisposition.FILE_OVERWRITE_IF
            assert open.create_options is CreateOptions.FILE_NON_DIRECTORY_FILE
            assert isinstance(open.creation_time, datetime)
            assert open.desired_access is FilePipePrinterAccessMask.MAXIMUM_ALLOWED
            assert not open.durable
            assert open.durable_timeout is None
            assert open.end_of_file == 0
            assert open.file_attributes == 32
            assert isinstance(open.file_id, bytes)
            assert open.file_name == "file.txt"
            assert open.is_persistent is None
            assert isinstance(open.last_access_time, datetime)
            assert open.last_disconnect_time == 0
            assert isinstance(open.last_write_time, datetime)
            assert open.operation_buckets == []
            assert open.oplock_level == 0
            assert not open.resilient_handle
            assert not open.resilient_timeout
            assert open.share_mode == 0
        finally:
            connection.disconnect(True)

    def test_dialect_3_0_2(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_0_2)
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "file.txt")
        try:
            session.connect()
            tree.connect()

            out_cont = open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            assert out_cont is None
            assert open.allocation_size == 0
            assert open.create_action in [CreateAction.FILE_CREATED, CreateAction.FILE_OVERWRITTEN]
            assert isinstance(open.change_time, datetime)
            assert open.create_disposition is CreateDisposition.FILE_OVERWRITE_IF
            assert open.create_options is CreateOptions.FILE_NON_DIRECTORY_FILE
            assert isinstance(open.creation_time, datetime)
            assert open.desired_access is FilePipePrinterAccessMask.MAXIMUM_ALLOWED
            assert not open.durable
            assert open.durable_timeout is None
            assert open.end_of_file == 0
            assert open.file_attributes == 32
            assert isinstance(open.file_id, bytes)
            assert open.file_name == "file.txt"
            assert open.is_persistent is None
            assert isinstance(open.last_access_time, datetime)
            assert open.last_disconnect_time == 0
            assert isinstance(open.last_write_time, datetime)
            assert open.operation_buckets == []
            assert open.oplock_level == 0
            assert not open.resilient_handle
            assert not open.resilient_timeout
            assert open.share_mode == 0
        finally:
            connection.disconnect(True)

    def test_dialect_3_1_1(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_1_1)
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "file.txt")
        try:
            session.connect()
            tree.connect()

            out_cont = open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            assert out_cont is None
            assert open.allocation_size == 0
            assert open.create_action in [CreateAction.FILE_CREATED, CreateAction.FILE_OVERWRITTEN]
            assert isinstance(open.change_time, datetime)
            assert open.create_disposition is CreateDisposition.FILE_OVERWRITE_IF
            assert open.create_options is CreateOptions.FILE_NON_DIRECTORY_FILE
            assert isinstance(open.creation_time, datetime)
            assert open.desired_access is FilePipePrinterAccessMask.MAXIMUM_ALLOWED
            assert not open.durable
            assert open.durable_timeout is None
            assert open.end_of_file == 0
            assert open.file_attributes == 32
            assert isinstance(open.file_id, bytes)
            assert open.file_name == "file.txt"
            assert open.is_persistent is None
            assert isinstance(open.last_access_time, datetime)
            assert open.last_disconnect_time == 0
            assert isinstance(open.last_write_time, datetime)
            assert open.operation_buckets == []
            assert open.oplock_level == 0
            assert not open.resilient_handle
            assert not open.resilient_timeout
            assert open.share_mode == 0
        finally:
            connection.disconnect(True)

    def test_open_root_directory(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_1_1)
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[5])
        dir_open = Open(tree, "")
        try:
            session.connect()
            tree.connect()

            dir_open.create(
                ImpersonationLevel.Impersonation,
                DirectoryAccessMask.FILE_LIST_DIRECTORY,
                FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
                ShareAccess.FILE_SHARE_READ,
                CreateDisposition.FILE_OPEN_IF,
                CreateOptions.FILE_DIRECTORY_FILE,
            )
            dir_open.close(get_attributes=False)
        finally:
            connection.disconnect(True)

    # test more file operations here
    def test_create_directory(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_0_0)
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[5])
        open = Open(tree, "folder")
        try:
            session.connect()
            tree.connect()

            out_cont = open.create(
                ImpersonationLevel.Impersonation,
                DirectoryAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
                0,
                CreateDisposition.FILE_OPEN_IF,
                CreateOptions.FILE_DIRECTORY_FILE,
            )
            assert out_cont is None
            assert open.allocation_size == 0
            assert open.create_action in [CreateAction.FILE_OPENED, CreateAction.FILE_CREATED]
            assert isinstance(open.change_time, datetime)
            assert open.create_disposition is CreateDisposition.FILE_OPEN_IF
            assert open.create_options is CreateOptions.FILE_DIRECTORY_FILE
            assert isinstance(open.creation_time, datetime)
            assert open.desired_access is DirectoryAccessMask.MAXIMUM_ALLOWED
            assert not open.durable
            assert open.durable_timeout is None
            assert open.end_of_file == 0
            assert open.file_attributes == FileAttributes.FILE_ATTRIBUTE_DIRECTORY
            assert isinstance(open.file_id, bytes)
            assert open.file_name == "folder"
            assert open.is_persistent is None
            assert isinstance(open.last_access_time, datetime)
            assert open.last_disconnect_time == 0
            assert isinstance(open.last_write_time, datetime)
            assert open.operation_buckets == []
            assert open.oplock_level == 0
            assert not open.resilient_handle
            assert not open.resilient_timeout
            assert open.share_mode == 0
        finally:
            connection.disconnect(True)

    def test_create_file_create_contexts(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_0_0)
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[5])
        open = Open(tree, "file-cont.txt")
        try:
            session.connect()
            tree.connect()

            alloc_size = SMB2CreateAllocationSize()
            alloc_size["allocation_size"] = 1024

            alloc_size_context = SMB2CreateContextRequest()
            alloc_size_context["buffer_name"] = CreateContextName.SMB2_CREATE_ALLOCATION_SIZE
            alloc_size_context["buffer_data"] = alloc_size

            query_disk = SMB2CreateContextRequest()
            query_disk["buffer_name"] = CreateContextName.SMB2_CREATE_QUERY_ON_DISK_ID

            max_req_data = SMB2CreateQueryMaximalAccessRequest()
            max_req = SMB2CreateContextRequest()
            max_req["buffer_name"] = CreateContextName.SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST
            max_req["buffer_data"] = max_req_data

            create_contexts = [alloc_size_context, query_disk, max_req]
            out_cont = open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
                create_contexts,
            )
            assert len(out_cont) == 2
            assert isinstance(out_cont[0], SMB2CreateQueryMaximalAccessResponse) or isinstance(
                out_cont[0], SMB2CreateQueryOnDiskIDResponse
            )
            assert isinstance(out_cont[1], SMB2CreateQueryMaximalAccessResponse) or isinstance(
                out_cont[1], SMB2CreateQueryOnDiskIDResponse
            )
        finally:
            connection.disconnect(True)

    @pytest.mark.parametrize("lease_version", ["v1", "v2"])
    def test_create_file_with_lease(self, smb_real, lease_version):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "file-lease.txt")
        try:
            session.connect()
            tree.connect()

            if lease_version == "v1":
                lease_request = SMB2CreateRequestLease()
            else:
                lease_request = SMB2CreateRequestLeaseV2()
                lease_request["parent_lease_key"] = b"\x00" * 16
                lease_request["epoch"] = os.urandom(2)

            lease_request["lease_key"] = os.urandom(16)
            lease_request["lease_state"] = 1

            out_cont = open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
                create_contexts=[lease_request],
                oplock_level=RequestedOplockLevel.SMB2_OPLOCK_LEVEL_LEASE,
            )
            assert len(out_cont) == 1

            if lease_version == "v1":
                assert isinstance(out_cont[0], SMB2CreateResponseLease)
            else:
                assert isinstance(out_cont[0], SMB2CreateResponseLeaseV2)
        finally:
            connection.disconnect(True)

    def test_create_read_write_from_file(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "file-read-write.txt")
        try:
            session.connect()
            tree.connect()

            open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )

            actual = open.write(b"\x01\x02\x03\x04")
            assert actual == 4
            actual = open.read(0, 4)
            assert actual == b"\x01\x02\x03\x04"
        finally:
            connection.disconnect(True)

    def test_flush_file(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_0_2)
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[5])
        open = Open(tree, "file-cont.txt")
        try:
            session.connect()
            tree.connect()

            open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            open.flush()

            # Test flush without send
            flush_req, flush_resp = open.flush(send=False)
            request = open.connection.send(
                flush_req, open.tree_connect.session.session_id, open.tree_connect.tree_connect_id
            )
            flush_resp = flush_resp(request)
            assert isinstance(flush_resp, SMB2FlushResponse)
        finally:
            connection.disconnect(True)

    def test_close_file_dont_get_attributes(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "file-read-write.txt")
        try:
            session.connect()
            tree.connect()

            open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )

            old_last_write_time = open.last_write_time
            old_end_of_file = open.end_of_file
            open.write(b"\x01")
            open.close(False)
            assert open.last_write_time == old_last_write_time
            assert open.end_of_file == old_end_of_file
        finally:
            open.close(False)  # test close when it has already been closed
            connection.disconnect(True)

    def test_close_file_get_attributes(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "file-read-write.txt")
        try:
            session.connect()
            tree.connect()

            open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )

            old_last_write_time = open.last_write_time
            old_end_of_file = open.end_of_file
            time.sleep(2)
            open.write(b"\x01")
            open.close(True)
            assert open.last_write_time != old_last_write_time
            assert open.end_of_file != old_end_of_file
            assert open.end_of_file == 1
        finally:
            connection.disconnect(True)

    def test_read_file_unbuffered(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_0_2)
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "file-read-write.txt")
        try:
            session.connect()
            tree.connect()

            open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )

            open.write(b"\x01")
            actual = open.read(0, 1, unbuffered=True)
            assert actual == b"\x01"
        finally:
            connection.disconnect(True)

    def test_read_file_unbuffered_unsupported(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_0_0)
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "file-read-write.txt")
        try:
            session.connect()
            tree.connect()

            open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )

            open.write(b"\x01")
            with pytest.raises(SMBUnsupportedFeature) as exc:
                open.read(0, 1, unbuffered=True)
            assert exc.value.feature_name == "SMB2_READFLAG_READ_UNBUFFERED"
            assert exc.value.negotiated_dialect == Dialects.SMB_3_0_0
            assert exc.value.required_dialect == Dialects.SMB_3_0_2
            assert exc.value.requires_newer
            assert (
                str(exc.value) == "SMB2_READFLAG_READ_UNBUFFERED is not available on the "
                "negotiated dialect (768) SMB_3_0_0, requires dialect (770) "
                "SMB_3_0_2 or newer"
            )
        finally:
            connection.disconnect(True)

    @pytest.mark.skipif(os.name == "nt", reason="write-through writes don't work on windows?")
    def test_write_file_write_through(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "file-read-write.txt")
        try:
            session.connect()
            tree.connect()

            open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_WRITE_THROUGH,
            )

            actual = open.write(b"\x01", write_through=True)
            assert actual == 1
            actual = open.read(0, 1)
            assert actual == b"\x01"
        finally:
            connection.disconnect(True)

    def test_write_file_write_through_unsupported(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_2_0_2)
        session = Session(connection, smb_real[0], smb_real[1], False)
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "file-read-write.txt")
        try:
            session.connect()
            tree.connect()

            open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_WRITE_THROUGH,
            )

            with pytest.raises(SMBUnsupportedFeature) as exc:
                open.write(b"\x01", write_through=True)
            assert exc.value.feature_name == "SMB2_WRITEFLAG_WRITE_THROUGH"
            assert exc.value.negotiated_dialect == Dialects.SMB_2_0_2
            assert exc.value.required_dialect == Dialects.SMB_2_1_0
            assert exc.value.requires_newer
            assert (
                str(exc.value) == "SMB2_WRITEFLAG_WRITE_THROUGH is not available on the "
                "negotiated dialect (514) SMB_2_0_2, requires dialect (528) "
                "SMB_2_1_0 or newer"
            )
        finally:
            connection.disconnect(True)

    @pytest.mark.skipif(os.name == "nt", reason="unbufferred writes don't work on windows?")
    def test_write_file_unbuffered(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "file-read-write.txt")
        try:
            session.connect()
            tree.connect()

            open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_NO_INTERMEDIATE_BUFFERING,
            )

            actual = open.write(b"\x01", unbuffered=True)
            assert actual == 1
            actual = open.read(0, 1)
            assert actual == b"\x01"
        finally:
            connection.disconnect(True)

    def test_write_file_unbuffered_unsupported(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_2_1_0)
        session = Session(connection, smb_real[0], smb_real[1], False)
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "file-read-write.txt")
        try:
            session.connect()
            tree.connect()

            open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_NO_INTERMEDIATE_BUFFERING,
            )

            with pytest.raises(SMBUnsupportedFeature) as exc:
                open.write(b"\x01", unbuffered=True)
            assert exc.value.feature_name == "SMB2_WRITEFLAG_WRITE_UNBUFFERED"
            assert exc.value.negotiated_dialect == Dialects.SMB_2_1_0
            assert exc.value.required_dialect == Dialects.SMB_3_0_2
            assert exc.value.requires_newer
            assert (
                str(exc.value) == "SMB2_WRITEFLAG_WRITE_UNBUFFERED is not available on the "
                "negotiated dialect (528) SMB_2_1_0, requires dialect (770) "
                "SMB_3_0_2 or newer"
            )
        finally:
            connection.disconnect(True)

    def test_query_directory(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "directory-query")
        try:
            session.connect()
            tree.connect()

            open.create(
                ImpersonationLevel.Impersonation,
                DirectoryAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
                CreateDisposition.FILE_OPEN_IF,
                CreateOptions.FILE_DIRECTORY_FILE,
            )

            file1 = Open(tree, r"directory-query\\file1.txt")
            file1.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                ShareAccess.FILE_SHARE_READ,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            file1.write(b"\x01\x02\x03\x04", 0)

            file2 = Open(tree, r"directory-query\\file2.log")
            file2.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                ShareAccess.FILE_SHARE_READ,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            file2.write(b"\x05\x06", 0)

            actual = open.query_directory("*", FileInformationClass.FILE_NAMES_INFORMATION)

            assert len(actual) == 4
            assert isinstance(actual[0], FileNamesInformation)
            assert actual[0]["file_name"].get_value().decode("utf-16-le") == "."
            assert isinstance(actual[1], FileNamesInformation)
            assert actual[1]["file_name"].get_value().decode("utf-16-le") == ".."

            file1_name = "file1.txt".encode("utf-16-le")
            file2_name = "file2.log".encode("utf-16-le")
            assert isinstance(actual[2], FileNamesInformation)
            assert actual[2]["file_name"].get_value() in [file1_name, file2_name]
            assert isinstance(actual[3], FileNamesInformation)
            assert actual[3]["file_name"].get_value() in [file1_name, file2_name]

            open.close()
        finally:
            connection.disconnect(True)

    def test_compounding_related_opens_encrypted(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "file-related.txt")
        try:
            session.connect()
            tree.connect()

            messages = [
                open.create(
                    ImpersonationLevel.Impersonation,
                    FilePipePrinterAccessMask.GENERIC_READ
                    | FilePipePrinterAccessMask.GENERIC_WRITE
                    | FilePipePrinterAccessMask.DELETE,
                    FileAttributes.FILE_ATTRIBUTE_NORMAL,
                    0,
                    CreateDisposition.FILE_OVERWRITE_IF,
                    CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_DELETE_ON_CLOSE,
                    send=False,
                ),
                open.write(b"\x01\x02\x03\x04", send=False),
                open.read(0, 4, send=False),
                open.close(False, send=False),
            ]
            requests = connection.send_compound(
                [x[0] for x in messages], session.session_id, tree.tree_connect_id, related=True
            )
            responses = []
            for i, request in enumerate(requests):
                response = messages[i][1](request)
                responses.append(response)

            assert open.file_id != b"\xff" * 16
            assert len(responses) == 4
            assert responses[0] is None
            assert responses[1] == 4
            assert responses[2] == b"\x01\x02\x03\x04"
            assert isinstance(responses[3], SMB2CloseResponse)
        finally:
            connection.disconnect(True)

    def test_compounding_related_opens_signed(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_2_0_2)
        session = Session(connection, smb_real[0], smb_real[1], require_encryption=False)
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "file-related.txt")
        try:
            session.connect()
            tree.connect()

            messages = [
                open.create(
                    ImpersonationLevel.Impersonation,
                    FilePipePrinterAccessMask.GENERIC_READ
                    | FilePipePrinterAccessMask.GENERIC_WRITE
                    | FilePipePrinterAccessMask.DELETE,
                    FileAttributes.FILE_ATTRIBUTE_NORMAL,
                    0,
                    CreateDisposition.FILE_OVERWRITE_IF,
                    CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_DELETE_ON_CLOSE,
                    send=False,
                ),
                open.write(b"\x01\x02\x03\x04", send=False),
                open.read(0, 4, send=False),
                open.close(False, send=False),
            ]
            requests = connection.send_compound(
                [x[0] for x in messages], session.session_id, tree.tree_connect_id, related=True
            )
            responses = []
            for i, request in enumerate(requests):
                response = messages[i][1](request)
                responses.append(response)

            assert open.file_id != b"\xff" * 16
            assert len(responses) == 4
            assert responses[0] is None
            assert responses[1] == 4
            assert responses[2] == b"\x01\x02\x03\x04"
            assert isinstance(responses[3], SMB2CloseResponse)
        finally:
            connection.disconnect(True)

    def test_compounding_open_requests(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "directory-compound-open")
        try:
            session.connect()
            tree.connect()

            open.create(
                ImpersonationLevel.Impersonation,
                DirectoryAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
                CreateDisposition.FILE_OPEN_IF,
                CreateOptions.FILE_DIRECTORY_FILE,
            )

            file1 = Open(tree, r"directory-compound-open\\file1.txt")
            file1.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                ShareAccess.FILE_SHARE_READ,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            file2 = Open(tree, r"directory-compound-open\\file2.log")
            file2.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                ShareAccess.FILE_SHARE_READ,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )

            # create messages for each operation
            messages = [
                file1.write(b"\x01\x02\x03\x04", 0, send=False),
                file2.write(b"\x05\x06", 0, send=False),
                file1.read(0, 4, send=False),
                open.query_directory("*", FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION, send=False),
                file1.close(send=False),
                file2.close(send=False),
            ]

            # send each message as a compound request
            requests = connection.send_compound([x[0] for x in messages], session.session_id, tree.tree_connect_id)

            # get responses and run unpack function
            responses = []
            for i, request in enumerate(requests):
                response = messages[i][1](request)
                responses.append(response)

            # assert each response
            assert len(responses) == 6
            assert isinstance(responses[0], int)
            assert isinstance(responses[1], int)
            assert isinstance(responses[2], bytes)
            assert isinstance(responses[3], list)
            assert isinstance(responses[4], SMB2CloseResponse)
            assert isinstance(responses[5], SMB2CloseResponse)

            write1 = responses[0]
            assert write1 == 4

            write2 = responses[1]
            assert write2 == 2

            read1 = responses[2]
            assert read1 == b"\x01\x02\x03\x04"

            query1 = responses[3]
            assert query1[0]["file_name"].get_value() == ".".encode("utf-16-le")
            assert query1[1]["file_name"].get_value() == "..".encode("utf-16-le")
            file1_name = "file1.txt".encode("utf-16-le")
            file2_name = "file2.log".encode("utf-16-le")
            assert query1[2]["file_name"].get_value() in [file1_name, file2_name]
            assert query1[3]["file_name"].get_value() in [file1_name, file2_name]

            open.close()
        finally:
            connection.disconnect(True)

    def test_compounding_open_requests_unencrypted(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_2_1_0)
        session = Session(connection, smb_real[0], smb_real[1], False)
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "directory-compound-open-plaintext")
        try:
            session.connect()
            tree.connect()

            open.create(
                ImpersonationLevel.Impersonation,
                DirectoryAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
                CreateDisposition.FILE_OPEN_IF,
                CreateOptions.FILE_DIRECTORY_FILE,
            )

            file1 = Open(tree, r"directory-compound-open-plaintext\\file1.txt")
            file1.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                ShareAccess.FILE_SHARE_READ,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            file2 = Open(tree, r"directory-compound-open-plaintext\\file2.log")
            file2.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                ShareAccess.FILE_SHARE_READ,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )

            # create messages for each operation
            messages = [
                file1.write(b"\x01\x02\x03\x04", 0, send=False),
                file2.write(b"\x05\x06", 0, send=False),
                file1.read(0, 4, send=False),
                open.query_directory("*", FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION, send=False),
                file1.close(send=False),
                file2.close(send=False),
            ]

            # send each message as a compound request
            requests = connection.send_compound([x[0] for x in messages], session.session_id, tree.tree_connect_id)

            # get responses and run unpack function
            responses = []
            for i, request in enumerate(requests):
                response = messages[i][1](request)
                responses.append(response)

            # assert each response
            assert len(responses) == 6
            assert isinstance(responses[0], int)
            assert isinstance(responses[1], int)
            assert isinstance(responses[2], bytes)
            assert isinstance(responses[3], list)
            assert isinstance(responses[4], SMB2CloseResponse)
            assert isinstance(responses[5], SMB2CloseResponse)

            write1 = responses[0]
            assert write1 == 4

            write2 = responses[1]
            assert write2 == 2

            read1 = responses[2]
            assert read1 == b"\x01\x02\x03\x04"

            query1 = responses[3]
            assert query1[0]["file_name"].get_value() == ".".encode("utf-16-le")
            assert query1[1]["file_name"].get_value() == "..".encode("utf-16-le")
            file1_name = "file1.txt".encode("utf-16-le")
            file2_name = "file2.log".encode("utf-16-le")
            assert query1[2]["file_name"].get_value() in [file1_name, file2_name]
            assert query1[3]["file_name"].get_value() in [file1_name, file2_name]

            open.close()
        finally:
            connection.disconnect(True)

    def test_close_file_already_closed(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_0_2)
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "file-read-write.txt")
        try:
            session.connect()
            tree.connect()

            open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            open.close()

            # we will just manually say it is still connected so we get the
            # proper error msg
            open._connected = True
            open.close()
        finally:
            connection.disconnect(True)

    def test_read_greater_than_max_size(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "file.txt")
        try:
            session.connect()
            tree.connect()

            open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )

            with pytest.raises(SMBException) as exc:
                open.read(0, connection.max_read_size + 1)
            assert (
                str(exc.value) == "The requested read length %d is "
                "greater than the maximum negotiated "
                "read size %d" % (connection.max_read_size + 1, connection.max_read_size)
            )
        finally:
            connection.disconnect(True)

    def test_write_greater_than_max_size(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "file.txt")
        try:
            session.connect()
            tree.connect()

            open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )

            with pytest.raises(SMBException) as exc:
                open.write(b"\x00" * (connection.max_write_size + 1), 0)
            assert (
                str(exc.value) == "The requested write length %d is "
                "greater than the maximum negotiated "
                "write size %d" % (connection.max_write_size + 1, connection.max_write_size)
            )
        finally:
            connection.disconnect(True)

    def test_read_file_multi_credits(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "file.txt")
        try:
            session.connect()
            tree.connect()

            open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            open.write(b"\x01\x02\x03\x04", 0)
            actual = open.read(0, 65538)
            assert actual == b"\x01\x02\x03\x04"
        finally:
            connection.disconnect(True)

    def test_receive_with_timeout(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "file.txt")

        try:
            session.connect()
            tree.connect()

            open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            read_req, unpack_func = open.write(b"\x00", 0, send=False)
            req = connection.send(read_req, sid=session.session_id, tid=tree.tree_connect_id)
            # get the response so we know the timeout will fail next as there
            # is no response to get
            connection.receive(request=req)
            req.response = None
            req.response_event.clear()

            start_time = time.time()
            with pytest.raises(SMBException) as exc:
                connection.receive(request=req, timeout=2)
            end_time = int(time.time() - start_time)
            assert end_time < 5
            assert (
                str(exc.value) == "Connection timeout of 2 seconds exceeded while waiting for a message id %s "
                "response from the server" % req.message["message_id"].get_value()
            )
        finally:
            connection.disconnect(True)

    def test_close_file_invalid_id(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "file.txt")

        try:
            session.connect()
            tree.connect()

            open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )

            # create a request for a known failure and pass that into the
            # _close_response to ensure the exception is thrown
            read_msg = open.read(10, 0, min_length=1024, send=False)[0]
            req = connection.send(read_msg, sid=session.session_id, tid=tree.tree_connect_id)

            with pytest.raises(EndOfFile) as exc:
                open._close_response(req)
        finally:
            connection.disconnect(True)

    def test_truncate_file(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "truncate-file.txt")

        try:
            session.connect()
            tree.connect()

            open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            assert open.end_of_file == 0

            def read_and_eof(open):
                read_req, read_func = open.read(0, 12, send=False)

                file_info = FileStandardInformation()
                query_req = SMB2QueryInfoRequest()
                query_req["info_type"] = InfoType.SMB2_0_INFO_FILE
                query_req["file_info_class"] = FileInformationClass.FILE_STANDARD_INFORMATION
                query_req["file_id"] = open.file_id
                query_req["output_buffer_length"] = len(file_info)

                requests = open.connection.send_compound(
                    [read_req, query_req],
                    open.tree_connect.session.session_id,
                    open.tree_connect.tree_connect_id,
                    related=True,
                )
                data = read_func(requests[0])
                resp = open.connection.receive(requests[1])

                query_resp = SMB2QueryInfoResponse()
                query_resp.unpack(resp["data"].get_value())
                file_info = query_resp.parse_buffer(FileStandardInformation)
                return data, file_info["end_of_file"].get_value()

            def truncate(open, size):
                eof_info = FileEndOfFileInformation()
                eof_info["end_of_file"] = size
                req = SMB2SetInfoRequest()
                req["info_type"] = InfoType.SMB2_0_INFO_FILE
                req["file_info_class"] = FileInformationClass.FILE_END_OF_FILE_INFORMATION
                req["file_id"] = open.file_id
                req["buffer"] = eof_info
                request = open.connection.send(
                    req, open.tree_connect.session.session_id, open.tree_connect.tree_connect_id
                )
                response = open.connection.receive(request)
                set_resp = SMB2SetInfoResponse()
                set_resp.unpack(response["data"].get_value())

            # Populate the file with some bytes
            open.write(b"\x01\x02\x03\x04")
            assert read_and_eof(open) == (b"\x01\x02\x03\x04", 4)

            # Make the file bigger
            truncate(open, 8)
            assert read_and_eof(open) == (b"\x01\x02\x03\x04\x00\x00\x00\x00", 8)

            # Make the file smaller
            truncate(open, 3)
            assert read_and_eof(open) == (b"\x01\x02\x03", 3)
        finally:
            connection.disconnect(True)
