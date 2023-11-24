# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import uuid
from datetime import datetime, timezone

from smbprotocol.file_info import (
    FileAllInformation,
    FileBothDirectoryInformation,
    FileDirectoryInformation,
    FileDispositionInformation,
    FileEndOfFileInformation,
    FileFsFullSizeInformation,
    FileFsObjectIdInformation,
    FileFsVolumeInformation,
    FileFullDirectoryInformation,
    FileFullEaInformation,
    FileGetEaInformation,
    FileIdBothDirectoryInformation,
    FileIdFullDirectoryInformation,
    FileLinkInformation,
    FileNameInformation,
    FileNamesInformation,
    FileRenameInformation,
    FileStandardInformation,
)
from smbprotocol.structure import DateTimeField


class TestFileNameInformation:
    DATA = b"\x08\x00\x00\x00" b"\x63\x00\x61\x00\x66\x00\xe9\x00"

    def test_create_message(self):
        message = FileNameInformation()
        message["file_name"] = "café"

        actual = message.pack()
        assert len(message) == 12
        assert actual == self.DATA

    def test_parse_message(self):
        actual = FileNameInformation()
        data = actual.unpack(self.DATA)

        assert data == b""
        assert len(actual) == 12
        assert actual["file_name_length"].get_value() == 8
        assert actual["file_name"].get_value() == "café"


class TestFileAllInformation:
    DATA = (
        b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
        b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
        b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
        b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
        b"\x20\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x01\x00\x00\x00"
        b"\x00"
        b"\x00"
        b"\x00\x00"
        b"\xe8\x05\x00\x00\x00\x00\x1a\x00"
        b"\x00\x00\x00\x00"
        b"\xa9\x00\x12\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x01\x00\x00\x00"
        b"\x00\x00\x00\x00"
    )

    def test_create_message(self):
        message = FileAllInformation()
        message["basic_information"]["creation_time"] = DateTimeField.EPOCH_FILETIME
        message["basic_information"]["last_access_time"] = DateTimeField.EPOCH_FILETIME
        message["basic_information"]["last_write_time"] = DateTimeField.EPOCH_FILETIME
        message["basic_information"]["change_time"] = DateTimeField.EPOCH_FILETIME
        message["basic_information"]["file_attributes"] = 32
        message["standard_information"]["number_of_links"] = 1
        message["internal_information"]["index_number"] = 7318349394478568
        message["access_information"]["access_flags"] = 1179817
        message["alignment_information"]["alignment_requirement"] = 1

        actual = message.pack()
        assert len(message) == 100
        assert actual == self.DATA

    def test_parse_message(self):
        actual = FileAllInformation()
        data = actual.unpack(self.DATA)
        assert data == b""
        assert len(actual) == 100

        basic = actual["basic_information"].get_value()
        assert basic["creation_time"].get_value() == DateTimeField.EPOCH_FILETIME
        assert basic["last_access_time"].get_value() == DateTimeField.EPOCH_FILETIME
        assert basic["last_write_time"].get_value() == DateTimeField.EPOCH_FILETIME
        assert basic["change_time"].get_value() == DateTimeField.EPOCH_FILETIME
        assert basic["file_attributes"].get_value() == 32
        assert basic["reserved"].get_value() == 0

        standard = actual["standard_information"].get_value()
        assert standard["allocation_size"].get_value() == 0
        assert standard["end_of_file"].get_value() == 0
        assert standard["number_of_links"].get_value() == 1
        assert standard["delete_pending"].get_value() is False
        assert standard["directory"].get_value() is False
        assert standard["reserved"].get_value() == 0

        internal = actual["internal_information"].get_value()
        assert internal["index_number"].get_value() == 7318349394478568

        ea = actual["ea_information"].get_value()
        assert ea["ea_size"].get_value() == 0

        access = actual["access_information"].get_value()
        assert access["access_flags"].get_value() == 1179817

        position = actual["position_information"].get_value()
        assert position["current_byte_offset"].get_value() == 0

        mode = actual["mode_information"].get_value()
        assert mode["mode"].get_value() == 0

        alignment = actual["alignment_information"].get_value()
        assert alignment["alignment_requirement"].get_value() == 1

        name = actual["name_information"].get_value()
        assert name["file_name_length"].get_value() == 0
        assert name["file_name"].get_value() == ""


class TestFileBothDirectoryInformation:
    def test_create_message(self):
        message = FileBothDirectoryInformation()
        message["creation_time"] = datetime.fromtimestamp(1024, timezone.utc)
        message["last_access_time"] = datetime.fromtimestamp(1024, timezone.utc)
        message["last_write_time"] = datetime.fromtimestamp(1024, timezone.utc)
        message["change_time"] = datetime.fromtimestamp(1024, timezone.utc)
        message["end_of_file"] = 4
        message["allocation_size"] = 1048576
        message["file_attributes"] = 32
        message["file_name"] = "file1.txt".encode("utf-16-le")

        expected = (
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x04\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x10\x00\x00\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x12\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x66\x00\x69\x00\x6C\x00\x65\x00"
            b"\x31\x00\x2E\x00\x74\x00\x78\x00"
            b"\x74\x00"
        )
        actual = message.pack()
        assert len(message) == 112
        assert actual == expected

    def test_parse_message(self):
        actual = FileBothDirectoryInformation()
        data = (
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x04\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x10\x00\x00\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x12\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x66\x00\x69\x00\x6C\x00\x65\x00"
            b"\x31\x00\x2E\x00\x74\x00\x78\x00"
            b"\x74\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 112
        assert data == b""
        assert actual["next_entry_offset"].get_value() == 0
        assert actual["file_index"].get_value() == 0
        assert actual["creation_time"].get_value() == datetime.fromtimestamp(1024, timezone.utc)
        assert actual["last_access_time"].get_value() == datetime.fromtimestamp(1024, timezone.utc)
        assert actual["last_write_time"].get_value() == datetime.fromtimestamp(1024, timezone.utc)
        assert actual["change_time"].get_value() == datetime.fromtimestamp(1024, timezone.utc)
        assert actual["end_of_file"].get_value() == 4
        assert actual["allocation_size"].get_value() == 1048576
        assert actual["file_attributes"].get_value() == 32
        assert actual["file_name_length"].get_value() == 18
        assert actual["ea_size"].get_value() == 0
        assert actual["short_name_length"].get_value() == 0
        assert actual["reserved"].get_value() == 0
        assert actual["short_name"].get_value() == b""
        assert actual["short_name_padding"].get_value() == b"\x00" * 24
        assert actual["file_name"].get_value() == "file1.txt".encode("utf-16-le")


class TestFileDirectoryInformation:
    def test_create_message(self):
        message = FileDirectoryInformation()
        message["creation_time"] = datetime.fromtimestamp(1024, timezone.utc)
        message["last_access_time"] = datetime.fromtimestamp(1024, timezone.utc)
        message["last_write_time"] = datetime.fromtimestamp(1024, timezone.utc)
        message["change_time"] = datetime.fromtimestamp(1024, timezone.utc)
        message["end_of_file"] = 4
        message["allocation_size"] = 1048576
        message["file_attributes"] = 32
        message["file_name"] = "file1.txt".encode("utf-16-le")

        expected = (
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x04\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x10\x00\x00\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x12\x00\x00\x00"
            b"\x66\x00\x69\x00\x6C\x00\x65\x00"
            b"\x31\x00\x2E\x00\x74\x00\x78\x00"
            b"\x74\x00"
        )
        actual = message.pack()
        assert len(message) == 82
        assert actual == expected

    def test_parse_message(self):
        actual = FileDirectoryInformation()
        data = (
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x04\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x10\x00\x00\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x12\x00\x00\x00"
            b"\x66\x00\x69\x00\x6C\x00\x65\x00"
            b"\x31\x00\x2E\x00\x74\x00\x78\x00"
            b"\x74\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 82
        assert data == b""
        assert actual["next_entry_offset"].get_value() == 0
        assert actual["file_index"].get_value() == 0
        assert actual["creation_time"].get_value() == datetime.fromtimestamp(1024, timezone.utc)
        assert actual["last_access_time"].get_value() == datetime.fromtimestamp(1024, timezone.utc)
        assert actual["last_write_time"].get_value() == datetime.fromtimestamp(1024, timezone.utc)
        assert actual["change_time"].get_value() == datetime.fromtimestamp(1024, timezone.utc)
        assert actual["end_of_file"].get_value() == 4
        assert actual["allocation_size"].get_value() == 1048576
        assert actual["file_attributes"].get_value() == 32
        assert actual["file_name_length"].get_value() == 18
        assert actual["file_name"].get_value() == "file1.txt".encode("utf-16-le")


class TestFileDispositionInformation:
    DATA = b"\x01"

    def test_create_message(self):
        message = FileDispositionInformation()
        message["delete_pending"] = True

        actual = message.pack()
        assert len(message) == 1
        assert actual == self.DATA

    def test_parse_message(self):
        actual = FileDispositionInformation()

        data = actual.unpack(self.DATA)
        assert len(actual) == 1
        assert data == b""

        assert actual["delete_pending"].get_value() is True


class TestFileEndOfFileInformation:
    def test_create_message(self):
        message = FileEndOfFileInformation()
        message["end_of_file"] = 1049459

        expected = b"\x73\x03\x10\x00\x00\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 8
        assert actual == expected

    def test_parse_message(self):
        actual = FileEndOfFileInformation()
        data = b"\x73\x03\x10\x00\x00\x00\x00\x00"
        data = actual.unpack(data)

        assert len(actual) == 8
        assert data == b""
        assert actual["end_of_file"].get_value() == 1049459


class TestFileFullDirectoryInformation:
    def test_create_message(self):
        message = FileFullDirectoryInformation()
        message["creation_time"] = datetime.fromtimestamp(1024, timezone.utc)
        message["last_access_time"] = datetime.fromtimestamp(1024, timezone.utc)
        message["last_write_time"] = datetime.fromtimestamp(1024, timezone.utc)
        message["change_time"] = datetime.fromtimestamp(1024, timezone.utc)
        message["end_of_file"] = 4
        message["allocation_size"] = 1048576
        message["file_attributes"] = 32
        message["file_name"] = "file1.txt".encode("utf-16-le")

        expected = (
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x04\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x10\x00\x00\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x12\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x66\x00\x69\x00\x6C\x00\x65\x00"
            b"\x31\x00\x2E\x00\x74\x00\x78\x00"
            b"\x74\x00"
        )
        actual = message.pack()
        assert len(message) == 86
        assert actual == expected

    def test_parse_message(self):
        actual = FileFullDirectoryInformation()
        data = (
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x04\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x10\x00\x00\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x12\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x66\x00\x69\x00\x6C\x00\x65\x00"
            b"\x31\x00\x2E\x00\x74\x00\x78\x00"
            b"\x74\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 86
        assert data == b""
        assert actual["next_entry_offset"].get_value() == 0
        assert actual["file_index"].get_value() == 0
        assert actual["creation_time"].get_value() == datetime.fromtimestamp(1024, timezone.utc)
        assert actual["last_access_time"].get_value() == datetime.fromtimestamp(1024, timezone.utc)
        assert actual["last_write_time"].get_value() == datetime.fromtimestamp(1024, timezone.utc)
        assert actual["change_time"].get_value() == datetime.fromtimestamp(1024, timezone.utc)
        assert actual["end_of_file"].get_value() == 4
        assert actual["allocation_size"].get_value() == 1048576
        assert actual["file_attributes"].get_value() == 32
        assert actual["file_name_length"].get_value() == 18
        assert actual["ea_size"].get_value() == 0
        assert actual["file_name"].get_value() == "file1.txt".encode("utf-16-le")


class TestFileFullEaInformation:
    DATA = b"\x14\x00\x00\x00" b"\x00" b"\x04" b"\x04\x00" b"\x43\x41\x46\xe9\x00" b"\x63\x61\x66\xe9"

    def test_create_message(self):
        message = FileFullEaInformation()
        message["next_entry_offset"] = 20
        message["ea_name"] = b"\x43\x41\x46\xe9"
        message["ea_value"] = b"\x63\x61\x66\xe9"

        actual = message.pack()
        assert len(message) == 17
        assert actual == self.DATA

    def test_parse_message(self):
        actual = FileFullEaInformation()

        data = actual.unpack(self.DATA)
        assert len(actual) == 17
        assert data == b""

        assert actual["next_entry_offset"].get_value() == 20
        assert actual["flags"].get_value() == 0
        assert actual["ea_name_length"].get_value() == 4
        assert actual["ea_value_length"].get_value() == 4
        assert actual["ea_name"].get_value() == b"\x43\x41\x46\xe9"
        assert actual["ea_name_padding"].get_value() == 0
        assert actual["ea_value"].get_value() == b"\x63\x61\x66\xe9"


class TestFileGetEaInformation:
    DATA = b"\x14\x00\x00\x00" b"\x04" b"\x43\x41\x46\xe9\x00"

    def test_create_message(self):
        message = FileGetEaInformation()
        message["next_entry_offset"] = 20
        message["ea_name"] = b"\x43\x41\x46\xe9"

        actual = message.pack()
        assert len(message) == 10
        assert actual == self.DATA

    def test_parse_message(self):
        actual = FileGetEaInformation()

        data = actual.unpack(self.DATA)
        assert data == b""
        assert len(actual) == 10

        assert actual["next_entry_offset"].get_value() == 20
        assert actual["ea_name_length"].get_value() == 4
        assert actual["ea_name"].get_value() == b"\x43\x41\x46\xe9"
        assert actual["padding"].get_value() == 0


class TestFileIdBothDirectoryInformation:
    def test_create_message(self):
        message = FileIdBothDirectoryInformation()
        message["creation_time"] = datetime.fromtimestamp(1024, timezone.utc)
        message["last_access_time"] = datetime.fromtimestamp(1024, timezone.utc)
        message["last_write_time"] = datetime.fromtimestamp(1024, timezone.utc)
        message["change_time"] = datetime.fromtimestamp(1024, timezone.utc)
        message["end_of_file"] = 4
        message["allocation_size"] = 1048576
        message["file_attributes"] = 32
        message["file_id"] = 8800388263864
        message["file_name"] = "file1.txt".encode("utf-16-le")

        expected = (
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x04\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x10\x00\x00\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x12\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00"
            b"\xB8\x2F\x04\x00\x01\x08\x00\x00"
            b"\x66\x00\x69\x00\x6C\x00\x65\x00"
            b"\x31\x00\x2E\x00\x74\x00\x78\x00"
            b"\x74\x00"
        )
        actual = message.pack()
        assert len(message) == 122
        assert actual == expected

    def test_parse_message(self):
        actual = FileIdBothDirectoryInformation()
        data = (
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x04\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x10\x00\x00\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x12\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00"
            b"\xB8\x2F\x04\x00\x01\x08\x00\x00"
            b"\x66\x00\x69\x00\x6C\x00\x65\x00"
            b"\x31\x00\x2E\x00\x74\x00\x78\x00"
            b"\x74\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 122
        assert data == b""
        assert actual["next_entry_offset"].get_value() == 0
        assert actual["file_index"].get_value() == 0
        assert actual["creation_time"].get_value() == datetime.fromtimestamp(1024, timezone.utc)
        assert actual["last_access_time"].get_value() == datetime.fromtimestamp(1024, timezone.utc)
        assert actual["last_write_time"].get_value() == datetime.fromtimestamp(1024, timezone.utc)
        assert actual["change_time"].get_value() == datetime.fromtimestamp(1024, timezone.utc)
        assert actual["end_of_file"].get_value() == 4
        assert actual["allocation_size"].get_value() == 1048576
        assert actual["file_attributes"].get_value() == 32
        assert actual["file_name_length"].get_value() == 18
        assert actual["ea_size"].get_value() == 0
        assert actual["short_name_length"].get_value() == 0
        assert actual["reserved1"].get_value() == 0
        assert actual["short_name"].get_value() == b""
        assert actual["short_name_padding"].get_value() == b"\x00" * 24
        assert actual["reserved2"].get_value() == 0
        assert actual["file_id"].get_value() == 8800388263864
        assert actual["file_name"].get_value() == "file1.txt".encode("utf-16-le")


class TestFileIdFullDirectoryInformation:
    def test_create_message(self):
        message = FileIdFullDirectoryInformation()
        message["creation_time"] = datetime.fromtimestamp(1024, timezone.utc)
        message["last_access_time"] = datetime.fromtimestamp(1024, timezone.utc)
        message["last_write_time"] = datetime.fromtimestamp(1024, timezone.utc)
        message["change_time"] = datetime.fromtimestamp(1024, timezone.utc)
        message["end_of_file"] = 4
        message["allocation_size"] = 1048576
        message["file_attributes"] = 32
        message["file_id"] = 8800388263864
        message["file_name"] = "file1.txt".encode("utf-16-le")

        expected = (
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x04\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x10\x00\x00\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x12\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xB8\x2F\x04\x00\x01\x08\x00\x00"
            b"\x66\x00\x69\x00\x6C\x00\x65\x00"
            b"\x31\x00\x2E\x00\x74\x00\x78\x00"
            b"\x74\x00"
        )
        actual = message.pack()
        assert len(message) == 98
        assert actual == expected

    def test_parse_message(self):
        actual = FileIdFullDirectoryInformation()
        data = (
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x00\x80\x98\x37\xe1\xb1\x9d\x01"
            b"\x04\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x10\x00\x00\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x12\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xB8\x2F\x04\x00\x01\x08\x00\x00"
            b"\x66\x00\x69\x00\x6C\x00\x65\x00"
            b"\x31\x00\x2E\x00\x74\x00\x78\x00"
            b"\x74\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 98
        assert data == b""
        assert actual["next_entry_offset"].get_value() == 0
        assert actual["file_index"].get_value() == 0
        assert actual["creation_time"].get_value() == datetime.fromtimestamp(1024, timezone.utc)
        assert actual["last_access_time"].get_value() == datetime.fromtimestamp(1024, timezone.utc)
        assert actual["last_write_time"].get_value() == datetime.fromtimestamp(1024, timezone.utc)
        assert actual["change_time"].get_value() == datetime.fromtimestamp(1024, timezone.utc)
        assert actual["end_of_file"].get_value() == 4
        assert actual["allocation_size"].get_value() == 1048576
        assert actual["file_attributes"].get_value() == 32
        assert actual["file_name_length"].get_value() == 18
        assert actual["ea_size"].get_value() == 0
        assert actual["reserved"].get_value() == 0
        assert actual["file_id"].get_value() == 8800388263864
        assert actual["file_name"].get_value() == "file1.txt".encode("utf-16-le")


class TestFileLinkInformation:
    DATA = (
        b"\x01"
        b"\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x08\x00\x00\x00"
        b"\x63\x00\x61\x00\x66\x00\xe9\x00"
    )

    def test_create_message(self):
        message = FileLinkInformation()
        message["replace_if_exists"] = True
        message["file_name"] = "café"

        actual = message.pack()
        assert len(message) == 28
        assert actual == self.DATA

    def test_parse_message(self):
        actual = FileLinkInformation()
        data = actual.unpack(self.DATA)

        assert data == b""
        assert len(actual) == 28
        assert actual["replace_if_exists"].get_value() is True
        assert actual["file_name_length"].get_value() == 8
        assert actual["file_name"].get_value() == "café"


class TestFileNamesInformation:
    def test_create_message(self):
        message = FileNamesInformation()
        message["file_name"] = "file1.txt".encode("utf-16-le")
        expected = (
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x12\x00\x00\x00"
            b"\x66\x00\x69\x00\x6C\x00\x65\x00"
            b"\x31\x00\x2E\x00\x74\x00\x78\x00"
            b"\x74\x00"
        )
        actual = message.pack()
        assert len(message) == 30
        assert actual == expected

    def test_parse_message(self):
        actual = FileNamesInformation()
        data = (
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x12\x00\x00\x00"
            b"\x66\x00\x69\x00\x6C\x00\x65\x00"
            b"\x31\x00\x2E\x00\x74\x00\x78\x00"
            b"\x74\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 30
        assert data == b""
        assert actual["next_entry_offset"].get_value() == 0
        assert actual["file_index"].get_value() == 0
        assert actual["file_name_length"].get_value() == 18
        assert actual["file_name"].get_value() == "file1.txt".encode("utf-16-le")


class TestFileRenameInformation:
    DATA = (
        b"\x01"
        b"\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x08\x00\x00\x00"
        b"\x63\x00\x61\x00\x66\x00\xe9\x00"
    )

    def test_create_message(self):
        message = FileRenameInformation()
        message["replace_if_exists"] = True
        message["file_name"] = "café"

        actual = message.pack()
        assert len(message) == 28
        assert actual == self.DATA

    def test_parse_message(self):
        actual = FileRenameInformation()
        data = actual.unpack(self.DATA)

        assert data == b""
        assert len(actual) == 28
        assert actual["replace_if_exists"].get_value() is True
        assert actual["file_name_length"].get_value() == 8
        assert actual["file_name"].get_value() == "café"


class TestFileStandardInformation:
    def test_create_message(self):
        message = FileStandardInformation()
        message["allocation_size"] = 123456
        message["end_of_file"] = 123450
        message["number_of_links"] = 32
        message["delete_pending"] = True
        message["directory"] = False

        expected = (
            b"\x40\xe2\x01\x00\x00\x00\x00\x00"
            b"\x3a\xe2\x01\x00\x00\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x01"
            b"\x00"
            b"\x00\x00"
        )

        actual = message.pack()
        assert len(message) == 24
        assert actual == expected

    def test_parse_message(self):
        actual = FileStandardInformation()
        data = (
            b"\x40\xe2\x01\x00\x00\x00\x00\x00"
            b"\x3a\xe2\x01\x00\x00\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x01"
            b"\x00"
            b"\x00\x00"
        )

        data = actual.unpack(data)
        assert len(actual) == 24
        assert data == b""
        assert actual["allocation_size"].get_value() == 123456
        assert actual["end_of_file"].get_value() == 123450
        assert actual["number_of_links"].get_value() == 32
        assert actual["delete_pending"].get_value() is True
        assert actual["directory"].get_value() is False


class TestFileFsObjectInformation:
    DATA = (
        b"\x01\x02\x03\x04\x05\x06\x07\x08"
        b"\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
    )

    def test_create_message(self):
        message = FileFsObjectIdInformation()
        message["object_id"] = b"\x01\x02\x03\x04\x05\x06\x07\x08" b"\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"

        actual = message.pack()
        assert len(message) == 64
        assert actual == self.DATA

    def test_parse_message(self):
        actual = FileFsObjectIdInformation()
        data = actual.unpack(self.DATA)

        assert len(actual) == 64
        assert data == b""

        assert actual["object_id"].get_value() == uuid.UUID(
            bytes=b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
        )
        assert actual["extended_info"].get_value() == b"\x00" * 48


class TestFileFsVolumeInformation:
    DATA = (
        b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
        b"\x0a\x00\x00\x00"
        b"\x08\x00\x00\x00"
        b"\x00"
        b"\x00"
        b"\x63\x00\x61\x00\x66\x00\xe9\x00"
    )

    def test_create_message(self):
        message = FileFsVolumeInformation()
        message["volume_creation_time"] = datetime.fromtimestamp(0, timezone.utc)
        message["volume_serial_number"] = 10
        message["volume_label"] = "café"

        actual = message.pack()
        assert len(message) == 26
        assert actual == self.DATA

    def test_parse_message(self):
        actual = FileFsVolumeInformation()
        data = actual.unpack(self.DATA)

        assert len(actual) == 26
        assert data == b""

        assert actual["volume_creation_time"].get_value() == datetime.fromtimestamp(0, timezone.utc)
        assert actual["volume_serial_number"].get_value() == 10
        assert actual["volume_label_length"].get_value() == 8
        assert actual["supports_objects"].get_value() is False
        assert actual["volume_label"].get_value() == "café"


class TestFileFsFullSizeInformation:
    DATA = (
        b"\xa4\x6f\xd6\x01\x00\x00\x00\x00"
        b"\x9c\x41\x12\x01\x00\x00\x00\x00"
        b"\x9c\x41\x12\x01\x00\x00\x00\x00"
        b"\x02\x00\x00\x00"
        b"\x00\x02\x00\x00"
    )

    def test_create_message(self):
        message = FileFsFullSizeInformation()
        message["total_allocation_units"] = 30830500
        message["caller_available_units"] = 17973660
        message["actual_available_units"] = 17973660
        message["sectors_per_unit"] = 2
        message["bytes_per_sector"] = 512

        actual = message.pack()
        assert len(message) == 32
        assert actual == self.DATA

    def test_parse_message(self):
        actual = FileFsFullSizeInformation()
        data = actual.unpack(self.DATA)

        assert len(actual) == 32
        assert data == b""

        assert actual["total_allocation_units"].get_value() == 30830500
        assert actual["caller_available_units"].get_value() == 17973660
        assert actual["actual_available_units"].get_value() == 17973660
        assert actual["sectors_per_unit"].get_value() == 2
        assert actual["bytes_per_sector"].get_value() == 512
