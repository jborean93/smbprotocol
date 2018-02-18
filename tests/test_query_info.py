from datetime import datetime

from smbprotocol.query_info import FileBothDirectoryInformation, \
    FileDirectoryInformation, FileFullDirectoryInformation, \
    FileIdBothDirectoryInformation, FileIdFullDirectoryInformation, \
    FileNamesInformation


class TestFileBothDirectoryInformation(object):

    def test_create_message(self):
        message = FileBothDirectoryInformation()
        message['creation_time'] = datetime.utcfromtimestamp(1024)
        message['last_access_time'] = datetime.utcfromtimestamp(1024)
        message['last_write_time'] = datetime.utcfromtimestamp(1024)
        message['change_time'] = datetime.utcfromtimestamp(1024)
        message['end_of_file'] = 4
        message['allocation_size'] = 1048576
        message['file_attributes'] = 32
        message['file_name'] = "file1.txt".encode("utf-16-le")

        expected = b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
                   b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
                   b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
                   b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
                   b"\x04\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x10\x00\x00\x00\x00\x00" \
                   b"\x20\x00\x00\x00" \
                   b"\x12\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00" \
                   b"\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x66\x00\x69\x00\x6C\x00\x65\x00" \
                   b"\x31\x00\x2E\x00\x74\x00\x78\x00" \
                   b"\x74\x00"
        actual = message.pack()
        assert len(message) == 112
        assert actual == expected

    def test_parse_message(self):
        actual = FileBothDirectoryInformation()
        data = b"\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
               b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
               b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
               b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
               b"\x04\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x10\x00\x00\x00\x00\x00" \
               b"\x20\x00\x00\x00" \
               b"\x12\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x00" \
               b"\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x66\x00\x69\x00\x6C\x00\x65\x00" \
               b"\x31\x00\x2E\x00\x74\x00\x78\x00" \
               b"\x74\x00"
        data = actual.unpack(data)
        assert len(actual) == 112
        assert data == b""
        assert actual['next_entry_offset'].get_value() == 0
        assert actual['file_index'].get_value() == 0
        assert actual['creation_time'].get_value() == \
            datetime.utcfromtimestamp(1024)
        assert actual['last_access_time'].get_value() == \
            datetime.utcfromtimestamp(1024)
        assert actual['last_write_time'].get_value() == \
            datetime.utcfromtimestamp(1024)
        assert actual['change_time'].get_value() == \
            datetime.utcfromtimestamp(1024)
        assert actual['end_of_file'].get_value() == 4
        assert actual['allocation_size'].get_value() == 1048576
        assert actual['file_attributes'].get_value() == 32
        assert actual['file_name_length'].get_value() == 18
        assert actual['ea_size'].get_value() == 0
        assert actual['short_name_length'].get_value() == 0
        assert actual['reserved'].get_value() == 0
        assert actual['short_name'].get_value() == b""
        assert actual['short_name_padding'].get_value() == b"\x00" * 24
        assert actual['file_name'].get_value() == \
            "file1.txt".encode('utf-16-le')


class TestFileDirectoryInformation(object):

    def test_create_message(self):
        message = FileDirectoryInformation()
        message['creation_time'] = datetime.utcfromtimestamp(1024)
        message['last_access_time'] = datetime.utcfromtimestamp(1024)
        message['last_write_time'] = datetime.utcfromtimestamp(1024)
        message['change_time'] = datetime.utcfromtimestamp(1024)
        message['end_of_file'] = 4
        message['allocation_size'] = 1048576
        message['file_attributes'] = 32
        message['file_name'] = "file1.txt".encode("utf-16-le")

        expected = b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
                   b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
                   b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
                   b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
                   b"\x04\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x10\x00\x00\x00\x00\x00" \
                   b"\x20\x00\x00\x00" \
                   b"\x12\x00\x00\x00" \
                   b"\x66\x00\x69\x00\x6C\x00\x65\x00" \
                   b"\x31\x00\x2E\x00\x74\x00\x78\x00" \
                   b"\x74\x00"
        actual = message.pack()
        assert len(message) == 82
        assert actual == expected

    def test_parse_message(self):
        actual = FileDirectoryInformation()
        data = b"\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
               b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
               b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
               b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
               b"\x04\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x10\x00\x00\x00\x00\x00" \
               b"\x20\x00\x00\x00" \
               b"\x12\x00\x00\x00" \
               b"\x66\x00\x69\x00\x6C\x00\x65\x00" \
               b"\x31\x00\x2E\x00\x74\x00\x78\x00" \
               b"\x74\x00"
        data = actual.unpack(data)
        assert len(actual) == 82
        assert data == b""
        assert actual['next_entry_offset'].get_value() == 0
        assert actual['file_index'].get_value() == 0
        assert actual['creation_time'].get_value() == \
            datetime.utcfromtimestamp(1024)
        assert actual['last_access_time'].get_value() == \
            datetime.utcfromtimestamp(1024)
        assert actual['last_write_time'].get_value() == \
            datetime.utcfromtimestamp(1024)
        assert actual['change_time'].get_value() == \
            datetime.utcfromtimestamp(1024)
        assert actual['end_of_file'].get_value() == 4
        assert actual['allocation_size'].get_value() == 1048576
        assert actual['file_attributes'].get_value() == 32
        assert actual['file_name_length'].get_value() == 18
        assert actual['file_name'].get_value() == \
            "file1.txt".encode('utf-16-le')


class TestFileFullDirectoryInformation(object):

    def test_create_message(self):
        message = FileFullDirectoryInformation()
        message['creation_time'] = datetime.utcfromtimestamp(1024)
        message['last_access_time'] = datetime.utcfromtimestamp(1024)
        message['last_write_time'] = datetime.utcfromtimestamp(1024)
        message['change_time'] = datetime.utcfromtimestamp(1024)
        message['end_of_file'] = 4
        message['allocation_size'] = 1048576
        message['file_attributes'] = 32
        message['file_name'] = "file1.txt".encode("utf-16-le")

        expected = b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
                   b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
                   b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
                   b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
                   b"\x04\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x10\x00\x00\x00\x00\x00" \
                   b"\x20\x00\x00\x00" \
                   b"\x12\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x66\x00\x69\x00\x6C\x00\x65\x00" \
                   b"\x31\x00\x2E\x00\x74\x00\x78\x00" \
                   b"\x74\x00"
        actual = message.pack()
        assert len(message) == 86
        assert actual == expected

    def test_parse_message(self):
        actual = FileFullDirectoryInformation()
        data = b"\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
               b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
               b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
               b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
               b"\x04\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x10\x00\x00\x00\x00\x00" \
               b"\x20\x00\x00\x00" \
               b"\x12\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x66\x00\x69\x00\x6C\x00\x65\x00" \
               b"\x31\x00\x2E\x00\x74\x00\x78\x00" \
               b"\x74\x00"
        data = actual.unpack(data)
        assert len(actual) == 86
        assert data == b""
        assert actual['next_entry_offset'].get_value() == 0
        assert actual['file_index'].get_value() == 0
        assert actual['creation_time'].get_value() == \
            datetime.utcfromtimestamp(1024)
        assert actual['last_access_time'].get_value() == \
            datetime.utcfromtimestamp(1024)
        assert actual['last_write_time'].get_value() == \
            datetime.utcfromtimestamp(1024)
        assert actual['change_time'].get_value() == \
            datetime.utcfromtimestamp(1024)
        assert actual['end_of_file'].get_value() == 4
        assert actual['allocation_size'].get_value() == 1048576
        assert actual['file_attributes'].get_value() == 32
        assert actual['file_name_length'].get_value() == 18
        assert actual['ea_size'].get_value() == 0
        assert actual['file_name'].get_value() == \
            "file1.txt".encode('utf-16-le')


class TestFileIdBothDirectoryInformation(object):

    def test_create_message(self):
        message = FileIdBothDirectoryInformation()
        message['creation_time'] = datetime.utcfromtimestamp(1024)
        message['last_access_time'] = datetime.utcfromtimestamp(1024)
        message['last_write_time'] = datetime.utcfromtimestamp(1024)
        message['change_time'] = datetime.utcfromtimestamp(1024)
        message['end_of_file'] = 4
        message['allocation_size'] = 1048576
        message['file_attributes'] = 32
        message['file_id'] = 8800388263864
        message['file_name'] = "file1.txt".encode("utf-16-le")

        expected = b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
                   b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
                   b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
                   b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
                   b"\x04\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x10\x00\x00\x00\x00\x00" \
                   b"\x20\x00\x00\x00" \
                   b"\x12\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00" \
                   b"\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00" \
                   b"\xB8\x2F\x04\x00\x01\x08\x00\x00" \
                   b"\x66\x00\x69\x00\x6C\x00\x65\x00" \
                   b"\x31\x00\x2E\x00\x74\x00\x78\x00" \
                   b"\x74\x00"
        actual = message.pack()
        assert len(message) == 122
        assert actual == expected

    def test_parse_message(self):
        actual = FileIdBothDirectoryInformation()
        data = b"\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
               b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
               b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
               b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
               b"\x04\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x10\x00\x00\x00\x00\x00" \
               b"\x20\x00\x00\x00" \
               b"\x12\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x00" \
               b"\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00" \
               b"\xB8\x2F\x04\x00\x01\x08\x00\x00" \
               b"\x66\x00\x69\x00\x6C\x00\x65\x00" \
               b"\x31\x00\x2E\x00\x74\x00\x78\x00" \
               b"\x74\x00"
        data = actual.unpack(data)
        assert len(actual) == 122
        assert data == b""
        assert actual['next_entry_offset'].get_value() == 0
        assert actual['file_index'].get_value() == 0
        assert actual['creation_time'].get_value() == \
            datetime.utcfromtimestamp(1024)
        assert actual['last_access_time'].get_value() == \
            datetime.utcfromtimestamp(1024)
        assert actual['last_write_time'].get_value() == \
            datetime.utcfromtimestamp(1024)
        assert actual['change_time'].get_value() == \
            datetime.utcfromtimestamp(1024)
        assert actual['end_of_file'].get_value() == 4
        assert actual['allocation_size'].get_value() == 1048576
        assert actual['file_attributes'].get_value() == 32
        assert actual['file_name_length'].get_value() == 18
        assert actual['ea_size'].get_value() == 0
        assert actual['short_name_length'].get_value() == 0
        assert actual['reserved1'].get_value() == 0
        assert actual['short_name'].get_value() == b""
        assert actual['short_name_padding'].get_value() == b"\x00" * 24
        assert actual['reserved2'].get_value() == 0
        assert actual['file_id'].get_value() == 8800388263864
        assert actual['file_name'].get_value() == \
            "file1.txt".encode('utf-16-le')


class TestFileIdFullDirectoryInformation(object):

    def test_create_message(self):
        message = FileIdFullDirectoryInformation()
        message['creation_time'] = datetime.utcfromtimestamp(1024)
        message['last_access_time'] = datetime.utcfromtimestamp(1024)
        message['last_write_time'] = datetime.utcfromtimestamp(1024)
        message['change_time'] = datetime.utcfromtimestamp(1024)
        message['end_of_file'] = 4
        message['allocation_size'] = 1048576
        message['file_attributes'] = 32
        message['file_id'] = 8800388263864
        message['file_name'] = "file1.txt".encode("utf-16-le")

        expected = b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
                   b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
                   b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
                   b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
                   b"\x04\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x10\x00\x00\x00\x00\x00" \
                   b"\x20\x00\x00\x00" \
                   b"\x12\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\xB8\x2F\x04\x00\x01\x08\x00\x00" \
                   b"\x66\x00\x69\x00\x6C\x00\x65\x00" \
                   b"\x31\x00\x2E\x00\x74\x00\x78\x00" \
                   b"\x74\x00"
        actual = message.pack()
        assert len(message) == 98
        assert actual == expected

    def test_parse_message(self):
        actual = FileIdFullDirectoryInformation()
        data = b"\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
               b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
               b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
               b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
               b"\x04\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x10\x00\x00\x00\x00\x00" \
               b"\x20\x00\x00\x00" \
               b"\x12\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\xB8\x2F\x04\x00\x01\x08\x00\x00" \
               b"\x66\x00\x69\x00\x6C\x00\x65\x00" \
               b"\x31\x00\x2E\x00\x74\x00\x78\x00" \
               b"\x74\x00"
        data = actual.unpack(data)
        assert len(actual) == 98
        assert data == b""
        assert actual['next_entry_offset'].get_value() == 0
        assert actual['file_index'].get_value() == 0
        assert actual['creation_time'].get_value() == \
            datetime.utcfromtimestamp(1024)
        assert actual['last_access_time'].get_value() == \
            datetime.utcfromtimestamp(1024)
        assert actual['last_write_time'].get_value() == \
            datetime.utcfromtimestamp(1024)
        assert actual['change_time'].get_value() == \
            datetime.utcfromtimestamp(1024)
        assert actual['end_of_file'].get_value() == 4
        assert actual['allocation_size'].get_value() == 1048576
        assert actual['file_attributes'].get_value() == 32
        assert actual['file_name_length'].get_value() == 18
        assert actual['ea_size'].get_value() == 0
        assert actual['reserved'].get_value() == 0
        assert actual['file_id'].get_value() == 8800388263864
        assert actual['file_name'].get_value() == \
            "file1.txt".encode('utf-16-le')


class TestFileNamesInformation(object):

    def test_create_message(self):
        message = FileNamesInformation()
        message['file_name'] = "file1.txt".encode('utf-16-le')
        expected = b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x12\x00\x00\x00" \
                   b"\x66\x00\x69\x00\x6C\x00\x65\x00" \
                   b"\x31\x00\x2E\x00\x74\x00\x78\x00" \
                   b"\x74\x00"
        actual = message.pack()
        assert len(message) == 30
        assert actual == expected

    def test_parse_message(self):
        actual = FileNamesInformation()
        data = b"\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x12\x00\x00\x00" \
               b"\x66\x00\x69\x00\x6C\x00\x65\x00" \
               b"\x31\x00\x2E\x00\x74\x00\x78\x00" \
               b"\x74\x00"
        data = actual.unpack(data)
        assert len(actual) == 30
        assert data == b""
        assert actual['next_entry_offset'].get_value() == 0
        assert actual['file_index'].get_value() == 0
        assert actual['file_name_length'].get_value() == 18
        assert actual['file_name'].get_value() == \
            "file1.txt".encode('utf-16-le')
