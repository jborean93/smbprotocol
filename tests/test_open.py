from datetime import datetime
from smbprotocol.open import CloseFlags, ReadWriteChannel, SMB2CloseRequest, \
    SMB2CloseResponse, SMB2CreateRequest, SMB2CreateResponse, \
    SMB2FlushRequest, SMB2FlushResponse, SMB2ReadRequest, SMB2ReadResponse, \
    SMB2WriteRequest, SMB2WriteResponse


class TestSMB2CreateRequest(object):

    def test_create_message(self):
        message = SMB2CreateRequest()

    def test_parse_message(self):
        a = ""


class TestSMB2CreateResponse(object):

    def test_create_message(self):
        message = SMB2CreateResponse()

    def test_parse_message(self):
        a = ""


class TestSMB2CloseRequest(object):

    def test_create_message(self):
        message = SMB2CloseRequest()
        message['flags'].set_flag(CloseFlags.SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB)
        message['file_id'] = b"\xff" * 16
        expected = b"\x18\x00" \
                   b"\x01\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff"
        actual = message.pack()
        assert len(actual) == 24
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CloseRequest()
        data = b"\x18\x00" \
               b"\x01\x00" \
               b"\x00\x00\x00\x00" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff"
        actual.unpack(data)
        assert len(actual) == 24
        assert actual['structure_size'].get_value() == 24
        assert actual['flags'].get_value() == \
            CloseFlags.SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB
        assert actual['reserved'].get_value() == 0
        assert actual['file_id'].get_value().pack() == b"\xff" * 16


class TestSMB2CloseResponse(object):

    def test_create_message(self):
        message = SMB2CloseResponse()
        message['creation_time'] = datetime.utcfromtimestamp(0)
        message['last_access_time'] = datetime.utcfromtimestamp(0)
        message['last_write_time'] = datetime.utcfromtimestamp(0)
        message['change_time'] = datetime.utcfromtimestamp(0)
        expected = b"\x3c\x00" \
                   b"\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x80\x3E\xD5\xDE\xB1\x9D\x01" \
                   b"\x00\x80\x3E\xD5\xDE\xB1\x9D\x01" \
                   b"\x00\x80\x3E\xD5\xDE\xB1\x9D\x01" \
                   b"\x00\x80\x3E\xD5\xDE\xB1\x9D\x01" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00"
        actual = message.pack()
        assert len(actual) == 60
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CloseResponse()
        data = b"\x3c\x00" \
               b"\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x00\x80\x3E\xD5\xDE\xB1\x9D\x01" \
               b"\x00\x80\x3E\xD5\xDE\xB1\x9D\x01" \
               b"\x00\x80\x3E\xD5\xDE\xB1\x9D\x01" \
               b"\x00\x80\x3E\xD5\xDE\xB1\x9D\x01" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00"
        actual.unpack(data)
        assert len(actual) == 60
        assert actual['structure_size'].get_value() == 60
        assert actual['flags'].get_value() == 0
        assert actual['reserved'].get_value() == 0
        assert actual['creation_time'].get_value() == \
            datetime.utcfromtimestamp(0)
        assert actual['last_access_time'].get_value() == \
            datetime.utcfromtimestamp(0)
        assert actual['last_write_time'].get_value() == \
            datetime.utcfromtimestamp(0)
        assert actual['change_time'].get_value() == \
            datetime.utcfromtimestamp(0)
        assert actual['allocation_size'].get_value() == 0
        assert actual['end_of_file'].get_value() == 0
        assert actual['file_attributes'].get_value() == 0


class TestSMB2FlushRequest(object):

    def test_create_message(self):
        message = SMB2FlushRequest()
        message['file_id'] = b"\xff" * 16
        expected = b"\x18\x00" \
                   b"\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff"
        actual = message.pack()
        assert len(message) == 24
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2FlushRequest()
        data = b"\x18\x00" \
               b"\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff"
        actual.unpack(data)
        assert len(actual) == 24
        assert actual['structure_size'].get_value() == 24
        assert actual['reserved1'].get_value() == 0
        assert actual['reserved2'].get_value() == 0
        assert actual['file_id'].pack() == b"\xff" * 16


class TestSMB2FlushResponse(object):

    def test_create_message(self):
        message = SMB2FlushResponse()
        expected = b"\x04\x00" \
                   b"\x00\x00"
        actual = message.pack()
        assert len(message) == 4
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2FlushResponse()
        data = b"\x04\x00" \
               b"\x00\x00"
        actual.unpack(data)
        assert len(actual) == 4
        assert actual['structure_size'].get_value() == 4
        assert actual['reserved'].get_value() == 0


class TestSMB2ReadRequest(object):

    def test_create_message(self):
        message = SMB2ReadRequest()
        message['padding'] = b"\x50"
        message['length'] = 1024
        message['offset'] = 0
        message['file_id'] = b"\xff" * 16
        message['remaining_bytes'] = 0
        expected = b"\x31\x00" \
                   b"\x50" \
                   b"\x00" \
                   b"\x00\x04\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00" \
                   b"\x00\x00" \
                   b"\x00"
        actual = message.pack()
        assert len(message) == 49
        assert actual == expected

    def test_create_message_channel_info(self):
        message = SMB2ReadRequest()
        message['padding'] = b"\x50"
        message['length'] = 1024
        message['offset'] = 0
        message['file_id'] = b"\xff" * 16
        message['channel'].set_flag(ReadWriteChannel.SMB2_CHANNEL_RDMA_V1)
        message['remaining_bytes'] = 0
        message['buffer'] = b"\x00" * 16
        expected = b"\x31\x00" \
                   b"\x50" \
                   b"\x00" \
                   b"\x00\x04\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\x00\x00\x00\x00" \
                   b"\x01\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x70\x00" \
                   b"\x10\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 64
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2ReadRequest()
        data = b"\x31\x00" \
               b"\x50" \
               b"\x00" \
               b"\x00\x04\x00\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x00\x00" \
               b"\x00\x00" \
               b"\x00"
        actual.unpack(data)
        assert len(actual) == 49
        assert actual['structure_size'].get_value() == 49
        assert actual['padding'].get_value() == 80
        assert actual['flags'].get_value() == 0
        assert actual['length'].get_value() == 1024
        assert actual['offset'].get_value() == 0
        assert actual['file_id'].pack() == b"\xff" * 16
        assert actual['minimum_count'].get_value() == 0
        assert actual['channel'].get_value() == 0
        assert actual['remaining_bytes'].get_value() == 0
        assert actual['read_channel_info_offset'].get_value() == 0
        assert actual['read_channel_info_length'].get_value() == 0
        assert actual['buffer'].get_value() == b"\x00"

    def test_parse_message_channel_info(self):
        actual = SMB2ReadRequest()
        data = b"\x31\x00" \
               b"\x50" \
               b"\x00" \
               b"\x00\x04\x00\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\x00\x00\x00\x00" \
               b"\x01\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x70\x00" \
               b"\x10\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00"
        actual.unpack(data)
        assert len(actual) == 64
        assert actual['structure_size'].get_value() == 49
        assert actual['padding'].get_value() == 80
        assert actual['flags'].get_value() == 0
        assert actual['length'].get_value() == 1024
        assert actual['offset'].get_value() == 0
        assert actual['file_id'].pack() == b"\xff" * 16
        assert actual['minimum_count'].get_value() == 0
        assert actual['channel'].get_value() == \
            ReadWriteChannel.SMB2_CHANNEL_RDMA_V1
        assert actual['remaining_bytes'].get_value() == 0
        assert actual['read_channel_info_offset'].get_value() == 112
        assert actual['read_channel_info_length'].get_value() == 16
        assert actual['buffer'].get_value() == b"\x00" * 16


class TestSMB2ReadResponse(object):

    def test_create_message(self):
        message = SMB2ReadResponse()
        message['data_offset'] = 80
        message['data_length'] = 4
        message['buffer'] = b"\x01\x02\x03\x04"
        expected = b"\x11\x00" \
                   b"\x50" \
                   b"\x00" \
                   b"\x04\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x01\x02\x03\x04"
        actual = message.pack()
        assert len(message) == 20
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2ReadResponse()
        data = b"\x11\x00" \
               b"\x50" \
               b"\x00" \
               b"\x04\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x01\x02\x03\x04"
        actual.unpack(data)
        assert len(actual) == 20
        assert actual['structure_size'].get_value() == 17
        assert actual['data_offset'].get_value() == 80
        assert actual['reserved'].get_value() == 0
        assert actual['data_length'].get_value() == 4
        assert actual['data_remaining'].get_value() == 0
        assert actual['reserved2'].get_value() == 0
        assert actual['buffer'].get_value() == b"\x01\x02\x03\x04"


class TestSMB2WriteRequest(object):

    def test_create_message(self):
        message = SMB2WriteRequest()
        message['offset'] = 131072
        message['file_id'] = b"\xff" * 16
        message['channel'].set_flag(ReadWriteChannel.SMB2_CHANNEL_NONE)
        message['remaining_bytes'] = 0
        message['buffer'] = b"\x01\x02\x03\x04"
        expected = b"\x31\x00" \
                   b"\x70\x00" \
                   b"\x04\x00\x00\x00" \
                   b"\x00\x00\x02\x00\x00\x00\x00\x00" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00" \
                   b"\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x01\x02\x03\x04"
        actual = message.pack()
        assert len(message) == 52
        assert actual == expected

    def test_create_message_channel_info(self):
        message = SMB2WriteRequest()
        message['offset'] = 131072
        message['file_id'] = b"\xff" * 16
        message['channel'].set_flag(ReadWriteChannel.SMB2_CHANNEL_RDMA_V1)
        message['remaining_bytes'] = 0
        message['buffer'] = b"\x01\x02\x03\x04"
        message['buffer_channel_info'] = b"\x00" * 16
        expected = b"\x31\x00" \
                   b"\x70\x00" \
                   b"\x04\x00\x00\x00" \
                   b"\x00\x00\x02\x00\x00\x00\x00\x00" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\x01\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x74\x00" \
                   b"\x10\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x01\x02\x03\x04" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 68
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2WriteRequest()
        data = b"\x31\x00" \
               b"\x70\x00" \
               b"\x04\x00\x00\x00" \
               b"\x00\x00\x02\x00\x00\x00\x00\x00" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x00\x00" \
               b"\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x01\x02\x03\x04"
        actual.unpack(data)
        assert len(actual) == 52
        assert actual['structure_size'].get_value() == 49
        assert actual['data_offset'].get_value() == 112
        assert actual['length'].get_value() == 4
        assert actual['offset'].get_value() == 131072
        assert actual['file_id'].pack() == b"\xff" * 16
        assert actual['channel'].get_value() == 0
        assert actual['remaining_bytes'].get_value() == 0
        assert actual['write_channel_info_offset'].get_value() == 0
        assert actual['write_channel_info_length'].get_value() == 0
        assert actual['flags'].get_value() == 0
        assert actual['buffer'].get_value() == b"\x01\x02\x03\x04"
        assert actual['buffer_channel_info'].get_value() == b""

    def test_parse_message_channel_info(self):
        actual = SMB2WriteRequest()
        data = b"\x31\x00" \
               b"\x70\x00" \
               b"\x04\x00\x00\x00" \
               b"\x00\x00\x02\x00\x00\x00\x00\x00" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x74\x00" \
               b"\x10\x00" \
               b"\x00\x00\x00\x00" \
               b"\x01\x02\x03\x04" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00"
        actual.unpack(data)
        assert len(actual) == 68
        assert actual['structure_size'].get_value() == 49
        assert actual['data_offset'].get_value() == 112
        assert actual['length'].get_value() == 4
        assert actual['offset'].get_value() == 131072
        assert actual['file_id'].pack() == b"\xff" * 16
        assert actual['channel'].get_value() == 0
        assert actual['remaining_bytes'].get_value() == 0
        assert actual['write_channel_info_offset'].get_value() == 116
        assert actual['write_channel_info_length'].get_value() == 16
        assert actual['flags'].get_value() == 0
        assert actual['buffer'].get_value() == b"\x01\x02\x03\x04"
        assert actual['buffer_channel_info'].get_value() == b"\x00" * 16


class TestSMB2WriteResponse(object):

    def test_create_message(self):
        message = SMB2WriteResponse()
        message['count'] = 58040
        expected = b"\x11\x00" \
                   b"\x00\x00" \
                   b"\xb8\xe2\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00" \
                   b"\x00\x00"
        actual = message.pack()
        assert len(message) == 16
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2WriteResponse()
        data = b"\x11\x00" \
               b"\x00\x00" \
               b"\xb8\xe2\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x00\x00" \
               b"\x00\x00"
        actual.unpack(data)
        assert len(actual) == 16
        assert actual['structure_size'].get_value() == 17
        assert actual['reserved'].get_value() == 0
        assert actual['count'].get_value() == 58040
        assert actual['remaining'].get_value() == 0
        assert actual['write_channel_info_offset'].get_value() == 0
        assert actual['write_channel_info_length'].get_value() == 0
