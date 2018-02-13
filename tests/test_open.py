from datetime import datetime
from smbprotocol.open import CloseFlags, CreateAction, CreateDisposition, \
    CreateOptions, FileAttributes, FileFlags, \
    FilePipePrinterAccessMask, ImpersonationLevel, ReadWriteChannel, \
    ShareAccess, SMB2CloseRequest, \
    SMB2CloseResponse, SMB2CreateRequest, SMB2CreateResponse, \
    SMB2FlushRequest, SMB2FlushResponse, SMB2ReadRequest, SMB2ReadResponse, \
    SMB2WriteRequest, SMB2WriteResponse
from smbprotocol.create_contexts import CreateContextName, \
    SMB2CreateContextRequest, SMB2CreateTimewarpToken


class TestSMB2CreateRequest(object):

    def test_create_message(self):
        timewarp_token = SMB2CreateTimewarpToken()
        timewarp_token['timestamp'] = datetime.utcfromtimestamp(0)
        timewarp_context = SMB2CreateContextRequest()
        timewarp_context['buffer_name'] = \
            CreateContextName.SMB2_CREATE_TIMEWARP_TOKEN
        timewarp_context['buffer_data'] = timewarp_token

        message = SMB2CreateRequest()
        message['impersonation_level'] = ImpersonationLevel.Impersonation
        message['desired_access'] = FilePipePrinterAccessMask.GENERIC_READ
        message['file_attributes'] = FileAttributes.FILE_ATTRIBUTE_NORMAL
        message['share_access'] = ShareAccess.FILE_SHARE_READ
        message['create_disposition'] = CreateDisposition.FILE_OPEN
        message['create_options'] = CreateOptions.FILE_NON_DIRECTORY_FILE
        message['buffer_path'] = r"\\server\share".encode("utf-16-le")
        message['buffer_contexts'] = [timewarp_context]
        expected = b"\x39\x00" \
                   b"\x00" \
                   b"\x00" \
                   b"\x02\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x80" \
                   b"\x80\x00\x00\x00" \
                   b"\x01\x00\x00\x00" \
                   b"\x01\x00\x00\x00" \
                   b"\x40\x00\x00\x00" \
                   b"\x78\x00" \
                   b"\x1c\x00" \
                   b"\x98\x00\x00\x00" \
                   b"\x20\x00\x00\x00" \
                   b"\x5c\x00\x5c\x00\x73\x00\x65\x00" \
                   b"\x72\x00\x76\x00\x65\x00\x72\x00" \
                   b"\x5C\x00\x73\x00\x68\x00\x61\x00" \
                   b"\x72\x00\x65\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x10\x00" \
                   b"\x04\x00" \
                   b"\x00\x00" \
                   b"\x18\x00" \
                   b"\x08\x00\x00\x00" \
                   b"\x54\x57\x72\x70" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
        actual = message.pack()
        assert len(message) == 120
        assert actual == expected

    def test_create_message_no_contexts(self):
        message = SMB2CreateRequest()
        message['impersonation_level'] = ImpersonationLevel.Impersonation
        message['desired_access'] = FilePipePrinterAccessMask.GENERIC_READ
        message['file_attributes'] = FileAttributes.FILE_ATTRIBUTE_NORMAL
        message['share_access'] = ShareAccess.FILE_SHARE_READ
        message['create_disposition'] = CreateDisposition.FILE_OPEN
        message['create_options'] = CreateOptions.FILE_NON_DIRECTORY_FILE
        message['buffer_path'] = r"\\server\share".encode("utf-16-le")
        expected = b"\x39\x00" \
                   b"\x00" \
                   b"\x00" \
                   b"\x02\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x80" \
                   b"\x80\x00\x00\x00" \
                   b"\x01\x00\x00\x00" \
                   b"\x01\x00\x00\x00" \
                   b"\x40\x00\x00\x00" \
                   b"\x78\x00" \
                   b"\x1c\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x5c\x00\x5c\x00\x73\x00\x65\x00" \
                   b"\x72\x00\x76\x00\x65\x00\x72\x00" \
                   b"\x5C\x00\x73\x00\x68\x00\x61\x00" \
                   b"\x72\x00\x65\x00"
        actual = message.pack()
        assert len(message) == 84
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CreateRequest()
        data = b"\x39\x00" \
               b"\x00" \
               b"\x00" \
               b"\x02\x00\x00\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x00\x80" \
               b"\x80\x00\x00\x00" \
               b"\x01\x00\x00\x00" \
               b"\x01\x00\x00\x00" \
               b"\x40\x00\x00\x00" \
               b"\x78\x00" \
               b"\x1c\x00" \
               b"\x98\x00\x00\x00" \
               b"\x20\x00\x00\x00" \
               b"\x5c\x00\x5c\x00\x73\x00\x65\x00" \
               b"\x72\x00\x76\x00\x65\x00\x72\x00" \
               b"\x5C\x00\x73\x00\x68\x00\x61\x00" \
               b"\x72\x00\x65\x00" \
               b"\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x10\x00" \
               b"\x04\x00" \
               b"\x00\x00" \
               b"\x18\x00" \
               b"\x08\x00\x00\x00" \
               b"\x54\x57\x72\x70" \
               b"\x00\x00\x00\x00" \
               b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
        data = actual.unpack(data)
        assert len(actual) == 120
        assert data == b""
        assert actual['structure_size'].get_value() == 57
        assert actual['security_flags'].get_value() == 0
        assert actual['requested_oplock_level'].get_value() == 0
        assert actual['impersonation_level'].get_value() == \
            ImpersonationLevel.Impersonation
        assert actual['smb_create_flags'].get_value() == 0
        assert actual['reserved'].get_value() == 0
        assert actual['desired_access'].get_value() == \
            FilePipePrinterAccessMask.GENERIC_READ
        assert actual['file_attributes'].get_value() == \
            FileAttributes.FILE_ATTRIBUTE_NORMAL
        assert actual['share_access'].get_value() == \
            ShareAccess.FILE_SHARE_READ
        assert actual['create_disposition'].get_value() == \
            CreateDisposition.FILE_OPEN
        assert actual['create_options'].get_value() == \
            CreateOptions.FILE_NON_DIRECTORY_FILE
        assert actual['name_offset'].get_value() == 120
        assert actual['name_length'].get_value() == 28
        assert actual['create_contexts_offset'].get_value() == 152
        assert actual['create_contexts_length'].get_value() == 32
        assert actual['buffer_path'].get_value() == \
            r"\\server\share".encode("utf-16-le")
        assert actual['padding'].get_value() == b"\x00\x00\x00\x00"

        contexts = actual['buffer_contexts'].get_value()
        assert isinstance(contexts, list)
        timewarp_context = contexts[0]
        timewarp_context['next'].get_value() == 0
        timewarp_context['name_offset'].get_value() == 16
        timewarp_context['name_length'].get_value() == 4
        timewarp_context['reserved'].get_value() == 0
        timewarp_context['data_offset'].get_value() == 24
        timewarp_context['data_length'].get_value() == 8
        timewarp_context['buffer_name'].get_value() == \
            CreateContextName.SMB2_CREATE_TIMEWARP_TOKEN
        timewarp_context['padding'].get_value() == b"\x00\x00\x00\x00"
        timewarp_context['buffer_data'].get_value() == \
            b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
        timewarp_context['padding2'].get_value() == b""

    def test_parse_message_no_contexts(self):
        actual = SMB2CreateRequest()
        data = b"\x39\x00" \
               b"\x00" \
               b"\x00" \
               b"\x02\x00\x00\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x00\x80" \
               b"\x80\x00\x00\x00" \
               b"\x01\x00\x00\x00" \
               b"\x01\x00\x00\x00" \
               b"\x40\x00\x00\x00" \
               b"\x78\x00" \
               b"\x1c\x00" \
               b"\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x5c\x00\x5c\x00\x73\x00\x65\x00" \
               b"\x72\x00\x76\x00\x65\x00\x72\x00" \
               b"\x5C\x00\x73\x00\x68\x00\x61\x00" \
               b"\x72\x00\x65\x00" \

        data = actual.unpack(data)
        assert len(actual) == 84
        assert data == b""
        assert actual['structure_size'].get_value() == 57
        assert actual['security_flags'].get_value() == 0
        assert actual['requested_oplock_level'].get_value() == 0
        assert actual['impersonation_level'].get_value() == \
            ImpersonationLevel.Impersonation
        assert actual['smb_create_flags'].get_value() == 0
        assert actual['reserved'].get_value() == 0
        assert actual['desired_access'].get_value() == \
            FilePipePrinterAccessMask.GENERIC_READ
        assert actual['file_attributes'].get_value() == \
            FileAttributes.FILE_ATTRIBUTE_NORMAL
        assert actual['share_access'].get_value() == \
            ShareAccess.FILE_SHARE_READ
        assert actual['create_disposition'].get_value() == \
            CreateDisposition.FILE_OPEN
        assert actual['create_options'].get_value() == \
            CreateOptions.FILE_NON_DIRECTORY_FILE
        assert actual['name_offset'].get_value() == 120
        assert actual['name_length'].get_value() == 28
        assert actual['create_contexts_offset'].get_value() == 0
        assert actual['create_contexts_length'].get_value() == 0
        assert actual['buffer_path'].get_value() == \
            r"\\server\share".encode("utf-16-le")
        assert actual['padding'].get_value() == b""
        assert actual['buffer_contexts'].get_value() == []


class TestSMB2CreateResponse(object):

    def test_create_message(self):
        message = SMB2CreateResponse()
        message['flag'] = FileFlags.SMB2_CREATE_FLAG_REPARSEPOINT
        message['create_action'] = CreateAction.FILE_CREATED
        message['creation_time'] = datetime.utcfromtimestamp(1024)
        message['last_access_time'] = datetime.utcfromtimestamp(2048)
        message['last_write_time'] = datetime.utcfromtimestamp(3072)
        message['change_time'] = datetime.utcfromtimestamp(4096)
        message['allocation_size'] = 10
        message['end_of_file'] = 20
        message['file_attributes'] = FileAttributes.FILE_ATTRIBUTE_ARCHIVE
        message['file_id'] = b"\xff" * 16

        timewarp_token = SMB2CreateTimewarpToken()
        timewarp_token['timestamp'] = datetime.utcfromtimestamp(0)
        timewarp_context = SMB2CreateContextRequest()
        timewarp_context['buffer_name'] = \
            CreateContextName.SMB2_CREATE_TIMEWARP_TOKEN
        timewarp_context['buffer_data'] = timewarp_token
        message['buffer'] = [timewarp_context]
        expected = b"\x59\x00" \
                   b"\x00" \
                   b"\x01" \
                   b"\x02\x00\x00\x00" \
                   b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
                   b"\x00\x80\xf2\x99\xe3\xb1\x9d\x01" \
                   b"\x00\x80\x4c\xfc\xe5\xb1\x9d\x01" \
                   b"\x00\x80\xa6\x5e\xe8\xb1\x9d\x01" \
                   b"\x0a\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x14\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x20\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\x98\x00\x00\x00" \
                   b"\x20\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x10\x00" \
                   b"\x04\x00" \
                   b"\x00\x00" \
                   b"\x18\x00" \
                   b"\x08\x00\x00\x00" \
                   b"\x54\x57\x72\x70" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
        actual = message.pack()
        assert len(message) == 120
        assert actual == expected

    def test_create_message_no_contexts(self):
        message = SMB2CreateResponse()
        message['flag'] = FileFlags.SMB2_CREATE_FLAG_REPARSEPOINT
        message['create_action'] = CreateAction.FILE_CREATED
        message['creation_time'] = datetime.utcfromtimestamp(1024)
        message['last_access_time'] = datetime.utcfromtimestamp(2048)
        message['last_write_time'] = datetime.utcfromtimestamp(3072)
        message['change_time'] = datetime.utcfromtimestamp(4096)
        message['allocation_size'] = 10
        message['end_of_file'] = 20
        message['file_attributes'] = FileAttributes.FILE_ATTRIBUTE_ARCHIVE
        message['file_id'] = b"\xff" * 16
        expected = b"\x59\x00" \
                   b"\x00" \
                   b"\x01" \
                   b"\x02\x00\x00\x00" \
                   b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
                   b"\x00\x80\xf2\x99\xe3\xb1\x9d\x01" \
                   b"\x00\x80\x4c\xfc\xe5\xb1\x9d\x01" \
                   b"\x00\x80\xa6\x5e\xe8\xb1\x9d\x01" \
                   b"\x0a\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x14\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x20\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 88
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2CreateResponse()
        data = b"\x59\x00" \
               b"\x00" \
               b"\x01" \
               b"\x02\x00\x00\x00" \
               b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
               b"\x00\x80\xf2\x99\xe3\xb1\x9d\x01" \
               b"\x00\x80\x4c\xfc\xe5\xb1\x9d\x01" \
               b"\x00\x80\xa6\x5e\xe8\xb1\x9d\x01" \
               b"\x0a\x00\x00\x00\x00\x00\x00\x00" \
               b"\x14\x00\x00\x00\x00\x00\x00\x00" \
               b"\x20\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\x98\x00\x00\x00" \
               b"\x20\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x10\x00" \
               b"\x04\x00" \
               b"\x00\x00" \
               b"\x18\x00" \
               b"\x08\x00\x00\x00" \
               b"\x54\x57\x72\x70" \
               b"\x00\x00\x00\x00" \
               b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
        data = actual.unpack(data)
        assert len(actual) == 120
        assert data == b""
        assert actual['structure_size'].get_value() == 89
        assert actual['oplock_level'].get_value() == 0
        assert actual['flag'].get_value() == \
            FileFlags.SMB2_CREATE_FLAG_REPARSEPOINT
        assert actual['create_action'].get_value() == CreateAction.FILE_CREATED
        assert actual['creation_time'].get_value() == \
            datetime.utcfromtimestamp(1024)
        assert actual['last_access_time'].get_value() == \
            datetime.utcfromtimestamp(2048)
        assert actual['last_write_time'].get_value() == \
            datetime.utcfromtimestamp(3072)
        assert actual['change_time'].get_value() == \
            datetime.utcfromtimestamp(4096)
        assert actual['allocation_size'].get_value() == 10
        assert actual['end_of_file'].get_value() == 20
        assert actual['file_attributes'].get_value() == \
            FileAttributes.FILE_ATTRIBUTE_ARCHIVE
        assert actual['reserved2'].get_value() == 0
        assert actual['file_id'].pack() == b"\xff" * 16
        assert actual['create_contexts_offset'].get_value() == 152
        assert actual['create_contexts_length'].get_value() == 32

        contexts = actual['buffer'].get_value()
        assert isinstance(contexts, list)
        timewarp_context = contexts[0]
        timewarp_context['next'].get_value() == 0
        timewarp_context['name_offset'].get_value() == 16
        timewarp_context['name_length'].get_value() == 4
        timewarp_context['reserved'].get_value() == 0
        timewarp_context['data_offset'].get_value() == 24
        timewarp_context['data_length'].get_value() == 8
        timewarp_context['buffer_name'].get_value() == \
            CreateContextName.SMB2_CREATE_TIMEWARP_TOKEN
        timewarp_context['padding'].get_value() == b"\x00\x00\x00\x00"
        timewarp_context['buffer_data'].get_value() == \
            b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
        timewarp_context['padding2'].get_value() == b""

    def test_parse_message_no_contexts(self):
        actual = SMB2CreateResponse()
        data = b"\x59\x00" \
               b"\x00" \
               b"\x01" \
               b"\x02\x00\x00\x00" \
               b"\x00\x80\x98\x37\xe1\xb1\x9d\x01" \
               b"\x00\x80\xf2\x99\xe3\xb1\x9d\x01" \
               b"\x00\x80\x4c\xfc\xe5\xb1\x9d\x01" \
               b"\x00\x80\xa6\x5e\xe8\xb1\x9d\x01" \
               b"\x0a\x00\x00\x00\x00\x00\x00\x00" \
               b"\x14\x00\x00\x00\x00\x00\x00\x00" \
               b"\x20\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00"
        data = actual.unpack(data)
        assert len(actual) == 88
        assert data == b""
        assert actual['structure_size'].get_value() == 89
        assert actual['oplock_level'].get_value() == 0
        assert actual['flag'].get_value() == \
            FileFlags.SMB2_CREATE_FLAG_REPARSEPOINT
        assert actual['create_action'].get_value() == CreateAction.FILE_CREATED
        assert actual['creation_time'].get_value() == \
            datetime.utcfromtimestamp(1024)
        assert actual['last_access_time'].get_value() == \
            datetime.utcfromtimestamp(2048)
        assert actual['last_write_time'].get_value() == \
            datetime.utcfromtimestamp(3072)
        assert actual['change_time'].get_value() == \
            datetime.utcfromtimestamp(4096)
        assert actual['allocation_size'].get_value() == 10
        assert actual['end_of_file'].get_value() == 20
        assert actual['file_attributes'].get_value() == \
            FileAttributes.FILE_ATTRIBUTE_ARCHIVE
        assert actual['reserved2'].get_value() == 0
        assert actual['file_id'].pack() == b"\xff" * 16
        assert actual['create_contexts_offset'].get_value() == 0
        assert actual['create_contexts_length'].get_value() == 0
        assert actual['buffer'].get_value() == []


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
