import uuid
from datetime import datetime

import pytest

from smbprotocol.constants import Commands, Ciphers, CtlCode, Dialects, \
    HashAlgorithms, IOCTLFlags, NegotiateContextType, SecurityMode, Smb1Flags2
from smbprotocol.messages import DirectTCPPacket, SMB1NegotiateRequest, \
    SMB1PacketHeader, SMB2EncryptionCapabilities, \
    SMB2ErrorResponse, SMB2IOCTLRequest, SMB2IOCTLResponse, SMB2Logoff, \
    SMB2NegotiateContextRequest, SMB2NegotiateRequest, SMB2NegotiateResponse, \
    SMB2PacketHeader, SMB2PreauthIntegrityCapabilities, \
    SMB2SessionSetupRequest, SMB2SessionSetupResponse, SMB2TransformHeader, \
    SMB2TreeConnectRequest, SMB2TreeConnectResponse, SMB2TreeDisconnect, \
    SMB2ValidateNegotiateInfoRequest, SMB2ValidateNegotiateInfoResponse, \
    SMB3NegotiateRequest, SMB3PacketHeader


class TestDirectTcpPacket(object):

    def test_create_message(self):
        message = DirectTCPPacket()
        message['smb2_message'] = b"\xfe\x53\x4d\x42"
        expected = b"\x00\x00\x00\x04" \
                   b"\xfe\x53\x4d\x42"

        actual = message.pack()
        assert len(message) == 8
        assert message['stream_protocol_length'].get_value() == 4
        assert actual == expected

    def test_parse_message(self):
        actual = DirectTCPPacket()
        data = b"\x00\x00\x00\x04" \
               b"\xfe\x53\x4d\x42"
        actual.unpack(data)
        assert len(actual) == 8
        assert actual['stream_protocol_length'].get_value() == 4
        assert isinstance(actual['smb2_message'].get_value(), bytes)

        actual_header = actual['smb2_message']
        assert len(actual_header) == 4
        assert actual_header.get_value() == b"\xfe\x53\x4d\x42"


class TestSMB1PacketHeader(object):

    def test_create_message(self):
        request = SMB1NegotiateRequest()
        request['dialects'] = b"\x02NT LM 0.12\x00" \
                              b"\x02SMB 2.002\x00" \
                              b"\x02SMB 2.???\x00"

        header = SMB1PacketHeader()
        header['command'] = 0x10
        header['flags2'] = Smb1Flags2.SMB_FLAGS2_UNICODE | \
            Smb1Flags2.SMB_FLAGS2_EXTENDED_SECURITY
        header['data'] = request
        expected = b"\xff\x53\x4d\x42" \
                   b"\x10" \
                   b"\x00\x00\x00\x00" \
                   b"\x00" \
                   b"\x00\x88" \
                   b"\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00" \
                   b"\x00\x00" \
                   b"\x00\x00" \
                   b"\x00\x00" \
                   b"\x00\x00" \
                   b"\x00" \
                   b"\x22\x00" \
                   b"\x02\x4e\x54\x20\x4c\x4d\x20\x30" \
                   b"\x2e\x31\x32\x00\x02\x53\x4d\x42" \
                   b"\x20\x32\x2e\x30\x30\x32\x00\x02" \
                   b"\x53\x4d\x42\x20\x32\x2e\x3f\x3f" \
                   b"\x3f\x00"
        actual = header.pack()
        assert len(header) == 69
        assert header['command'].get_value() == 16
        assert header['flags2'].get_value() == 34816
        assert isinstance(header['data'].get_value(), SMB1NegotiateRequest)
        assert len(request) == 37
        assert request['word_count'].get_value() == 0
        assert request['byte_count'].get_value() == 34
        assert request['dialects'].get_value() == b"\x02NT LM 0.12\x00" \
                                                  b"\x02SMB 2.002\x00" \
                                                  b"\x02SMB 2.???\x00"
        assert actual == expected

    def test_parse_message(self):
        actual = SMB1PacketHeader()
        data = b"\xff\x53\x4d\x42" \
               b"\x10" \
               b"\x00\x00\x00\x00" \
               b"\x00" \
               b"\x00\x88" \
               b"\x00\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00" \
               b"\x00\x00" \
               b"\x00\x00" \
               b"\x00\x00" \
               b"\x00\x00" \
               b"\x00" \
               b"\x22\x00" \
               b"\x02\x4e\x54\x20\x4c\x4d\x20\x30" \
               b"\x2e\x31\x32\x00\x02\x53\x4d\x42" \
               b"\x20\x32\x2e\x30\x30\x32\x00\x02" \
               b"\x53\x4d\x42\x20\x32\x2e\x3f\x3f" \
               b"\x3f\x00"
        actual.unpack(data)

        assert len(actual) == 69
        assert actual['protocol'].get_value() == b"\xff\x53\x4d\x42"
        assert actual['command'].get_value() == 16
        assert actual['status'].get_value() == 0
        assert actual['flags'].get_value() == 0
        assert actual['flags2'].get_value() == 34816
        assert actual['security_features'].get_value() == 0
        assert actual['reserved'].get_value() == 0
        assert actual['tid'].get_value() == 0
        assert actual['pid_low'].get_value() == 0
        assert actual['uid'].get_value() == 0
        assert actual['mid'].get_value() == 0
        assert isinstance(actual['data'].get_value(), SMB1NegotiateRequest)

        actual_req = actual['data']
        assert len(actual_req) == 37
        assert actual_req['word_count'].get_value() == 0
        assert actual_req['byte_count'].get_value() == 34
        assert actual_req['dialects'].get_value() == b"\x02NT LM 0.12\x00" \
                                                     b"\x02SMB 2.002\x00" \
                                                     b"\x02SMB 2.???\x00"


class TestSMB2PacketHeader(object):

    def test_create_message(self):
        header = SMB2PacketHeader()
        header['command'] = Commands.SMB2_SESSION_SETUP
        header['message_id'] = 1
        header['session_id'] = 10
        expected = b"\xfe\x53\x4d\x42" \
                   b"\x40\x00" \
                   b"\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x01\x00" \
                   b"\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x01\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x0a\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00"
        actual = header.pack()
        assert len(header) == 64
        print(str(header))
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2PacketHeader()
        data = b"\xfe\x53\x4d\x42" \
               b"\x40\x00" \
               b"\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x01\x00" \
               b"\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x01\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x0a\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x01\x02\x03\x04"
        actual.unpack(data)
        assert len(actual) == 68
        assert actual['protocol_id'].get_value() == b"\xfeSMB"
        assert actual['structure_size'].get_value() == 64
        assert actual['credit_charge'].get_value() == 0
        assert actual['status'].get_value() == 0
        assert actual['command'].get_value() == Commands.SMB2_SESSION_SETUP
        assert actual['credit'].get_value() == 0
        assert actual['flags'].get_value() == 0
        assert actual['next_command'].get_value() == 0
        assert actual['message_id'].get_value() == 1
        assert actual['reserved'].get_value() == 0
        assert actual['tree_id'].get_value() == 0
        assert actual['session_id'].get_value() == 10
        assert actual['signature'].get_value() == b"\x00" * 16
        assert actual['data'].get_value() == b"\x01\x02\x03\x04"


class TestSMB3PacketHeader(object):

    def test_create_message(self):
        header = SMB3PacketHeader()
        header['command'] = Commands.SMB2_SESSION_SETUP
        header['message_id'] = 1
        header['process_id'] = 15
        header['session_id'] = 10
        expected = b"\xfe\x53\x4d\x42" \
                   b"\x40\x00" \
                   b"\x00\x00" \
                   b"\x00\x00" \
                   b"\x00\x00" \
                   b"\x01\x00" \
                   b"\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x01\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x0f\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x0a\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00"
        actual = header.pack()
        assert len(header) == 64
        assert actual == expected

    def test_parse_message(self):
        actual = SMB3PacketHeader()
        data = b"\xfe\x53\x4d\x42" \
               b"\x40\x00" \
               b"\x00\x00" \
               b"\x00\x00" \
               b"\x00\x00" \
               b"\x01\x00" \
               b"\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x01\x00\x00\x00\x00\x00\x00\x00" \
               b"\x0f\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x0a\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x01\x02\x03\x04"
        actual.unpack(data)
        assert len(actual) == 68
        assert actual['protocol_id'].get_value() == b"\xfeSMB"
        assert actual['structure_size'].get_value() == 64
        assert actual['credit_charge'].get_value() == 0
        assert actual['channel_sequence'].get_value() == 0
        assert actual['reserved'].get_value() == 0
        assert actual['command'].get_value() == Commands.SMB2_SESSION_SETUP
        assert actual['credit'].get_value() == 0
        assert actual['flags'].get_value() == 0
        assert actual['next_command'].get_value() == 0
        assert actual['message_id'].get_value() == 1
        assert actual['process_id'].get_value() == 15
        assert actual['tree_id'].get_value() == 0
        assert actual['session_id'].get_value() == 10
        assert actual['signature'].get_value() == b"\x00" * 16
        assert actual['data'].get_value() == b"\x01\x02\x03\x04"


class TestSMB2ErrorResponse(object):

    def test_create_message_plain(self):
        # This is a plain error response without the error context response
        # data appended
        message = SMB2ErrorResponse()
        expected = b"\x09\x00" \
                   b"\x00" \
                   b"\x00" \
                   b"\x00\x00\x00\x00"
        actual = message.pack()
        assert len(actual) == 8
        assert actual == expected

    def test_parse_message_plain(self):
        actual = SMB2ErrorResponse()
        data = b"\x09\x00" \
               b"\x00" \
               b"\x00" \
               b"\x00\x00\x00\x00"
        actual.unpack(data)
        assert len(actual) == 8
        assert actual['structure_size'].get_value() == 9
        assert actual['error_context_count'].get_value() == 0
        assert actual['reserved'].get_value() == 0
        assert actual['byte_count'].get_value() == 0
        assert actual['error_data'].get_value() == []


# TODO: Once I get proper responses from the server
class TestSMB2ErrorContextResponse(object):

    def test_create_message(self):
        pass

    def test_parse_message(self):
        pass


class TestSMB2NegotiateRequest(object):

    def test_create_message(self):
        message = SMB2NegotiateRequest()
        message['security_mode'] = SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        message['capabilities'] = 10
        message['client_guid'] = uuid.UUID(bytes=b"\x33" * 16)
        message['dialects'] = [
            Dialects.SMB_2_0_2,
            Dialects.SMB_2_1_0,
            Dialects.SMB_3_0_0,
            Dialects.SMB_3_0_2
        ]
        expected = b"\x24\x00" \
                   b"\x04\x00" \
                   b"\x01\x00" \
                   b"\x00\x00" \
                   b"\x0a\x00\x00\x00" \
                   b"\x33\x33\x33\x33\x33\x33\x33\x33" \
                   b"\x33\x33\x33\x33\x33\x33\x33\x33" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x02\x02" \
                   b"\x10\x02" \
                   b"\x00\x03" \
                   b"\x02\x03"
        actual = message.pack()
        assert len(message) == 44
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2NegotiateRequest()
        data = b"\x24\x00" \
               b"\x04\x00" \
               b"\x01\x00" \
               b"\x00\x00" \
               b"\x0a\x00\x00\x00" \
               b"\x33\x33\x33\x33\x33\x33\x33\x33" \
               b"\x33\x33\x33\x33\x33\x33\x33\x33" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x02\x02" \
               b"\x10\x02" \
               b"\x00\x03" \
               b"\x02\x03"
        actual.unpack(data)
        assert len(actual) == 44
        assert actual['structure_size'].get_value() == 36
        assert actual['dialect_count'].get_value() == 4
        assert actual['security_mode'].get_value() == \
            SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        assert actual['reserved'].get_value() == 0
        assert actual['capabilities'].get_value() == 10
        assert actual['client_guid'].get_value() == \
            uuid.UUID(bytes=b"\x33" * 16)
        assert actual['client_start_time'].get_value() == 0
        assert actual['dialects'].get_value() == [
            Dialects.SMB_2_0_2,
            Dialects.SMB_2_1_0,
            Dialects.SMB_3_0_0,
            Dialects.SMB_3_0_2
        ]


class TestSMB3NegotiateRequest(object):

    def test_create_message(self):
        message = SMB3NegotiateRequest()
        message['security_mode'] = SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        message['capabilities'] = 10
        message['client_guid'] = uuid.UUID(bytes=b"\x33" * 16)
        message['dialects'] = [
            Dialects.SMB_2_0_2,
            Dialects.SMB_2_1_0,
            Dialects.SMB_3_0_0,
            Dialects.SMB_3_0_2,
            Dialects.SMB_3_1_1
        ]
        con_req = SMB2NegotiateContextRequest()
        con_req['context_type'] = \
            NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES

        enc_cap = SMB2EncryptionCapabilities()
        enc_cap['ciphers'] = [Ciphers.AES_128_GCM]
        con_req['data'] = enc_cap
        message['negotiate_context_list'] = [
            con_req
        ]
        expected = b"\x24\x00" \
                   b"\x05\x00" \
                   b"\x01\x00" \
                   b"\x00\x00" \
                   b"\x0a\x00\x00\x00" \
                   b"\x33\x33\x33\x33\x33\x33\x33\x33" \
                   b"\x33\x33\x33\x33\x33\x33\x33\x33" \
                   b"\x70\x00\x00\x00" \
                   b"\x01\x00" \
                   b"\x00\x00" \
                   b"\x02\x02" \
                   b"\x10\x02" \
                   b"\x00\x03" \
                   b"\x02\x03" \
                   b"\x11\x03" \
                   b"\x00\x00" \
                   b"\x02\x00\x04\x00\x00\x00\x00\x00" \
                   b"\x01\x00\x02\x00" \
                   b"\x00\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 64
        assert actual == expected

    def test_create_message_one_dialect(self):
        message = SMB3NegotiateRequest()
        message['security_mode'] = SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        message['capabilities'] = 10
        message['client_guid'] = uuid.UUID(bytes=b"\x33" * 16)
        message['dialects'] = [
            Dialects.SMB_3_1_1
        ]
        con_req = SMB2NegotiateContextRequest()
        con_req['context_type'] = \
            NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES

        enc_cap = SMB2EncryptionCapabilities()
        enc_cap['ciphers'] = [Ciphers.AES_128_GCM]
        con_req['data'] = enc_cap
        message['negotiate_context_list'] = [
            con_req
        ]
        expected = b"\x24\x00" \
                   b"\x01\x00" \
                   b"\x01\x00" \
                   b"\x00\x00" \
                   b"\x0a\x00\x00\x00" \
                   b"\x33\x33\x33\x33\x33\x33\x33\x33" \
                   b"\x33\x33\x33\x33\x33\x33\x33\x33" \
                   b"\x68\x00\x00\x00" \
                   b"\x01\x00" \
                   b"\x00\x00" \
                   b"\x11\x03" \
                   b"\x00\x00" \
                   b"\x02\x00\x04\x00\x00\x00\x00\x00" \
                   b"\x01\x00\x02\x00" \
                   b"\x00\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 56
        assert actual == expected

    def test_parse_message(self):
        actual = SMB3NegotiateRequest()
        data = b"\x24\x00" \
               b"\x05\x00" \
               b"\x01\x00" \
               b"\x00\x00" \
               b"\x0a\x00\x00\x00" \
               b"\x33\x33\x33\x33\x33\x33\x33\x33" \
               b"\x33\x33\x33\x33\x33\x33\x33\x33" \
               b"\x70\x00\x00\x00" \
               b"\x01\x00" \
               b"\x00\x00" \
               b"\x02\x02" \
               b"\x10\x02" \
               b"\x00\x03" \
               b"\x02\x03" \
               b"\x11\x03" \
               b"\x00\x00" \
               b"\x02\x00\x04\x00\x00\x00\x00\x00" \
               b"\x01\x00\x02\x00" \
               b"\x00\x00\x00\x00"
        actual.unpack(data)
        assert len(actual) == 60
        assert actual['structure_size'].get_value() == 36
        assert actual['dialect_count'].get_value() == 5
        assert actual['security_mode'].get_value() == \
            SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        assert actual['reserved'].get_value() == 0
        assert actual['capabilities'].get_value() == 10
        assert actual['client_guid'].get_value() == \
            uuid.UUID(bytes=b"\x33" * 16)
        assert actual['negotiate_context_offset'].get_value() == 112
        assert actual['negotiate_context_count'].get_value() == 1
        assert actual['reserved2'].get_value() == 0
        assert actual['dialects'].get_value() == [
            Dialects.SMB_2_0_2,
            Dialects.SMB_2_1_0,
            Dialects.SMB_3_0_0,
            Dialects.SMB_3_0_2,
            Dialects.SMB_3_1_1
        ]
        assert actual['padding'].get_value() == b"\x00\x00"

        assert len(actual['negotiate_context_list'].get_value()) == 1
        neg_con = actual['negotiate_context_list'][0]
        assert isinstance(neg_con, SMB2NegotiateContextRequest)
        assert len(neg_con) == 12
        assert neg_con['context_type'].get_value() == \
            NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES
        assert neg_con['data_length'].get_value() == 4
        assert neg_con['reserved'].get_value() == 0
        assert isinstance(neg_con['data'].get_value(),
                          SMB2EncryptionCapabilities)
        assert neg_con['data']['cipher_count'].get_value() == 1
        assert neg_con['data']['ciphers'].get_value() == [Ciphers.AES_128_GCM]


class TestSMB2NegotiateContextRequest(object):

    def test_create_message(self):
        message = SMB2NegotiateContextRequest()
        message['context_type'] = \
            NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES

        enc_cap = SMB2EncryptionCapabilities()
        enc_cap['ciphers'] = [Ciphers.AES_128_GCM]
        message['data'] = enc_cap
        expected = b"\x02\x00" \
                   b"\x04\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x01\x00" \
                   b"\x02\x00" \
                   b"\x00\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 16
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2NegotiateContextRequest()
        data = b"\x02\x00" \
               b"\x04\x00" \
               b"\x00\x00\x00\x00" \
               b"\x01\x00" \
               b"\x02\x00"
        actual.unpack(data)
        assert len(actual) == 12
        assert actual['context_type'].get_value() == \
            NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES
        assert actual['data_length'].get_value() == 4
        assert actual['reserved'].get_value() == 0
        assert isinstance(actual['data'].get_value(),
                          SMB2EncryptionCapabilities)
        assert actual['data']['cipher_count'].get_value() == 1
        assert actual['data']['ciphers'].get_value() == [Ciphers.AES_128_GCM]

    def test_parse_message_invalid_context_type(self):
        actual = SMB2NegotiateContextRequest()
        data = b"\x03\x00" \
               b"\x04\x00" \
               b"\x00\x00\x00\x00" \
               b"\x01\x00" \
               b"\x02\x00"
        with pytest.raises(Exception) as exc:
            actual.unpack(data)
        assert str(exc.value) == "Enum value 3 does not exist in enum type " \
                                 "<class 'smbprotocol.constants." \
                                 "NegotiateContextType'>"


class TestSMB2PreauthIntegrityCapabilities(object):

    def test_create_message(self):
        message = SMB2PreauthIntegrityCapabilities()
        message['hash_algorithms'] = [
            HashAlgorithms.SHA_512
        ]
        message['salt'] = b"\x01" * 16
        expected = b"\x01\x00" \
                   b"\x10\x00" \
                   b"\x01\x00" \
                   b"\x01\x01\x01\x01\x01\x01\x01\x01" \
                   b"\x01\x01\x01\x01\x01\x01\x01\x01"
        actual = message.pack()
        assert len(message) == 22
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2PreauthIntegrityCapabilities()
        data = b"\x01\x00" \
               b"\x10\x00" \
               b"\x01\x00" \
               b"\x01\x01\x01\x01\x01\x01\x01\x01" \
               b"\x01\x01\x01\x01\x01\x01\x01\x01"
        actual.unpack(data)
        assert len(actual) == 22
        assert actual['hash_algorithm_count'].get_value() == 1
        assert actual['salt_length'].get_value() == 16
        assert actual['hash_algorithms'].get_value() == [
            HashAlgorithms.SHA_512
        ]
        assert actual['salt'].get_value() == b"\x01" * 16


class TestSMB2EncryptionCapabilities(object):

    def test_create_message(self):
        message = SMB2EncryptionCapabilities()
        message['ciphers'] = [
            Ciphers.AES_128_CCM,
            Ciphers.AES_128_GCM
        ]
        expected = b"\x02\x00" \
                   b"\x01\x00" \
                   b"\x02\x00"
        actual = message.pack()
        assert len(message) == 6
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2EncryptionCapabilities()
        data = b"\x02\x00" \
               b"\x01\x00" \
               b"\x02\x00"
        actual.unpack(data)
        assert len(actual) == 6
        assert actual['cipher_count'].get_value() == 2
        assert actual['ciphers'].get_value() == [
            Ciphers.AES_128_CCM,
            Ciphers.AES_128_GCM
        ]


class TestSMB2NegotiateResponse(object):

    def test_create_message(self):
        message = SMB2NegotiateResponse()
        message['security_mode'] = SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        message['dialect_revision'] = Dialects.SMB_3_0_2
        message['server_guid'] = uuid.UUID(bytes=b"\x11" * 16)
        message['capabilities'] = 39
        message['max_transact_size'] = 8388608
        message['max_read_size'] = 8388608
        message['max_write_size'] = 8388608
        message['system_time'] = datetime(
            year=2017, month=11, day=15, hour=11, minute=32, second=12,
            microsecond=1616)
        message['server_start_time'] = datetime(
            year=2017, month=11, day=15, hour=11, minute=27, second=26,
            microsecond=349606)
        message['buffer'] = b"\x01\x02\x03\x04\x05\x06\x07\x08" \
                            b"\x09\x10"

        expected = b"\x41\x00" \
                   b"\x01\x00" \
                   b"\x02\x03" \
                   b"\x00\x00" \
                   b"\x11\x11\x11\x11\x11\x11\x11\x11" \
                   b"\x11\x11\x11\x11\x11\x11\x11\x11" \
                   b"\x27\x00\x00\x00" \
                   b"\x00\x00\x80\x00" \
                   b"\x00\x00\x80\x00" \
                   b"\x00\x00\x80\x00" \
                   b"\x20\xc5\x0d\x61\x05\x5e\xd3\x01" \
                   b"\x7c\xbb\xca\xb6\x04\x5e\xd3\x01" \
                   b"\x80\x00" \
                   b"\x0a\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x01\x02\x03\x04\x05\x06\x07\x08" \
                   b"\x09\x10"
        actual = message.pack()
        assert len(message) == 74
        assert actual == expected

    def test_create_message_3_1_1(self):
        message = SMB2NegotiateResponse()
        message['security_mode'] = SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        message['dialect_revision'] = Dialects.SMB_3_1_1
        message['server_guid'] = uuid.UUID(bytes=b"\x11" * 16)
        message['capabilities'] = 39
        message['max_transact_size'] = 8388608
        message['max_read_size'] = 8388608
        message['max_write_size'] = 8388608
        message['system_time'] = datetime(
            year=2017, month=11, day=15, hour=11, minute=32, second=12,
            microsecond=1616)
        message['server_start_time'] = datetime(
            year=2017, month=11, day=15, hour=11, minute=27, second=26,
            microsecond=349606)
        message['buffer'] = b"\x01\x02\x03\x04\x05\x06\x07\x08" \
                            b"\x09\x10"

        int_cap = SMB2PreauthIntegrityCapabilities()
        int_cap['hash_algorithms'] = [HashAlgorithms.SHA_512]
        int_cap['salt'] = b"\x22" * 32

        negotiate_context = SMB2NegotiateContextRequest()
        negotiate_context['context_type'] = \
            NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES
        negotiate_context['data'] = int_cap

        message['negotiate_context_list'] = [negotiate_context]
        expected = b"\x41\x00" \
                   b"\x01\x00" \
                   b"\x11\x03" \
                   b"\x01\x00" \
                   b"\x11\x11\x11\x11\x11\x11\x11\x11" \
                   b"\x11\x11\x11\x11\x11\x11\x11\x11" \
                   b"\x27\x00\x00\x00" \
                   b"\x00\x00\x80\x00" \
                   b"\x00\x00\x80\x00" \
                   b"\x00\x00\x80\x00" \
                   b"\x20\xc5\x0d\x61\x05\x5e\xd3\x01" \
                   b"\x7c\xbb\xca\xb6\x04\x5e\xd3\x01" \
                   b"\x80\x00" \
                   b"\x0a\x00" \
                   b"\x90\x00\x00\x00" \
                   b"\x01\x02\x03\x04\x05\x06\x07\x08" \
                   b"\x09\x10" \
                   b"\x00\x00\x00\x00\x00\x00" \
                   b"\x01\x00\x26\x00\x00\x00\x00\x00" \
                   b"\x01\x00\x20\x00\x01\x00\x22\x22" \
                   b"\x22\x22\x22\x22\x22\x22\x22\x22" \
                   b"\x22\x22\x22\x22\x22\x22\x22\x22" \
                   b"\x22\x22\x22\x22\x22\x22\x22\x22" \
                   b"\x22\x22\x22\x22\x22\x22" \
                   b"\x00\x00"
        actual = message.pack()
        assert len(message) == 128
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2NegotiateResponse()
        data = b"\x41\x00" \
               b"\x01\x00" \
               b"\x02\x03" \
               b"\x00\x00" \
               b"\x11\x11\x11\x11\x11\x11\x11\x11" \
               b"\x11\x11\x11\x11\x11\x11\x11\x11" \
               b"\x67\x00\x00\x00" \
               b"\x00\x00\x80\x00" \
               b"\x00\x00\x80\x00" \
               b"\x00\x00\x80\x00" \
               b"\x14\x85\x12\x8b\xc2\x5e\xd3\x01" \
               b"\x04\x88\x4d\x21\xc2\x5e\xd3\x01" \
               b"\x80\x00" \
               b"\x78\x00" \
               b"\x00\x00\x00\x00" \
               b"\x60\x76\x06\x06\x2b\x06\x01\x05" \
               b"\x05\x02\xa0\x6c\x30\x6a\xa0\x3c" \
               b"\x30\x3a\x06\x0a\x2b\x06\x01\x04" \
               b"\x01\x82\x37\x02\x02\x1e\x06\x09" \
               b"\x2a\x86\x48\x82\xf7\x12\x01\x02" \
               b"\x02\x06\x09\x2a\x86\x48\x86\xf7" \
               b"\x12\x01\x02\x02\x06\x0a\x2a\x86" \
               b"\x48\x86\xf7\x12\x01\x02\x02\x03" \
               b"\x06\x0a\x2b\x06\x01\x04\x01\x82" \
               b"\x37\x02\x02\x0a\xa3\x2a\x30\x28" \
               b"\xa0\x26\x1b\x24\x6e\x6f\x74\x5f" \
               b"\x64\x65\x66\x69\x6e\x65\x64\x5f" \
               b"\x69\x6e\x5f\x52\x46\x43\x34\x31" \
               b"\x37\x38\x40\x70\x6c\x65\x61\x73" \
               b"\x65\x5f\x69\x67\x6e\x6f\x72\x65"
        actual.unpack(data)

        assert len(actual) == 184
        assert actual['structure_size'].get_value() == 65

        assert actual['security_mode'].get_value() == \
            SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        assert actual['dialect_revision'].get_value() == Dialects.SMB_3_0_2
        assert actual['negotiate_context_count'].get_value() == 0
        assert actual['server_guid'].get_value() == uuid.UUID(
            bytes=b"\x11" * 16)
        assert actual['capabilities'].get_value() == 103
        assert actual['max_transact_size'].get_value() == 8388608
        assert actual['max_read_size'].get_value() == 8388608
        assert actual['max_write_size'].get_value() == 8388608
        assert actual['system_time'].get_value() == datetime(
            year=2017, month=11, day=16, hour=10, minute=6, second=17,
            microsecond=378946)
        assert actual['server_start_time'].get_value() == datetime(
            year=2017, month=11, day=16, hour=10, minute=3, second=19,
            microsecond=927194)
        assert actual['security_buffer_offset'].get_value() == 128
        assert actual['security_buffer_length'].get_value() == 120
        assert actual['negotiate_context_offset'].get_value() == 0
        assert isinstance(actual['buffer'].get_value(), bytes)
        assert len(actual['buffer']) == 120
        assert actual['padding'].get_value() == b""
        assert actual['negotiate_context_list'].get_value() == []

    def test_parse_message_3_1_1(self):
        actual = SMB2NegotiateResponse()
        data = b"\x41\x00" \
               b"\x01\x00" \
               b"\x11\x03" \
               b"\x01\x00" \
               b"\x11\x11\x11\x11\x11\x11\x11\x11" \
               b"\x11\x11\x11\x11\x11\x11\x11\x11" \
               b"\x27\x00\x00\x00" \
               b"\x00\x00\x80\x00" \
               b"\x00\x00\x80\x00" \
               b"\x00\x00\x80\x00" \
               b"\x24\xc5\x0d\x61\x05\x5e\xd3\x01" \
               b"\x7f\xbb\xca\xb6\x04\x5e\xd3\x01" \
               b"\x80\x00" \
               b"\x78\x00" \
               b"\xf8\x00\x00\x00" \
               b"\x60\x76\x06\x06\x2b\x06\x01\x05" \
               b"\x05\x02\xa0\x6c\x30\x6a\xa0\x3c" \
               b"\x30\x3a\x06\x0a\x2b\x06\x01\x04" \
               b"\x01\x82\x37\x02\x02\x1e\x06\x09" \
               b"\x2a\x86\x48\x82\xf7\x12\x01\x02" \
               b"\x02\x06\x09\x2a\x86\x48\x86\xf7" \
               b"\x12\x01\x02\x02\x06\x0a\x2a\x86" \
               b"\x48\x86\xf7\x12\x01\x02\x02\x03" \
               b"\x06\x0a\x2b\x06\x01\x04\x01\x82" \
               b"\x37\x02\x02\x0a\xa3\x2a\x30\x28" \
               b"\xa0\x26\x1b\x24\x6e\x6f\x74\x5f" \
               b"\x64\x65\x66\x69\x6e\x65\x64\x5f" \
               b"\x69\x6e\x5f\x52\x46\x43\x34\x31" \
               b"\x37\x38\x40\x70\x6c\x65\x61\x73" \
               b"\x65\x5f\x69\x67\x6e\x6f\x72\x65" \
               b"" \
               b"\x01\x00\x26\x00\x00\x00\x00\x00" \
               b"\x01\x00\x20\x00\x01\x00\x22\x22" \
               b"\x22\x22\x22\x22\x22\x22\x22\x22" \
               b"\x22\x22\x22\x22\x22\x22\x22\x22" \
               b"\x22\x22\x22\x22\x22\x22\x22\x22" \
               b"\x22\x22\x22\x22\x22\x22"
        actual.unpack(data)

        assert len(actual) == 230
        assert actual['structure_size'].get_value() == 65

        assert actual['security_mode'].get_value() == \
            SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        assert actual['dialect_revision'].get_value() == Dialects.SMB_3_1_1
        assert actual['negotiate_context_count'].get_value() == 1
        assert actual['server_guid'].get_value() == uuid.UUID(
            bytes=b"\x11" * 16)
        assert actual['capabilities'].get_value() == 39
        assert actual['max_transact_size'].get_value() == 8388608
        assert actual['max_read_size'].get_value() == 8388608
        assert actual['max_write_size'].get_value() == 8388608
        assert actual['system_time'].get_value() == datetime(
            year=2017, month=11, day=15, hour=11, minute=32, second=12,
            microsecond=1616)
        assert actual['server_start_time'].get_value() == datetime(
            year=2017, month=11, day=15, hour=11, minute=27, second=26,
            microsecond=349606)
        assert actual['security_buffer_offset'].get_value() == 128
        assert actual['security_buffer_length'].get_value() == 120
        assert actual['negotiate_context_offset'].get_value() == 248
        assert isinstance(actual['buffer'].get_value(), bytes)
        assert len(actual['buffer']) == 120
        assert actual['padding'].get_value() == b""

        assert isinstance(actual['negotiate_context_list'].get_value(), list)
        assert len(actual['negotiate_context_list'].get_value()) == 1

        neg_context = actual['negotiate_context_list'].get_value()[0]
        assert isinstance(neg_context, SMB2NegotiateContextRequest)
        assert neg_context['context_type'].get_value() == \
            NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES
        assert neg_context['data_length'].get_value() == 38
        assert neg_context['reserved'].get_value() == 0

        preauth_cap = neg_context['data']
        assert preauth_cap['hash_algorithm_count'].get_value() == 1
        assert preauth_cap['salt_length'].get_value() == 32
        assert preauth_cap['hash_algorithms'].get_value() == [
            HashAlgorithms.SHA_512
        ]
        assert preauth_cap['salt'].get_value() == b"\x22" * 32


class TestSMB2SessionSetupRequest(object):

    def test_create_message(self):
        message = SMB2SessionSetupRequest()
        message['security_mode'] = SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        message['buffer'] = b"\x01\x02\x03\x04"
        expected = b"\x19\x00" \
                   b"\x00" \
                   b"\x01" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x58\x00" \
                   b"\x04\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x01\x02\x03\x04"
        actual = message.pack()
        assert len(message) == 28
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2SessionSetupRequest()
        data = b"\x19\x00" \
               b"\x00" \
               b"\x01" \
               b"\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x58\x00" \
               b"\x04\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x01\x02\x03\x04"
        actual.unpack(data)
        assert len(actual) == 28
        assert actual['structure_size'].get_value() == 25
        assert actual['flags'].get_value() == 0
        assert actual['security_mode'].get_value() == 1
        assert actual['capabilities'].get_value() == 0
        assert actual['security_buffer_offset'].get_value() == 88
        assert actual['security_buffer_length'].get_value() == 4
        assert actual['previous_session_id'].get_value() == 0
        assert actual['buffer'].get_value() == b"\x01\x02\x03\x04"


class TestSMB2SessionSetupResponse(object):

    def test_create_message(self):
        message = SMB2SessionSetupResponse()
        message['session_flags'] = 1
        message['buffer'] = b"\x04\x03\x02\x01"
        expected = b"\x09\x00" \
                   b"\x01\x00" \
                   b"\x48\x00" \
                   b"\x04\x00" \
                   b"\x04\x03\x02\x01"
        actual = message.pack()
        assert len(message) == 12
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2SessionSetupResponse()
        data = b"\x09\x00" \
               b"\x01\x00" \
               b"\x48\x00" \
               b"\x04\x00" \
               b"\x04\x03\x02\x01"
        actual.unpack(data)
        assert len(actual) == 12
        assert actual['structure_size'].get_value() == 9
        assert actual['session_flags'].get_value() == 1
        assert actual['security_buffer_offset'].get_value() == 72
        assert actual['security_buffer_length'].get_value() == 4
        assert actual['buffer'].get_value() == b"\x04\x03\x02\x01"


class TestSMB2Logoff(object):

    def test_create_message(self):
        message = SMB2Logoff()
        expected = b"\x04\x00" \
                   b"\x00\x00"
        actual = message.pack()
        assert len(message) == 4
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2Logoff()
        data = b"\x04\x00" \
               b"\x00\x00"
        actual.unpack(data)
        assert len(actual) == 4
        assert actual['structure_size'].get_value() == 4
        assert actual['reserved'].get_value() == 0


class TestSMB2TreeConnectRequest(object):

    def test_create_message(self):
        message = SMB2TreeConnectRequest()
        message['flags'] = 2
        message['buffer'] = "\\\\127.0.0.1\\c$".encode("utf-16-le")
        expected = b"\x09\x00" \
                   b"\x02\x00" \
                   b"\x48\x00" \
                   b"\x1c\x00" \
                   b"\x5c\x00\x5c\x00\x31\x00\x32\x00" \
                   b"\x37\x00\x2e\x00\x30\x00\x2e\x00" \
                   b"\x30\x00\x2e\x00\x31\x00\x5c\x00" \
                   b"\x63\x00\x24\x00"
        actual = message.pack()
        assert len(message) == 36
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2TreeConnectRequest()
        data = b"\x09\x00" \
               b"\x02\x00" \
               b"\x48\x00" \
               b"\x1c\x00" \
               b"\x5c\x00\x5c\x00\x31\x00\x32\x00" \
               b"\x37\x00\x2e\x00\x30\x00\x2e\x00" \
               b"\x30\x00\x2e\x00\x31\x00\x5c\x00" \
               b"\x63\x00\x24\x00"
        actual.unpack(data)
        assert len(actual) == 36
        assert actual['structure_size'].get_value() == 9
        assert actual['flags'].get_value() == 2
        assert actual['path_offset'].get_value() == 72
        assert actual['path_length'].get_value() == 28
        assert actual['buffer'].get_value() == "\\\\127.0.0.1\\c$"\
            .encode("utf-16-le")


class TestSMB2TreeConnectResponse(object):

    def test_create_message(self):
        message = SMB2TreeConnectResponse()
        message['share_type'] = 1
        message['share_flags'] = 2
        message['capabilities'] = 8
        message['maximal_access'] = 10
        expected = b"\x10\x00" \
                   b"\x01" \
                   b"\x00" \
                   b"\x02\x00\x00\x00" \
                   b"\x08\x00\x00\x00" \
                   b"\x0a\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 16
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2TreeConnectResponse()
        data = b"\x10\x00" \
               b"\x01" \
               b"\x00" \
               b"\x02\x00\x00\x00" \
               b"\x08\x00\x00\x00" \
               b"\x0a\x00\x00\x00"
        actual.unpack(data)
        assert len(actual) == 16
        assert actual['structure_size'].get_value() == 16
        assert actual['share_type'].get_value() == 1
        assert actual['reserved'].get_value() == 0
        assert actual['share_flags'].get_value() == 2
        assert actual['capabilities'].get_value() == 8
        assert actual['maximal_access'].get_value() == 10


class TestSMB2TreeDisconnect(object):

    def test_create_message(self):
        message = SMB2TreeDisconnect()
        expected = b"\x04\x00" \
                   b"\x00\x00"
        actual = message.pack()
        assert len(message) == 4
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2TreeDisconnect()
        data = b"\x04\x00" \
               b"\x00\x00"
        actual.unpack(data)
        assert len(actual) == 4
        assert actual['structure_size'].get_value() == 4
        assert actual['reserved'].get_value() == 0


class TestSMB2IOCTLRequest(object):

    def test_create_message(self):
        message = SMB2IOCTLRequest()
        message['ctl_code'] = CtlCode.FSCTL_VALIDATE_NEGOTIATE_INFO
        message['file_id'] = b"\xff" * 16
        message['max_input_response'] = 12
        message['max_output_response'] = 12
        message['flags'] = IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL
        message['buffer'] = b"\x12\x13\x14\x15"
        expected = b"\x39\x00" \
                   b"\x00\x00" \
                   b"\x04\x02\x14\x00" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\x78\x00\x00\x00" \
                   b"\x04\x00\x00\x00" \
                   b"\x0c\x00\x00\x00" \
                   b"\x78\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x0c\x00\x00\x00" \
                   b"\x01\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x12\x13\x14\x15"
        actual = message.pack()
        assert len(message) == 60
        assert actual == expected

    def test_create_message_no_buffer(self):
        message = SMB2IOCTLRequest()
        message['ctl_code'] = CtlCode.FSCTL_VALIDATE_NEGOTIATE_INFO
        message['file_id'] = b"\xff" * 16
        message['flags'] = IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL
        expected = b"\x39\x00" \
                   b"\x00\x00" \
                   b"\x04\x02\x14\x00" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x01\x00\x00\x00" \
                   b"\x00\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 56
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2IOCTLRequest()
        data = b"\x39\x00" \
               b"\x00\x00" \
               b"\x04\x02\x14\x00" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\x78\x00\x00\x00" \
               b"\x04\x00\x00\x00" \
               b"\x0c\x00\x00\x00" \
               b"\x78\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x0c\x00\x00\x00" \
               b"\x01\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x12\x13\x14\x15"
        actual.unpack(data)
        assert len(actual) == 60
        assert actual['structure_size'].get_value() == 57
        assert actual['reserved'].get_value() == 0
        assert actual['ctl_code'].get_value() == \
            CtlCode.FSCTL_VALIDATE_NEGOTIATE_INFO
        assert actual['file_id'].pack() == b"\xff" * 16
        assert actual['input_offset'].get_value() == 120
        assert actual['input_count'].get_value() == 4
        assert actual['max_input_response'].get_value() == 12
        assert actual['output_offset'].get_value() == 120
        assert actual['output_count'].get_value() == 0
        assert actual['max_output_response'].get_value() == 12
        assert actual['flags'].get_value() == IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL
        assert actual['reserved2'].get_value() == 0
        assert actual['buffer'].get_value() == b"\x12\x13\x14\x15"


class TestSMB2ValidateNegotiateInfoRequest(object):

    def test_create_message(self):
        message = SMB2ValidateNegotiateInfoRequest()
        message['capabilities'] = 8
        message['guid'] = b"\x11" * 16
        message['security_mode'] = 1
        message['dialect_count'] = 2
        message['dialects'] = [Dialects.SMB_2_0_2, Dialects.SMB_2_1_0]
        expected = b"\x08\x00\x00\x00" \
                   b"\x11\x11\x11\x11\x11\x11\x11\x11" \
                   b"\x11\x11\x11\x11\x11\x11\x11\x11" \
                   b"\x01\x00" \
                   b"\x02\x00" \
                   b"\x02\x02\x10\x02"
        actual = message.pack()
        assert len(message) == 28
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2ValidateNegotiateInfoRequest()
        data = b"\x08\x00\x00\x00" \
               b"\x11\x11\x11\x11\x11\x11\x11\x11" \
               b"\x11\x11\x11\x11\x11\x11\x11\x11" \
               b"\x01\x00" \
               b"\x02\x00" \
               b"\x02\x02\x10\x02"
        actual.unpack(data)
        assert len(actual) == 28
        assert actual['capabilities'].get_value() == 8
        assert actual['guid'].get_value() == uuid.UUID(bytes=b"\x11" * 16)
        assert actual['security_mode'].get_value() == 1
        assert actual['dialect_count'].get_value() == 2
        assert actual['dialects'][0] == 514
        assert actual['dialects'][1] == 528
        assert len(actual['dialects'].get_value()) == 2


class TestSMB2IOCTLResponse(object):

    def test_create_message(self):
        message = SMB2IOCTLResponse()
        message['ctl_code'] = CtlCode.FSCTL_VALIDATE_NEGOTIATE_INFO
        message['file_id'] = b"\xff" * 16
        message['input_offset'] = 0
        message['input_count'] = 0
        message['output_offset'] = 112
        message['output_count'] = 4
        message['flags'] = IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL
        message['buffer'] = b"\x20\x21\x22\x23"
        expected = b"\x31\x00\x00\x00" \
                   b"\x04\x02\x14\x00" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x70\x00\x00\x00" \
                   b"\x04\x00\x00\x00" \
                   b"\x01\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x20\x21\x22\x23"
        actual = message.pack()
        assert len(message) == 52
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2IOCTLResponse()
        data = b"\x31\x00\x00\x00" \
               b"\x04\x02\x14\x00" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x70\x00\x00\x00" \
               b"\x04\x00\x00\x00" \
               b"\x01\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x20\x21\x22\x23"
        actual.unpack(data)
        assert len(actual) == 52
        assert actual['structure_size'].get_value() == 49
        assert actual['reserved'].get_value() == 0
        assert actual['ctl_code'].get_value() == \
            CtlCode.FSCTL_VALIDATE_NEGOTIATE_INFO
        assert actual['file_id'].pack() == b"\xff" * 16
        assert actual['input_offset'].get_value() == 0
        assert actual['input_count'].get_value() == 0
        assert actual['output_offset'].get_value() == 112
        assert actual['output_count'].get_value() == 4
        assert actual['flags'].get_value() == IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL
        assert actual['reserved2'].get_value() == 0
        assert actual['buffer'].get_value() == b"\x20\x21\x22\x23"


class TestSMB2ValidateNegotiateInfoResponse(object):

    def test_create_message(self):
        message = SMB2ValidateNegotiateInfoResponse()
        message['capabilities'] = 8
        message['guid'] = b"\xff" * 16
        message['security_mode'] = 0
        message['dialect'] = Dialects.SMB_3_0_2
        expected = b"\x08\x00\x00\x00" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\x00\x00" \
                   b"\x02\x03"
        actual = message.pack()
        assert len(message) == 24
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2ValidateNegotiateInfoResponse()
        data = b"\x08\x00\x00\x00" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\x00\x00" \
               b"\x02\x03"
        actual.unpack(data)
        assert len(actual) == 24
        assert actual['capabilities'].get_value() == 8
        assert actual['guid'].get_value() == uuid.UUID(bytes=b"\xff" * 16)
        assert actual['security_mode'].get_value() == 0
        assert actual['dialect'].get_value() == Dialects.SMB_3_0_2


class TestSMB2TransformHeader(object):

    def test_create_message(self):
        message = SMB2TransformHeader()
        message['nonce'] = b"\xff" * 16
        message['original_message_size'] = 4
        message['session_id'] = 1
        message['data'] = b"\x01\x02\x03\x04"
        expected = b"\xfd\x53\x4d\x42" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\x04\x00\x00\x00" \
                   b"\x00\x00" \
                   b"\x01\x00" \
                   b"\x01\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x01\x02\x03\x04"
        actual = message.pack()
        assert len(message) == 56
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2TransformHeader()
        data = b"\xfd\x53\x4d\x42" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\x04\x00\x00\x00" \
               b"\x00\x00" \
               b"\x01\x00" \
               b"\x01\x00\x00\x00\x00\x00\x00\x00" \
               b"\x01\x02\x03\x04"
        actual.unpack(data)
        assert len(actual) == 56
        assert actual['protocol_id'].get_value() == b"\xfd\x53\x4d\x42"
        assert actual['signature'].get_value() == b"\x00" * 16
        assert actual['nonce'].get_value() == b"\xff" * 16
        assert actual['original_message_size'].get_value() == 4
        assert actual['reserved'].get_value() == 0
        assert actual['flags'].get_value() == 1
        assert actual['session_id'].get_value() == 1
        assert actual['data'].get_value() == b"\x01\x02\x03\x04"
