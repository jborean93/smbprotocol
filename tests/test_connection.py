# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os
import threading
import uuid
from datetime import datetime, timezone

import pytest

from smbprotocol import Dialects
from smbprotocol.connection import (
    Ciphers,
    Connection,
    HashAlgorithms,
    NegotiateContextType,
    Request,
    SecurityMode,
    SigningAlgorithms,
    SMB2CancelRequest,
    SMB2Echo,
    SMB2EncryptionCapabilities,
    SMB2NegotiateContextRequest,
    SMB2NegotiateRequest,
    SMB2NegotiateResponse,
    SMB2NetnameNegotiateContextId,
    SMB2PreauthIntegrityCapabilities,
    SMB2SigningCapabilities,
    SMB2TransformHeader,
    SMB3NegotiateRequest,
)
from smbprotocol.exceptions import SMBConnectionClosed, SMBException
from smbprotocol.header import Smb2Flags, SMB2HeaderResponse
from smbprotocol.ioctl import SMB2IOCTLRequest
from smbprotocol.session import Session


@pytest.fixture
def connected_session(smb_real):
    """
    Return a (connection, session) tuple that is already connected to the
    SMB server and that will disconnect at the end.
    """
    connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
    connection.connect()
    session = Session(connection, smb_real[0], smb_real[1])
    session.connect()

    yield connection, session

    connection.disconnect(True)


class TestSMB2NegotiateRequest:
    def test_create_message(self):
        message = SMB2NegotiateRequest()
        message["security_mode"] = SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        message["capabilities"] = 10
        message["client_guid"] = uuid.UUID(bytes=b"\x33" * 16)
        message["dialects"] = [Dialects.SMB_2_0_2, Dialects.SMB_2_1_0, Dialects.SMB_3_0_0, Dialects.SMB_3_0_2]
        expected = (
            b"\x24\x00"
            b"\x04\x00"
            b"\x01\x00"
            b"\x00\x00"
            b"\x0a\x00\x00\x00"
            b"\x33\x33\x33\x33\x33\x33\x33\x33"
            b"\x33\x33\x33\x33\x33\x33\x33\x33"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x02\x02"
            b"\x10\x02"
            b"\x00\x03"
            b"\x02\x03"
        )
        actual = message.pack()
        assert len(message) == 44
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2NegotiateRequest()
        data = (
            b"\x24\x00"
            b"\x04\x00"
            b"\x01\x00"
            b"\x00\x00"
            b"\x0a\x00\x00\x00"
            b"\x33\x33\x33\x33\x33\x33\x33\x33"
            b"\x33\x33\x33\x33\x33\x33\x33\x33"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x02\x02"
            b"\x10\x02"
            b"\x00\x03"
            b"\x02\x03"
        )
        actual.unpack(data)
        assert len(actual) == 44
        assert actual["structure_size"].get_value() == 36
        assert actual["dialect_count"].get_value() == 4
        assert actual["security_mode"].get_value() == SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        assert actual["reserved"].get_value() == 0
        assert actual["capabilities"].get_value() == 10
        assert actual["client_guid"].get_value() == uuid.UUID(bytes=b"\x33" * 16)
        assert actual["client_start_time"].get_value() == 0
        assert actual["dialects"].get_value() == [
            Dialects.SMB_2_0_2,
            Dialects.SMB_2_1_0,
            Dialects.SMB_3_0_0,
            Dialects.SMB_3_0_2,
        ]


class TestSMB3NegotiateRequest:
    def test_create_message(self):
        message = SMB3NegotiateRequest()
        message["security_mode"] = SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        message["capabilities"] = 10
        message["client_guid"] = uuid.UUID(bytes=b"\x33" * 16)
        message["dialects"] = [
            Dialects.SMB_2_0_2,
            Dialects.SMB_2_1_0,
            Dialects.SMB_3_0_0,
            Dialects.SMB_3_0_2,
            Dialects.SMB_3_1_1,
        ]
        con_req = SMB2NegotiateContextRequest()
        con_req["context_type"] = NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES

        enc_cap = SMB2EncryptionCapabilities()
        enc_cap["ciphers"] = [Ciphers.AES_128_GCM]
        con_req["data"] = enc_cap

        netname = SMB2NegotiateContextRequest()
        netname["context_type"] = NegotiateContextType.SMB2_NETNAME_NEGOTIATE_CONTEXT_ID
        netname["data"] = SMB2NetnameNegotiateContextId()
        netname["data"]["net_name"] = "café"

        message["negotiate_context_list"] = [
            con_req,
            netname,
        ]
        expected = (
            b"\x24\x00"
            b"\x05\x00"
            b"\x01\x00"
            b"\x00\x00"
            b"\x0a\x00\x00\x00"
            b"\x33\x33\x33\x33\x33\x33\x33\x33"
            b"\x33\x33\x33\x33\x33\x33\x33\x33"
            b"\x70\x00\x00\x00"
            b"\x02\x00"
            b"\x00\x00"
            b"\x02\x02"
            b"\x10\x02"
            b"\x00\x03"
            b"\x02\x03"
            b"\x11\x03"
            b"\x00\x00"
            b"\x02\x00\x04\x00\x00\x00\x00\x00"
            b"\x01\x00\x02\x00"
            b"\x00\x00\x00\x00"
            b"\x05\x00\x08\x00\x00\x00\x00\x00"
            b"\x63\x00\x61\x00\x66\x00\xe9\x00"
        )

        actual = message.pack()
        assert len(message) == 80
        assert actual == expected

    def test_create_message_one_dialect(self):
        message = SMB3NegotiateRequest()
        message["security_mode"] = SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        message["capabilities"] = 10
        message["client_guid"] = uuid.UUID(bytes=b"\x33" * 16)
        message["dialects"] = [Dialects.SMB_3_1_1]
        con_req = SMB2NegotiateContextRequest()
        con_req["context_type"] = NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES

        enc_cap = SMB2EncryptionCapabilities()
        enc_cap["ciphers"] = [Ciphers.AES_128_GCM]
        con_req["data"] = enc_cap
        message["negotiate_context_list"] = [con_req]
        expected = (
            b"\x24\x00"
            b"\x01\x00"
            b"\x01\x00"
            b"\x00\x00"
            b"\x0a\x00\x00\x00"
            b"\x33\x33\x33\x33\x33\x33\x33\x33"
            b"\x33\x33\x33\x33\x33\x33\x33\x33"
            b"\x68\x00\x00\x00"
            b"\x01\x00"
            b"\x00\x00"
            b"\x11\x03"
            b"\x00\x00"
            b"\x02\x00\x04\x00\x00\x00\x00\x00"
            b"\x01\x00\x02\x00"
            b"\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 56
        assert actual == expected

    def test_parse_message(self):
        actual = SMB3NegotiateRequest()
        data = (
            b"\x24\x00"
            b"\x05\x00"
            b"\x01\x00"
            b"\x00\x00"
            b"\x0a\x00\x00\x00"
            b"\x33\x33\x33\x33\x33\x33\x33\x33"
            b"\x33\x33\x33\x33\x33\x33\x33\x33"
            b"\x70\x00\x00\x00"
            b"\x02\x00"
            b"\x00\x00"
            b"\x02\x02"
            b"\x10\x02"
            b"\x00\x03"
            b"\x02\x03"
            b"\x11\x03"
            b"\x00\x00"
            b"\x02\x00\x04\x00\x00\x00\x00\x00"
            b"\x01\x00\x02\x00"
            b"\x00\x00\x00\x00"
            b"\x05\x00\x08\x00\x00\x00\x00\x00"
            b"\x63\x00\x61\x00\x66\x00\xe9\x00"
        )

        actual.unpack(data)
        assert len(actual) == 76
        assert actual["structure_size"].get_value() == 36
        assert actual["dialect_count"].get_value() == 5
        assert actual["security_mode"].get_value() == SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        assert actual["reserved"].get_value() == 0
        assert actual["capabilities"].get_value() == 10
        assert actual["client_guid"].get_value() == uuid.UUID(bytes=b"\x33" * 16)
        assert actual["negotiate_context_offset"].get_value() == 112
        assert actual["negotiate_context_count"].get_value() == 2
        assert actual["reserved2"].get_value() == 0
        assert actual["dialects"].get_value() == [
            Dialects.SMB_2_0_2,
            Dialects.SMB_2_1_0,
            Dialects.SMB_3_0_0,
            Dialects.SMB_3_0_2,
            Dialects.SMB_3_1_1,
        ]
        assert actual["padding"].get_value() == b"\x00\x00"

        assert len(actual["negotiate_context_list"].get_value()) == 2
        neg_con = actual["negotiate_context_list"][0]
        assert isinstance(neg_con, SMB2NegotiateContextRequest)
        assert len(neg_con) == 12
        assert neg_con["context_type"].get_value() == NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES
        assert neg_con["data_length"].get_value() == 4
        assert neg_con["reserved"].get_value() == 0
        assert isinstance(neg_con["data"].get_value(), SMB2EncryptionCapabilities)
        assert neg_con["data"]["cipher_count"].get_value() == 1
        assert neg_con["data"]["ciphers"].get_value() == [Ciphers.AES_128_GCM]

        net_name = actual["negotiate_context_list"][1]
        assert isinstance(net_name, SMB2NegotiateContextRequest)
        assert len(net_name) == 16
        assert net_name["context_type"].get_value() == NegotiateContextType.SMB2_NETNAME_NEGOTIATE_CONTEXT_ID
        assert net_name["data_length"].get_value() == 8
        assert net_name["reserved"].get_value() == 0
        assert isinstance(net_name["data"].get_value(), SMB2NetnameNegotiateContextId)
        assert net_name["data"]["net_name"].get_value() == "café"

    def test_create_message_with_context_no_padding(self):
        message = SMB3NegotiateRequest()
        message["security_mode"] = SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED
        message["capabilities"] = 69
        message["client_guid"] = uuid.UUID(bytes=b"\x33" * 16)
        message["dialects"] = [Dialects.SMB_3_1_1]

        preauth_req = SMB2NegotiateContextRequest()
        preauth_req["context_type"] = NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES
        preauth = SMB2PreauthIntegrityCapabilities()
        preauth["hash_algorithms"] = [HashAlgorithms.SHA_512]
        preauth["salt"] = b"\x11" * 32
        preauth_req["data"] = preauth

        enc_cap_req = SMB2NegotiateContextRequest()
        enc_cap_req["context_type"] = NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES
        enc_cap = SMB2EncryptionCapabilities()
        enc_cap["ciphers"] = [Ciphers.AES_128_GCM, Ciphers.AES_128_CCM]
        enc_cap_req["data"] = enc_cap

        netname_req = SMB2NegotiateContextRequest()
        netname_req["context_type"] = NegotiateContextType.SMB2_NETNAME_NEGOTIATE_CONTEXT_ID
        netname = SMB2NetnameNegotiateContextId()
        netname["net_name"] = "testing1"  # Length is specific to test no padding needed
        netname_req["data"] = netname

        signing_req = SMB2NegotiateContextRequest()
        signing_req["context_type"] = NegotiateContextType.SMB2_SIGNING_CAPABILITIES
        signing = SMB2SigningCapabilities()
        signing["signing_algorithms"] = [
            SigningAlgorithms.AES_GMAC,
            SigningAlgorithms.AES_CMAC,
            SigningAlgorithms.HMAC_SHA256,
        ]
        signing_req["data"] = signing

        message["negotiate_context_list"] = [preauth_req, enc_cap_req, netname_req, signing_req]

        expected = (
            b"\x24\x00"
            b"\x01\x00"
            b"\x02\x00"
            b"\x00\x00"
            b"\x45\x00\x00\x00"
            b"\x33\x33\x33\x33\x33\x33\x33\x33"
            b"\x33\x33\x33\x33\x33\x33\x33\x33"
            b"\x68\x00\x00\x00"
            b"\x04\x00"
            b"\x00\x00"
            b"\x11\x03"
            b"\x00\x00"
            b"\x01\x00\x26\x00\x00\x00\x00\x00"
            b"\x01\x00\x20\x00\x01\x00\x11\x11"
            b"\x11\x11\x11\x11\x11\x11\x11\x11"
            b"\x11\x11\x11\x11\x11\x11\x11\x11"
            b"\x11\x11\x11\x11\x11\x11\x11\x11"
            b"\x11\x11\x11\x11\x11\x11\x00\x00"
            b"\x02\x00\x06\x00\x00\x00\x00\x00"
            b"\x02\x00\x02\x00\x01\x00\x00\x00"
            b"\x05\x00\x10\x00\x00\x00\x00\x00"
            b"\x74\x00\x65\x00\x73\x00\x74\x00"
            b"\x69\x00\x6e\x00\x67\x00\x31\x00"
            b"\x08\x00\x08\x00\x00\x00\x00\x00"
            b"\x03\x00\x02\x00\x01\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 144
        assert actual == expected

    def test_parse_message_with_context_no_padding(self):
        actual = SMB3NegotiateRequest()
        data = (
            b"\x24\x00"
            b"\x01\x00"
            b"\x02\x00"
            b"\x00\x00"
            b"\x45\x00\x00\x00"
            b"\x33\x33\x33\x33\x33\x33\x33\x33"
            b"\x33\x33\x33\x33\x33\x33\x33\x33"
            b"\x68\x00\x00\x00"
            b"\x04\x00"
            b"\x00\x00"
            b"\x11\x03"
            b"\x00\x00"
            b"\x01\x00\x26\x00\x00\x00\x00\x00"
            b"\x01\x00\x20\x00\x01\x00\x11\x11"
            b"\x11\x11\x11\x11\x11\x11\x11\x11"
            b"\x11\x11\x11\x11\x11\x11\x11\x11"
            b"\x11\x11\x11\x11\x11\x11\x11\x11"
            b"\x11\x11\x11\x11\x11\x11\x00\x00"
            b"\x02\x00\x06\x00\x00\x00\x00\x00"
            b"\x02\x00\x02\x00\x01\x00\x00\x00"
            b"\x05\x00\x10\x00\x00\x00\x00\x00"
            b"\x74\x00\x65\x00\x73\x00\x74\x00"
            b"\x69\x00\x6e\x00\x67\x00\x31\x00"
            b"\x08\x00\x08\x00\x00\x00\x00\x00"
            b"\x03\x00\x02\x00\x01\x00\x00\x00"
        )
        actual.unpack(data)
        assert len(actual) == 140
        assert actual["structure_size"].get_value() == 36
        assert actual["dialect_count"].get_value() == 1
        assert actual["security_mode"].get_value() == SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED
        assert actual["reserved"].get_value() == 0
        assert actual["capabilities"].get_value() == 69
        assert actual["client_guid"].get_value() == uuid.UUID(bytes=b"\x33" * 16)
        assert actual["negotiate_context_offset"].get_value() == 104
        assert actual["negotiate_context_count"].get_value() == 4
        assert actual["reserved2"].get_value() == 0
        assert actual["dialects"].get_value() == [
            Dialects.SMB_3_1_1,
        ]
        assert actual["padding"].get_value() == b"\x00\x00"

        assert len(actual["negotiate_context_list"].get_value()) == 4

        preauth = actual["negotiate_context_list"][0]
        assert isinstance(preauth, SMB2NegotiateContextRequest)
        assert len(preauth) == 46
        assert preauth["context_type"].get_value() == NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES
        assert preauth["data_length"].get_value() == 38
        assert preauth["reserved"].get_value() == 0
        assert isinstance(preauth["data"].get_value(), SMB2PreauthIntegrityCapabilities)
        assert preauth["data"]["hash_algorithm_count"].get_value() == 1
        assert preauth["data"]["salt_length"].get_value() == 32
        assert preauth["data"]["hash_algorithms"].get_value() == [HashAlgorithms.SHA_512]
        assert preauth["data"]["salt"].get_value() == b"\x11" * 32

        enc_cap = actual["negotiate_context_list"][1]
        assert isinstance(enc_cap, SMB2NegotiateContextRequest)
        assert len(enc_cap) == 14
        assert enc_cap["context_type"].get_value() == NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES
        assert enc_cap["data_length"].get_value() == 6
        assert enc_cap["reserved"].get_value() == 0
        assert isinstance(enc_cap["data"].get_value(), SMB2EncryptionCapabilities)
        assert enc_cap["data"]["cipher_count"].get_value() == 2
        assert enc_cap["data"]["ciphers"].get_value() == [Ciphers.AES_128_GCM, Ciphers.AES_128_CCM]

        netname = actual["negotiate_context_list"][2]
        assert isinstance(netname, SMB2NegotiateContextRequest)
        assert len(netname) == 24
        assert netname["context_type"].get_value() == NegotiateContextType.SMB2_NETNAME_NEGOTIATE_CONTEXT_ID
        assert netname["data_length"].get_value() == 16
        assert netname["reserved"].get_value() == 0
        assert isinstance(netname["data"].get_value(), SMB2NetnameNegotiateContextId)
        assert netname["data"]["net_name"].get_value() == "testing1"

        signing = actual["negotiate_context_list"][3]
        assert isinstance(signing, SMB2NegotiateContextRequest)
        assert len(signing) == 16
        assert signing["context_type"].get_value() == NegotiateContextType.SMB2_SIGNING_CAPABILITIES
        assert signing["data_length"].get_value() == 8
        assert signing["reserved"].get_value() == 0
        assert isinstance(signing["data"].get_value(), SMB2SigningCapabilities)
        assert signing["data"]["signing_algorithm_count"].get_value() == 3
        assert signing["data"]["signing_algorithms"].get_value() == [
            SigningAlgorithms.AES_GMAC,
            SigningAlgorithms.AES_CMAC,
            SigningAlgorithms.HMAC_SHA256,
        ]


class TestSMB2NegotiateContextRequest:
    def test_create_message(self):
        message = SMB2NegotiateContextRequest()
        message["context_type"] = NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES

        enc_cap = SMB2EncryptionCapabilities()
        enc_cap["ciphers"] = [Ciphers.AES_128_GCM]
        message["data"] = enc_cap
        expected = b"\x02\x00" b"\x04\x00" b"\x00\x00\x00\x00" b"\x01\x00" b"\x02\x00" b"\x00\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 16
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2NegotiateContextRequest()
        data = b"\x02\x00" b"\x04\x00" b"\x00\x00\x00\x00" b"\x01\x00" b"\x02\x00"
        actual.unpack(data)
        assert len(actual) == 12
        assert actual["context_type"].get_value() == NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES
        assert actual["data_length"].get_value() == 4
        assert actual["reserved"].get_value() == 0
        assert isinstance(actual["data"].get_value(), SMB2EncryptionCapabilities)
        assert actual["data"]["cipher_count"].get_value() == 1
        assert actual["data"]["ciphers"].get_value() == [Ciphers.AES_128_GCM]

    def test_parse_message_invalid_context_type(self):
        actual = SMB2NegotiateContextRequest()
        data = b"\xFF\xFF" b"\x04\x00" b"\x00\x00\x00\x00" b"\x01\x00" b"\x02\x00"
        with pytest.raises(Exception) as exc:
            actual.unpack(data)
        assert (
            str(exc.value) == "Enum value 65535 does not exist in enum type "
            "<class 'smbprotocol.connection."
            "NegotiateContextType'>"
        )


class TestSMB2PreauthIntegrityCapabilities:
    def test_create_message(self):
        message = SMB2PreauthIntegrityCapabilities()
        message["hash_algorithms"] = [HashAlgorithms.SHA_512]
        message["salt"] = b"\x01" * 16
        expected = (
            b"\x01\x00" b"\x10\x00" b"\x01\x00" b"\x01\x01\x01\x01\x01\x01\x01\x01" b"\x01\x01\x01\x01\x01\x01\x01\x01"
        )
        actual = message.pack()
        assert len(message) == 22
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2PreauthIntegrityCapabilities()
        data = (
            b"\x01\x00" b"\x10\x00" b"\x01\x00" b"\x01\x01\x01\x01\x01\x01\x01\x01" b"\x01\x01\x01\x01\x01\x01\x01\x01"
        )
        actual.unpack(data)
        assert len(actual) == 22
        assert actual["hash_algorithm_count"].get_value() == 1
        assert actual["salt_length"].get_value() == 16
        assert actual["hash_algorithms"].get_value() == [HashAlgorithms.SHA_512]
        assert actual["salt"].get_value() == b"\x01" * 16


class TestSMB2EncryptionCapabilities:
    def test_create_message(self):
        message = SMB2EncryptionCapabilities()
        message["ciphers"] = [Ciphers.AES_128_CCM, Ciphers.AES_128_GCM]
        expected = b"\x02\x00" b"\x01\x00" b"\x02\x00"
        actual = message.pack()
        assert len(message) == 6
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2EncryptionCapabilities()
        data = b"\x02\x00" b"\x01\x00" b"\x02\x00"
        actual.unpack(data)
        assert len(actual) == 6
        assert actual["cipher_count"].get_value() == 2
        assert actual["ciphers"].get_value() == [Ciphers.AES_128_CCM, Ciphers.AES_128_GCM]


class TestSMB2NetnameNegotiateContextId:
    def test_create_message(self):
        message = SMB2NetnameNegotiateContextId()
        message["net_name"] = "hostname"
        expected = b"\x68\x00\x6F\x00\x73\x00\x74\x00" b"\x6E\x00\x61\x00\x6D\x00\x65\x00"
        actual = message.pack()
        assert len(message) == 16
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2NetnameNegotiateContextId()
        data = b"\x68\x00\x6F\x00\x73\x00\x74\x00" b"\x6E\x00\x61\x00\x6D\x00\x65\x00"
        actual.unpack(data)
        assert len(actual) == 16
        assert actual["net_name"].get_value() == "hostname"


class TestSMB2SigningCapabilities:
    def test_create_message(self):
        message = SMB2SigningCapabilities()
        message["signing_algorithms"] = [
            SigningAlgorithms.AES_GMAC,
            SigningAlgorithms.AES_CMAC,
            SigningAlgorithms.HMAC_SHA256,
        ]
        expected = b"\x03\x00" b"\x02\x00" b"\x01\x00" b"\x00\x00"
        actual = message.pack()
        assert len(message) == 8
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2SigningCapabilities()
        data = b"\x03\x00" b"\x02\x00" b"\x01\x00" b"\x00\x00"
        actual.unpack(data)
        assert len(actual) == 8
        assert actual["signing_algorithms"].get_value() == [
            SigningAlgorithms.AES_GMAC,
            SigningAlgorithms.AES_CMAC,
            SigningAlgorithms.HMAC_SHA256,
        ]


class TestSMB2NegotiateResponse:
    def test_create_message(self):
        message = SMB2NegotiateResponse()
        message["security_mode"] = SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        message["dialect_revision"] = Dialects.SMB_3_0_2
        message["server_guid"] = uuid.UUID(bytes=b"\x11" * 16)
        message["capabilities"] = 39
        message["max_transact_size"] = 8388608
        message["max_read_size"] = 8388608
        message["max_write_size"] = 8388608
        message["system_time"] = datetime(year=2017, month=11, day=15, hour=11, minute=32, second=12, microsecond=1616)
        message["server_start_time"] = datetime(
            year=2017, month=11, day=15, hour=11, minute=27, second=26, microsecond=349606
        )
        message["buffer"] = b"\x01\x02\x03\x04\x05\x06\x07\x08" b"\x09\x10"

        expected = (
            b"\x41\x00"
            b"\x01\x00"
            b"\x02\x03"
            b"\x00\x00"
            b"\x11\x11\x11\x11\x11\x11\x11\x11"
            b"\x11\x11\x11\x11\x11\x11\x11\x11"
            b"\x27\x00\x00\x00"
            b"\x00\x00\x80\x00"
            b"\x00\x00\x80\x00"
            b"\x00\x00\x80\x00"
            b"\x20\xc5\x0d\x61\x05\x5e\xd3\x01"
            b"\x7c\xbb\xca\xb6\x04\x5e\xd3\x01"
            b"\x80\x00"
            b"\x0a\x00"
            b"\x00\x00\x00\x00"
            b"\x01\x02\x03\x04\x05\x06\x07\x08"
            b"\x09\x10"
        )
        actual = message.pack()
        assert len(message) == 74
        assert actual == expected

    def test_create_message_3_1_1(self):
        message = SMB2NegotiateResponse()
        message["security_mode"] = SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        message["dialect_revision"] = Dialects.SMB_3_1_1
        message["server_guid"] = uuid.UUID(bytes=b"\x11" * 16)
        message["capabilities"] = 39
        message["max_transact_size"] = 8388608
        message["max_read_size"] = 8388608
        message["max_write_size"] = 8388608
        message["system_time"] = datetime(year=2017, month=11, day=15, hour=11, minute=32, second=12, microsecond=1616)
        message["server_start_time"] = datetime(
            year=2017, month=11, day=15, hour=11, minute=27, second=26, microsecond=349606
        )
        message["buffer"] = b"\x01\x02\x03\x04\x05\x06\x07\x08" b"\x09\x10"

        int_cap = SMB2PreauthIntegrityCapabilities()
        int_cap["hash_algorithms"] = [HashAlgorithms.SHA_512]
        int_cap["salt"] = b"\x22" * 32

        negotiate_context = SMB2NegotiateContextRequest()
        negotiate_context["context_type"] = NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES
        negotiate_context["data"] = int_cap

        message["negotiate_context_list"] = [negotiate_context]
        expected = (
            b"\x41\x00"
            b"\x01\x00"
            b"\x11\x03"
            b"\x01\x00"
            b"\x11\x11\x11\x11\x11\x11\x11\x11"
            b"\x11\x11\x11\x11\x11\x11\x11\x11"
            b"\x27\x00\x00\x00"
            b"\x00\x00\x80\x00"
            b"\x00\x00\x80\x00"
            b"\x00\x00\x80\x00"
            b"\x20\xc5\x0d\x61\x05\x5e\xd3\x01"
            b"\x7c\xbb\xca\xb6\x04\x5e\xd3\x01"
            b"\x80\x00"
            b"\x0a\x00"
            b"\x90\x00\x00\x00"
            b"\x01\x02\x03\x04\x05\x06\x07\x08"
            b"\x09\x10"
            b"\x00\x00\x00\x00\x00\x00"
            b"\x01\x00\x26\x00\x00\x00\x00\x00"
            b"\x01\x00\x20\x00\x01\x00\x22\x22"
            b"\x22\x22\x22\x22\x22\x22\x22\x22"
            b"\x22\x22\x22\x22\x22\x22\x22\x22"
            b"\x22\x22\x22\x22\x22\x22\x22\x22"
            b"\x22\x22\x22\x22\x22\x22"
            b"\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 128
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2NegotiateResponse()
        data = (
            b"\x41\x00"
            b"\x01\x00"
            b"\x02\x03"
            b"\x00\x00"
            b"\x11\x11\x11\x11\x11\x11\x11\x11"
            b"\x11\x11\x11\x11\x11\x11\x11\x11"
            b"\x67\x00\x00\x00"
            b"\x00\x00\x80\x00"
            b"\x00\x00\x80\x00"
            b"\x00\x00\x80\x00"
            b"\x14\x85\x12\x8b\xc2\x5e\xd3\x01"
            b"\x04\x88\x4d\x21\xc2\x5e\xd3\x01"
            b"\x80\x00"
            b"\x78\x00"
            b"\x00\x00\x00\x00"
            b"\x60\x76\x06\x06\x2b\x06\x01\x05"
            b"\x05\x02\xa0\x6c\x30\x6a\xa0\x3c"
            b"\x30\x3a\x06\x0a\x2b\x06\x01\x04"
            b"\x01\x82\x37\x02\x02\x1e\x06\x09"
            b"\x2a\x86\x48\x82\xf7\x12\x01\x02"
            b"\x02\x06\x09\x2a\x86\x48\x86\xf7"
            b"\x12\x01\x02\x02\x06\x0a\x2a\x86"
            b"\x48\x86\xf7\x12\x01\x02\x02\x03"
            b"\x06\x0a\x2b\x06\x01\x04\x01\x82"
            b"\x37\x02\x02\x0a\xa3\x2a\x30\x28"
            b"\xa0\x26\x1b\x24\x6e\x6f\x74\x5f"
            b"\x64\x65\x66\x69\x6e\x65\x64\x5f"
            b"\x69\x6e\x5f\x52\x46\x43\x34\x31"
            b"\x37\x38\x40\x70\x6c\x65\x61\x73"
            b"\x65\x5f\x69\x67\x6e\x6f\x72\x65"
        )
        actual.unpack(data)

        assert len(actual) == 184
        assert actual["structure_size"].get_value() == 65

        assert actual["security_mode"].get_value() == SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        assert actual["dialect_revision"].get_value() == Dialects.SMB_3_0_2
        assert actual["negotiate_context_count"].get_value() == 0
        assert actual["server_guid"].get_value() == uuid.UUID(bytes=b"\x11" * 16)
        assert actual["capabilities"].get_value() == 103
        assert actual["max_transact_size"].get_value() == 8388608
        assert actual["max_read_size"].get_value() == 8388608
        assert actual["max_write_size"].get_value() == 8388608
        assert actual["system_time"].get_value() == datetime(
            year=2017,
            month=11,
            day=16,
            hour=10,
            minute=6,
            second=17,
            microsecond=378946,
            tzinfo=timezone.utc,
        )
        assert actual["server_start_time"].get_value() == datetime(
            year=2017,
            month=11,
            day=16,
            hour=10,
            minute=3,
            second=19,
            microsecond=927194,
            tzinfo=timezone.utc,
        )
        assert actual["security_buffer_offset"].get_value() == 128
        assert actual["security_buffer_length"].get_value() == 120
        assert actual["negotiate_context_offset"].get_value() == 0
        assert isinstance(actual["buffer"].get_value(), bytes)
        assert len(actual["buffer"]) == 120
        assert actual["padding"].get_value() == b""
        assert actual["negotiate_context_list"].get_value() == []

    def test_parse_message_3_1_1(self):
        actual = SMB2NegotiateResponse()
        data = (
            b"\x41\x00"
            b"\x01\x00"
            b"\x11\x03"
            b"\x01\x00"
            b"\x11\x11\x11\x11\x11\x11\x11\x11"
            b"\x11\x11\x11\x11\x11\x11\x11\x11"
            b"\x27\x00\x00\x00"
            b"\x00\x00\x80\x00"
            b"\x00\x00\x80\x00"
            b"\x00\x00\x80\x00"
            b"\x24\xc5\x0d\x61\x05\x5e\xd3\x01"
            b"\x7f\xbb\xca\xb6\x04\x5e\xd3\x01"
            b"\x80\x00"
            b"\x78\x00"
            b"\xf8\x00\x00\x00"
            b"\x60\x76\x06\x06\x2b\x06\x01\x05"
            b"\x05\x02\xa0\x6c\x30\x6a\xa0\x3c"
            b"\x30\x3a\x06\x0a\x2b\x06\x01\x04"
            b"\x01\x82\x37\x02\x02\x1e\x06\x09"
            b"\x2a\x86\x48\x82\xf7\x12\x01\x02"
            b"\x02\x06\x09\x2a\x86\x48\x86\xf7"
            b"\x12\x01\x02\x02\x06\x0a\x2a\x86"
            b"\x48\x86\xf7\x12\x01\x02\x02\x03"
            b"\x06\x0a\x2b\x06\x01\x04\x01\x82"
            b"\x37\x02\x02\x0a\xa3\x2a\x30\x28"
            b"\xa0\x26\x1b\x24\x6e\x6f\x74\x5f"
            b"\x64\x65\x66\x69\x6e\x65\x64\x5f"
            b"\x69\x6e\x5f\x52\x46\x43\x34\x31"
            b"\x37\x38\x40\x70\x6c\x65\x61\x73"
            b"\x65\x5f\x69\x67\x6e\x6f\x72\x65"
            b""
            b"\x01\x00\x26\x00\x00\x00\x00\x00"
            b"\x01\x00\x20\x00\x01\x00\x22\x22"
            b"\x22\x22\x22\x22\x22\x22\x22\x22"
            b"\x22\x22\x22\x22\x22\x22\x22\x22"
            b"\x22\x22\x22\x22\x22\x22\x22\x22"
            b"\x22\x22\x22\x22\x22\x22"
        )
        actual.unpack(data)

        assert len(actual) == 230
        assert actual["structure_size"].get_value() == 65

        assert actual["security_mode"].get_value() == SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        assert actual["dialect_revision"].get_value() == Dialects.SMB_3_1_1
        assert actual["negotiate_context_count"].get_value() == 1
        assert actual["server_guid"].get_value() == uuid.UUID(bytes=b"\x11" * 16)
        assert actual["capabilities"].get_value() == 39
        assert actual["max_transact_size"].get_value() == 8388608
        assert actual["max_read_size"].get_value() == 8388608
        assert actual["max_write_size"].get_value() == 8388608
        assert actual["system_time"].get_value() == datetime(
            year=2017,
            month=11,
            day=15,
            hour=11,
            minute=32,
            second=12,
            microsecond=1616,
            tzinfo=timezone.utc,
        )
        assert actual["server_start_time"].get_value() == datetime(
            year=2017,
            month=11,
            day=15,
            hour=11,
            minute=27,
            second=26,
            microsecond=349606,
            tzinfo=timezone.utc,
        )
        assert actual["security_buffer_offset"].get_value() == 128
        assert actual["security_buffer_length"].get_value() == 120
        assert actual["negotiate_context_offset"].get_value() == 248
        assert isinstance(actual["buffer"].get_value(), bytes)
        assert len(actual["buffer"]) == 120
        assert actual["padding"].get_value() == b""

        assert isinstance(actual["negotiate_context_list"].get_value(), list)
        assert len(actual["negotiate_context_list"].get_value()) == 1

        neg_context = actual["negotiate_context_list"].get_value()[0]
        assert isinstance(neg_context, SMB2NegotiateContextRequest)
        assert neg_context["context_type"].get_value() == NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES
        assert neg_context["data_length"].get_value() == 38
        assert neg_context["reserved"].get_value() == 0

        preauth_cap = neg_context["data"]
        assert preauth_cap["hash_algorithm_count"].get_value() == 1
        assert preauth_cap["salt_length"].get_value() == 32
        assert preauth_cap["hash_algorithms"].get_value() == [HashAlgorithms.SHA_512]
        assert preauth_cap["salt"].get_value() == b"\x22" * 32


class TestSMB2Echo:
    def test_create_message(self):
        message = SMB2Echo()
        expected = b"\x04\x00" b"\x00\x00"
        actual = message.pack()
        assert len(message) == 4
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2Echo()
        data = b"\x04\x00" b"\x00\x00"
        data = actual.unpack(data)
        assert len(actual) == 4
        assert data == b""
        assert actual["structure_size"].get_value() == 4
        assert actual["reserved"].get_value() == 0


class TestSMB2CancelRequest:
    DATA = b"\x04\x00" b"\x00\x00"

    def test_create_message(self):
        message = SMB2CancelRequest()
        actual = message.pack()
        assert len(message) == 4
        assert actual == self.DATA

    def test_parse_message(self):
        actual = SMB2CancelRequest()
        assert actual.unpack(self.DATA) == b""
        assert len(actual) == 4
        assert actual["structure_size"].get_value() == 4
        assert actual["reserved"].get_value() == 0


class TestSMB2TransformHeader:
    def test_create_message(self):
        message = SMB2TransformHeader()
        message["nonce"] = b"\xff" * 16
        message["original_message_size"] = 4
        message["session_id"] = 1
        message["data"] = b"\x01\x02\x03\x04"
        expected = (
            b"\xfd\x53\x4d\x42"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x04\x00\x00\x00"
            b"\x00\x00"
            b"\x01\x00"
            b"\x01\x00\x00\x00\x00\x00\x00\x00"
            b"\x01\x02\x03\x04"
        )
        actual = message.pack()
        assert len(message) == 56
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2TransformHeader()
        data = (
            b"\xfd\x53\x4d\x42"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\x04\x00\x00\x00"
            b"\x00\x00"
            b"\x01\x00"
            b"\x01\x00\x00\x00\x00\x00\x00\x00"
            b"\x01\x02\x03\x04"
        )
        actual.unpack(data)
        assert len(actual) == 56
        assert actual["protocol_id"].get_value() == b"\xfd\x53\x4d\x42"
        assert actual["signature"].get_value() == b"\x00" * 16
        assert actual["nonce"].get_value() == b"\xff" * 16
        assert actual["original_message_size"].get_value() == 4
        assert actual["reserved"].get_value() == 0
        assert actual["flags"].get_value() == 1
        assert actual["session_id"].get_value() == 1
        assert actual["data"].get_value() == b"\x01\x02\x03\x04"


class TestConnection:
    def test_dialect_2_0_2(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_2_0_2)
        try:
            assert connection.dialect == Dialects.SMB_2_0_2
            assert connection.negotiated_dialects == [Dialects.SMB_2_0_2]
            assert connection.gss_negotiate_token is not None
            assert len(connection.preauth_integrity_hash_value) == 2
            assert len(connection.salt) == 32
            assert connection.sequence_window["low"] == 1
            assert connection.sequence_window["high"] == 2
            assert connection.client_security_mode == SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED
            assert not connection.supports_encryption
            assert connection.require_signing
        finally:
            connection.disconnect()

    def test_dialect_2_1_0(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_2_1_0)
        try:
            assert connection.dialect == Dialects.SMB_2_1_0
            assert connection.negotiated_dialects == [Dialects.SMB_2_1_0]
            assert connection.gss_negotiate_token is not None
            assert len(connection.preauth_integrity_hash_value) == 2
            assert len(connection.salt) == 32
            assert connection.sequence_window["low"] == 1
            assert connection.sequence_window["high"] == 2
            assert connection.client_security_mode == SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED
            assert not connection.supports_encryption
            assert connection.require_signing
        finally:
            connection.disconnect()

    def test_dialect_3_0_0(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_0_0)
        try:
            assert connection.dialect == Dialects.SMB_3_0_0
            assert connection.negotiated_dialects == [Dialects.SMB_3_0_0]
            assert connection.gss_negotiate_token is not None
            assert len(connection.preauth_integrity_hash_value) == 2
            assert len(connection.salt) == 32
            assert connection.sequence_window["low"] == 1
            assert connection.sequence_window["high"] == 2
            assert connection.client_security_mode == SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED
            assert connection.supports_encryption
            assert connection.require_signing
        finally:
            connection.disconnect()

    def test_dialect_3_0_2(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_0_2)
        try:
            assert connection.dialect == Dialects.SMB_3_0_2
            assert connection.negotiated_dialects == [Dialects.SMB_3_0_2]
            assert connection.gss_negotiate_token is not None
            assert len(connection.preauth_integrity_hash_value) == 2
            assert len(connection.salt) == 32
            assert connection.sequence_window["low"] == 1
            assert connection.sequence_window["high"] == 2
            assert connection.client_security_mode == SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED
            assert connection.supports_encryption
            assert connection.require_signing
        finally:
            connection.disconnect()

    def test_dialect_3_1_1_not_require_signing(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3], False)
        connection.connect(Dialects.SMB_3_1_1)
        try:
            assert connection.dialect == Dialects.SMB_3_1_1
            assert connection.negotiated_dialects == [Dialects.SMB_3_1_1]
            assert connection.gss_negotiate_token is not None
            assert len(connection.preauth_integrity_hash_value) == 2
            assert len(connection.salt) == 32
            assert connection.sequence_window["low"] == 1
            assert connection.sequence_window["high"] == 2
            assert connection.client_security_mode == SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
            assert connection.supports_encryption

            if connection.server_security_mode & SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED:
                assert connection.require_signing
            else:
                assert not connection.require_signing
        finally:
            connection.disconnect()

    def test_dialect_implicit_require_signing(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3], True)
        connection.connect()
        try:
            assert connection.dialect == Dialects.SMB_3_1_1
            assert connection.negotiated_dialects == [
                Dialects.SMB_2_0_2,
                Dialects.SMB_2_1_0,
                Dialects.SMB_3_0_0,
                Dialects.SMB_3_0_2,
                Dialects.SMB_3_1_1,
            ]
            assert connection.gss_negotiate_token is not None
            assert len(connection.preauth_integrity_hash_value) == 2
            assert len(connection.salt) == 32
            assert connection.sequence_window["low"] == 1
            assert connection.sequence_window["high"] == 2
            assert connection.client_security_mode == SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED
            assert connection.supports_encryption
            assert connection.require_signing
        finally:
            connection.disconnect()

    def test_verify_message_skip(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3], True)
        connection.connect()
        try:
            header = SMB2HeaderResponse()
            header["message_id"] = 0xFFFFFFFFFFFFFFFF
            connection.verify_signature(header, 0)
        finally:
            connection.disconnect()

    def test_broken_message_worker_closed_socket(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3], True)
        connection.connect()
        try:
            test_msg = SMB2NegotiateRequest()
            test_req = Request(test_msg, type(test_msg), connection)
            connection.outstanding_requests[666] = test_req

            # Close the connection manually
            connection.transport.close()

            with pytest.raises(SMBConnectionClosed):
                connection.receive(test_req)

            with pytest.raises(SMBConnectionClosed):
                connection.send(SMB2NegotiateRequest())
        finally:
            connection.disconnect()

    def test_broken_message_worker_exception(self, mocker):
        connection = Connection(uuid.uuid4(), "server", 445, True)

        mock_transport = mocker.MagicMock()
        connection.transport = mock_transport
        connection.transport.recv.side_effect = Exception("test")
        connection._process_message_thread()

        with pytest.raises(Exception, match="test"):
            connection.send(SMB2Echo())

        with pytest.raises(Exception, match="test"):
            connection.receive(None)

    def test_message_worker_timeout(self, mocker):
        connection = Connection(uuid.uuid4(), "server", 445, True)

        connection.session_table[1] = mocker.MagicMock()

        mock_send = mocker.MagicMock()
        connection.send = mock_send

        mock_transport = mocker.MagicMock()
        connection.transport = mock_transport
        connection.transport.recv.side_effect = (TimeoutError, b"")

        # Not the best test but better than waiting 10 minutes for the socket to timeout.
        connection._process_message_thread()

        assert mock_send.call_count == 1
        assert isinstance(mock_send.call_args[0][0], SMB2Echo)
        assert mock_send.call_args[1] == {"sid": 1}

    def test_message_worker_timeout_connection_dead(self, mocker):
        connection = Connection(uuid.uuid4(), "server", 445, True)
        connection.dialect = Dialects.SMB_2_1_0

        mock_session = mocker.MagicMock()
        mock_session.session_id = 1
        mock_session.signing_key = b"test"
        mock_session.encryption_key = b"\x00" * 16
        connection.session_table[mock_session.session_id] = mock_session

        mock_transport = mocker.MagicMock()
        connection.transport = mock_transport
        connection.transport.recv.side_effect = (TimeoutError, TimeoutError)

        mock_disconnect = mocker.MagicMock()
        connection.disconnect = mock_disconnect

        # Not the best test but better than waiting 10 minutes for the socket to timeout.
        connection._process_message_thread()

        # First timeout: keepalive echo sent
        assert mock_transport.send.call_count == 1
        assert mock_transport.send.call_args[0][0]["session_id"].get_value() == mock_session.session_id

        # Second timeout: close connection
        assert mock_disconnect.call_count == 1
        with pytest.raises(SMBConnectionClosed):
            connection.receive(None)

    def test_verify_fail_no_session(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3], True)
        connection.connect()
        try:
            header = SMB2HeaderResponse()
            header["message_id"] = 1
            header["flags"].set_flag(Smb2Flags.SMB2_FLAGS_SIGNED)
            with pytest.raises(SMBException) as exc:
                connection.verify_signature(header, 100)
            assert str(exc.value) == "Failed to find session 100 for message verification"
        finally:
            connection.disconnect()

    def test_verify_mistmatch(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3], True)
        session = Session(connection, smb_real[0], smb_real[1])
        connection.connect()
        try:
            session.connect()
            b_header = connection.preauth_integrity_hash_value[-2]
            header = SMB2HeaderResponse()
            header.unpack(b_header)
            # just set some random values for verification failure
            header["flags"].set_flag(Smb2Flags.SMB2_FLAGS_SIGNED)
            header["signature"] = b"\xff" * 16
            with pytest.raises(SMBException) as exc:
                connection.verify_signature(header, list(connection.session_table.keys())[0], force=True)
            assert "Server message signature could not be verified:" in str(exc.value)
        finally:
            connection.disconnect(True)

    def test_decrypt_invalid_flag(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3], True)
        session = Session(connection, smb_real[0], smb_real[1])
        connection.connect()
        try:
            session.connect()
            # just get some random message
            b_header = connection.preauth_integrity_hash_value[-1]
            header = SMB2HeaderResponse()
            header.unpack(b_header)
            enc_header = connection._encrypt(header.pack(), session)
            assert isinstance(enc_header, SMB2TransformHeader)
            enc_header["flags"] = 5
            with pytest.raises(SMBException) as exc:
                connection._decrypt(enc_header)
            assert str(exc.value) == "Expecting flag of 0x0001 but got 5 in the SMB Transform Header Response"
        finally:
            connection.disconnect(True)

    def test_decrypt_invalid_session_id(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3], True)
        session = Session(connection, smb_real[0], smb_real[1])
        connection.connect()
        try:
            session.connect()
            # just get some random message
            b_header = connection.preauth_integrity_hash_value[-1]
            header = SMB2HeaderResponse()
            header.unpack(b_header)
            enc_header = connection._encrypt(header.pack(), session)
            assert isinstance(enc_header, SMB2TransformHeader)
            enc_header["session_id"] = 100
            with pytest.raises(SMBException) as exc:
                connection._decrypt(enc_header)
            assert str(exc.value) == "Failed to find valid session 100 for message decryption"
        finally:
            connection.disconnect(True)

    def test_requested_credits_greater_than_available(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3], True)
        connection.connect()
        try:
            msg = SMB2IOCTLRequest()
            msg["max_output_response"] = 65538  # results in 2 credits required
            with pytest.raises(SMBException) as exc:
                connection.send(msg, None, None, 0)
            assert str(exc.value) == "Request requires 2 credits but only 1 credits are available"
        finally:
            connection.disconnect()

    def test_send_invalid_tree_id(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        session = Session(connection, smb_real[0], smb_real[1])
        connection.connect()
        try:
            session.connect()
            msg = SMB2IOCTLRequest()
            msg["file_id"] = b"\xff" * 16
            with pytest.raises(SMBException) as exc:
                connection.send(msg, session.session_id, 10)
            assert str(exc.value) == "Cannot find Tree with the ID 10 in the session tree table"
        finally:
            connection.disconnect()

    def test_connection_echo(self, smb_real):
        """
        SMB2 Echo can be used to request extra credits from the server.
        """
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()
        session = Session(connection, smb_real[0], smb_real[1])
        session.connect()
        try:
            actual = connection.echo(sid=session.session_id, credit_request=2)
            assert actual == 2
        finally:
            connection.disconnect(True)

    @pytest.mark.parametrize(
        "key, cipher, signature, data",
        [
            (
                b"\xff" * 16,
                Ciphers.AES_128_CCM,
                b"\xc8\x73\x0c\x9b\xa7\xe5\x9f\x1c\xfd\x37\x51\xa1\x95\xf2\xb3\xac",
                b"\x21\x91\xe3\x0e",
            ),
            (
                b"\xff" * 32,
                Ciphers.AES_256_CCM,
                b"\x3E\xFB\x47\x97\x51\x8A\xAB\x05\xC5\x48\xA7\xFC\x20\x74\xF5\x93",
                b"\x2F\x58\x41\xD7",
            ),
        ],
        ids=["AES128_CCM", "AES256_CCM"],
    )
    def test_encrypt_ccm(self, key, cipher, signature, data, monkeypatch):
        def mockurandom(length):
            return b"\xff" * length

        monkeypatch.setattr(os, "urandom", mockurandom)

        connection = Connection(uuid.uuid4(), "server", 445)
        connection.dialect = Dialects.SMB_3_1_1
        connection.cipher_id = cipher
        session = Session(connection, "user", "pass")
        session.session_id = 1
        session.encryption_key = key

        expected = SMB2TransformHeader()
        expected["signature"] = signature
        expected["nonce"] = b"\xff" * 11 + b"\x00" * 5
        expected["original_message_size"] = 4
        expected["flags"] = 1
        expected["session_id"] = 1
        expected["data"] = data

        actual = connection._encrypt(b"\x01\x02\x03\x04", session)
        assert isinstance(actual, SMB2TransformHeader)
        assert actual.pack() == expected.pack()

    @pytest.mark.parametrize(
        "key, cipher, signature, data",
        [
            (
                b"\xff" * 16,
                Ciphers.AES_128_GCM,
                b"\x39\xd8\x32\x34\xd7\x53\xd0\x8e\xc0\xfc\xbe\x33\x01\x5f\x19\xbd",
                b"\xda\x26\x57\x33",
            ),
            (
                b"\xff" * 32,
                Ciphers.AES_256_GCM,
                b"\x45\xE5\xB7\x23\x05\x2E\xCA\xD0\x1E\xEF\xAD\x6F\x04\x87\xE3\x2D",
                b"\xBC\x39\xBD\x81",
            ),
        ],
        ids=["AES128_CCM", "AES256_CCM"],
    )
    def test_encrypt_gcm(self, key, cipher, signature, data, monkeypatch):
        def mockurandom(length):
            return b"\xff" * length

        monkeypatch.setattr(os, "urandom", mockurandom)

        connection = Connection(uuid.uuid4(), "server", 445)
        connection.dialect = Dialects.SMB_3_1_1
        connection.cipher_id = cipher
        session = Session(connection, "user", "pass")
        session.session_id = 1
        session.encryption_key = key

        expected = SMB2TransformHeader()
        expected["signature"] = signature
        expected["nonce"] = b"\xff" * 12 + b"\x00" * 4
        expected["original_message_size"] = 4
        expected["flags"] = 1
        expected["session_id"] = 1
        expected["data"] = data

        actual = connection._encrypt(b"\x01\x02\x03\x04", session)
        assert isinstance(actual, SMB2TransformHeader)
        assert actual.pack() == expected.pack()

    def test_connection_echo_more(self, connected_session):
        """
        When requesting more credit from the server, it will return the
        allocated credits.
        """
        connection, session = connected_session

        actual = connection.echo(sid=session.session_id, credit_request=65535)

        assert actual == 8129

    def test_disconnect_wait_for_thread(self, connected_session):
        """
        Disconnect will continue after the message thread is stopped.
        """
        connection, _ = connected_session
        msg_thread = f"msg_worker-{connection.server_name}:{connection.port}"

        current_threads = [t.name for t in threading.enumerate()]
        assert msg_thread in current_threads

        connection.disconnect()

        current_threads = [t.name for t in threading.enumerate()]
        assert msg_thread not in current_threads

    def test_disconnect_already_disconnected(self, connected_session):
        """
        Disconnect can be called multiple times, and is a noop if
        already disconnected.
        """
        connection, _ = connected_session

        connection.disconnect()
        connection.disconnect()
