# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import uuid

import pytest

from smbprotocol import Dialects
from smbprotocol.connection import Connection, SecurityMode
from smbprotocol.exceptions import SMBAuthenticationError, SMBException
from smbprotocol.session import (
    Session,
    SMB2Logoff,
    SMB2SessionSetupRequest,
    SMB2SessionSetupResponse,
)
from smbprotocol.session import spnego as pyspnego


class TestSMB2SessionSetupRequest:
    def test_create_message(self):
        message = SMB2SessionSetupRequest()
        message["security_mode"] = SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        message["buffer"] = b"\x01\x02\x03\x04"
        expected = (
            b"\x19\x00"
            b"\x00"
            b"\x01"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x58\x00"
            b"\x04\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x01\x02\x03\x04"
        )
        actual = message.pack()
        assert len(message) == 28
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2SessionSetupRequest()
        data = (
            b"\x19\x00"
            b"\x00"
            b"\x01"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x58\x00"
            b"\x04\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x01\x02\x03\x04"
        )
        actual.unpack(data)
        assert len(actual) == 28
        assert actual["structure_size"].get_value() == 25
        assert actual["flags"].get_value() == 0
        assert actual["security_mode"].get_value() == 1
        assert actual["capabilities"].get_value() == 0
        assert actual["security_buffer_offset"].get_value() == 88
        assert actual["security_buffer_length"].get_value() == 4
        assert actual["previous_session_id"].get_value() == 0
        assert actual["buffer"].get_value() == b"\x01\x02\x03\x04"


class TestSMB2SessionSetupResponse:
    def test_create_message(self):
        message = SMB2SessionSetupResponse()
        message["session_flags"] = 1
        message["buffer"] = b"\x04\x03\x02\x01"
        expected = b"\x09\x00" b"\x01\x00" b"\x48\x00" b"\x04\x00" b"\x04\x03\x02\x01"
        actual = message.pack()
        assert len(message) == 12
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2SessionSetupResponse()
        data = b"\x09\x00" b"\x01\x00" b"\x48\x00" b"\x04\x00" b"\x04\x03\x02\x01"
        actual.unpack(data)
        assert len(actual) == 12
        assert actual["structure_size"].get_value() == 9
        assert actual["session_flags"].get_value() == 1
        assert actual["security_buffer_offset"].get_value() == 72
        assert actual["security_buffer_length"].get_value() == 4
        assert actual["buffer"].get_value() == b"\x04\x03\x02\x01"


class TestSMB2Logoff:
    def test_create_message(self):
        message = SMB2Logoff()
        expected = b"\x04\x00" b"\x00\x00"
        actual = message.pack()
        assert len(message) == 4
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2Logoff()
        data = b"\x04\x00" b"\x00\x00"
        actual.unpack(data)
        assert len(actual) == 4
        assert actual["structure_size"].get_value() == 4
        assert actual["reserved"].get_value() == 0


class TestSession:
    def test_dialect_2_0_2(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_2_0_2)
        session = Session(connection, smb_real[0], smb_real[1], require_encryption=False)
        try:
            session.connect()
            assert len(session.application_key) == 16
            assert session.decryption_key is None
            assert not session.encrypt_data
            assert session.encryption_key is None
            assert len(session.connection.preauth_integrity_hash_value) == 2
            assert len(session.preauth_integrity_hash_value) == 3
            assert not session.require_encryption
            assert session.session_id is not None
            assert session.session_key == session.application_key
            assert session.signing_key == session.signing_key
            assert session.signing_required
        finally:
            connection.disconnect(True)

    def test_dialect_2_1_0(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_2_1_0)
        session = Session(connection, smb_real[0], smb_real[1], require_encryption=False)
        try:
            session.connect()
            assert len(session.application_key) == 16
            assert session.decryption_key is None
            assert not session.encrypt_data
            assert session.encryption_key is None
            assert len(session.connection.preauth_integrity_hash_value) == 2
            assert len(session.preauth_integrity_hash_value) == 3
            assert not session.require_encryption
            assert session.session_id is not None
            assert session.session_key == session.application_key
            assert session.signing_key == session.signing_key
            assert session.signing_required
        finally:
            connection.disconnect(True)

    def test_dialect_3_0_0(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_0_0)
        session = Session(connection, smb_real[0], smb_real[1])
        try:
            session.connect()
            assert len(session.application_key) == 16
            assert session.application_key != session.session_key
            assert len(session.decryption_key) == 16
            assert session.decryption_key != session.session_key
            assert session.encrypt_data
            assert len(session.encryption_key) == 16
            assert session.encryption_key != session.session_key
            assert len(session.connection.preauth_integrity_hash_value) == 2
            assert len(session.preauth_integrity_hash_value) == 3
            assert session.require_encryption
            assert session.session_id is not None
            assert len(session.session_key) == 16
            assert len(session.signing_key) == 16
            assert session.signing_key != session.session_key
            assert not session.signing_required
        finally:
            connection.disconnect(True)

    def test_dialect_3_0_2(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_0_2)
        session = Session(connection, smb_real[0], smb_real[1])
        try:
            session.connect()
            assert len(session.application_key) == 16
            assert session.application_key != session.session_key
            assert len(session.decryption_key) == 16
            assert session.decryption_key != session.session_key
            assert session.encrypt_data
            assert len(session.encryption_key) == 16
            assert session.encryption_key != session.session_key
            assert len(session.connection.preauth_integrity_hash_value) == 2
            assert len(session.preauth_integrity_hash_value) == 3
            assert session.require_encryption
            assert session.session_id is not None
            assert len(session.session_key) == 16
            assert len(session.signing_key) == 16
            assert session.signing_key != session.session_key
            assert not session.signing_required
        finally:
            connection.disconnect(True)

    def test_dialect_3_1_1(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_1_1)
        session = Session(connection, smb_real[0], smb_real[1])
        try:
            session.connect()
            assert len(session.application_key) == 16
            assert session.application_key != session.session_key
            assert len(session.decryption_key) == 16
            assert session.decryption_key != session.session_key
            assert session.encrypt_data
            assert len(session.encryption_key) == 16
            assert session.encryption_key != session.session_key
            assert len(session.connection.preauth_integrity_hash_value) == 2
            assert len(session.preauth_integrity_hash_value) == 3
            assert session.require_encryption
            assert session.session_id is not None
            assert len(session.session_key) == 16
            assert len(session.signing_key) == 16
            assert session.signing_key != session.session_key
            assert not session.signing_required
        finally:
            connection.disconnect(True)
            # test that disconnect can be run multiple times
            session.disconnect()

    def test_require_encryption(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()
        session = Session(connection, smb_real[0], smb_real[1], True)
        try:
            session.connect()
            assert len(session.application_key) == 16
            assert session.application_key != session.session_key
            assert len(session.decryption_key) == 16
            assert session.decryption_key != session.session_key
            assert session.encrypt_data
            assert len(session.encryption_key) == 16
            assert session.encryption_key != session.session_key
            assert len(session.connection.preauth_integrity_hash_value) == 2
            assert len(session.preauth_integrity_hash_value) == 3
            assert session.require_encryption
            assert session.session_id is not None
            assert len(session.session_key) == 16
            assert len(session.signing_key) == 16
            assert session.signing_key != session.session_key
            assert not session.signing_required
        finally:
            connection.disconnect(True)

    def test_require_encryption_not_supported(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_2_1_0)
        try:
            session = Session(connection, smb_real[0], smb_real[1])
            with pytest.raises(SMBException) as exc:
                session.connect()
            assert str(exc.value) == "SMB encryption is required but the connection does not support it"
        finally:
            connection.disconnect(True)

    def test_connect_fail(self, smb_real, monkeypatch, mocker):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()
        try:
            monkeypatch.setattr(
                pyspnego, "client", mocker.MagicMock(side_effect=pyspnego.exceptions.NoCredentialError())
            )
            session = Session(connection, smb_real[0], smb_real[1])

            with pytest.raises(SMBAuthenticationError, match="Failed to authenticate with server"):
                session.connect()

        finally:
            connection.disconnect(True)

    def test_setup_session_with_ms_gss_token(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()
        connection.gss_negotiate_token = (
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
        session = Session(connection, smb_real[0], smb_real[1], False)
        try:
            session.connect()
            assert len(session.application_key) == 16
            assert session.application_key != session.session_key
            assert len(session.decryption_key) == 16
            assert session.decryption_key != session.session_key
            assert not session.encrypt_data
            assert len(session.encryption_key) == 16
            assert session.encryption_key != session.session_key
            assert len(session.connection.preauth_integrity_hash_value) == 2
            assert len(session.preauth_integrity_hash_value) == 3
            assert not session.require_encryption
            assert session.session_id is not None
            assert len(session.session_key) == 16
            assert len(session.signing_key) == 16
            assert session.signing_key != session.session_key
            assert session.signing_required
        finally:
            connection.disconnect(True)

    def test_setup_session_with_ntlm_only(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()

        session = Session(connection, smb_real[0], smb_real[1], False, auth_protocol="ntlm")
        try:
            session.connect()
            assert len(session.application_key) == 16
            assert session.application_key != session.session_key
            assert len(session.decryption_key) == 16
            assert session.decryption_key != session.session_key
            assert not session.encrypt_data
            assert len(session.encryption_key) == 16
            assert session.encryption_key != session.session_key
            assert len(session.connection.preauth_integrity_hash_value) == 2
            assert len(session.preauth_integrity_hash_value) == 3
            assert not session.require_encryption
            assert session.session_id is not None
            assert len(session.session_key) == 16
            assert len(session.signing_key) == 16
            assert session.signing_key != session.session_key
            assert session.signing_required
        finally:
            connection.disconnect()
