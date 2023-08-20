# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import uuid

import pytest

from smbprotocol import Dialects
from smbprotocol.connection import Ciphers, Connection, SigningAlgorithms
from smbprotocol.exceptions import AccessDenied, SMBException
from smbprotocol.session import Session
from smbprotocol.tree import (
    SMB2TreeConnectRequest,
    SMB2TreeConnectResponse,
    SMB2TreeDisconnect,
    TreeConnect,
)


class TestSMB2TreeConnectRequest:
    def test_create_message(self):
        message = SMB2TreeConnectRequest()
        message["flags"] = 2
        message["buffer"] = "\\\\127.0.0.1\\c$".encode("utf-16-le")
        expected = (
            b"\x09\x00"
            b"\x02\x00"
            b"\x48\x00"
            b"\x1c\x00"
            b"\x5c\x00\x5c\x00\x31\x00\x32\x00"
            b"\x37\x00\x2e\x00\x30\x00\x2e\x00"
            b"\x30\x00\x2e\x00\x31\x00\x5c\x00"
            b"\x63\x00\x24\x00"
        )
        actual = message.pack()
        assert len(message) == 36
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2TreeConnectRequest()
        data = (
            b"\x09\x00"
            b"\x02\x00"
            b"\x48\x00"
            b"\x1c\x00"
            b"\x5c\x00\x5c\x00\x31\x00\x32\x00"
            b"\x37\x00\x2e\x00\x30\x00\x2e\x00"
            b"\x30\x00\x2e\x00\x31\x00\x5c\x00"
            b"\x63\x00\x24\x00"
        )
        actual.unpack(data)
        assert len(actual) == 36
        assert actual["structure_size"].get_value() == 9
        assert actual["flags"].get_value() == 2
        assert actual["path_offset"].get_value() == 72
        assert actual["path_length"].get_value() == 28
        assert actual["buffer"].get_value() == "\\\\127.0.0.1\\c$".encode("utf-16-le")


class TestSMB2TreeConnectResponse:
    def test_create_message(self):
        message = SMB2TreeConnectResponse()
        message["share_type"] = 1
        message["share_flags"] = 2
        message["capabilities"] = 8
        message["maximal_access"] = 10
        expected = b"\x10\x00" b"\x01" b"\x00" b"\x02\x00\x00\x00" b"\x08\x00\x00\x00" b"\x0a\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 16
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2TreeConnectResponse()
        data = b"\x10\x00" b"\x01" b"\x00" b"\x02\x00\x00\x00" b"\x08\x00\x00\x00" b"\x0a\x00\x00\x00"
        actual.unpack(data)
        assert len(actual) == 16
        assert actual["structure_size"].get_value() == 16
        assert actual["share_type"].get_value() == 1
        assert actual["reserved"].get_value() == 0
        assert actual["share_flags"].get_value() == 2
        assert actual["capabilities"].get_value() == 8
        assert actual["maximal_access"].get_value() == 10


class TestSMB2TreeDisconnect:
    def test_create_message(self):
        message = SMB2TreeDisconnect()
        expected = b"\x04\x00" b"\x00\x00"
        actual = message.pack()
        assert len(message) == 4
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2TreeDisconnect()
        data = b"\x04\x00" b"\x00\x00"
        actual.unpack(data)
        assert len(actual) == 4
        assert actual["structure_size"].get_value() == 4
        assert actual["reserved"].get_value() == 0


class TestTreeConnect:
    def test_dialect_2_0_2(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_2_0_2)
        session = Session(connection, smb_real[0], smb_real[1], False)
        tree = TreeConnect(session, smb_real[4])
        try:
            session.connect()
            tree.connect()
            assert tree.encrypt_data is None
            assert not tree.is_ca_share
            assert not tree.is_dfs_share
            assert not tree.is_scaleout_share
            assert isinstance(tree.tree_connect_id, int)
        finally:
            connection.disconnect(True)

    def test_dialect_2_1_0(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_2_1_0)
        session = Session(connection, smb_real[0], smb_real[1], False)
        tree = TreeConnect(session, smb_real[4])
        try:
            session.connect()
            tree.connect()
            assert tree.encrypt_data is None
            assert not tree.is_ca_share
            assert not tree.is_dfs_share
            assert not tree.is_scaleout_share
            assert isinstance(tree.tree_connect_id, int)
        finally:
            connection.disconnect(True)

    def test_dialect_3_0_0(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_0_0)
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        try:
            session.connect()
            tree.connect()
            assert not tree.encrypt_data
            assert not tree.is_ca_share
            assert not tree.is_dfs_share
            assert not tree.is_scaleout_share
            assert isinstance(tree.tree_connect_id, int)
        finally:
            connection.disconnect(True)

    def test_dialect_3_0_2(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_0_2)
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        try:
            session.connect()
            tree.connect()
            assert not tree.encrypt_data
            assert not tree.is_ca_share
            assert not tree.is_dfs_share
            assert not tree.is_scaleout_share
            assert isinstance(tree.tree_connect_id, int)
        finally:
            connection.disconnect(True)

    def test_dialect_3_1_1(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_1_1)
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        try:
            session.connect()
            tree.connect()
            assert not tree.encrypt_data
            assert not tree.is_ca_share
            assert not tree.is_dfs_share
            assert not tree.is_scaleout_share
            assert isinstance(tree.tree_connect_id, int)
        finally:
            connection.disconnect(True)

    def test_dialect_2_encrypted_share(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_2_1_0)
        session = Session(connection, smb_real[0], smb_real[1], False)
        tree = TreeConnect(session, smb_real[5])
        try:
            session.connect()
            with pytest.raises(AccessDenied) as exc:
                tree.connect()
        finally:
            connection.disconnect(True)

    def test_dialect_3_encrypted_share(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_1_1)
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[5])
        try:
            session.connect()
            tree.connect()
            assert tree.encrypt_data
            assert not tree.is_ca_share
            assert not tree.is_dfs_share
            assert not tree.is_scaleout_share
            assert isinstance(tree.tree_connect_id, int)
        finally:
            connection.disconnect(True)

    def test_secure_negotiation_verification_failed(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_0_2)
        session = Session(connection, smb_real[0], smb_real[1])
        connection.dialect = Dialects.SMB_3_0_0
        tree = TreeConnect(session, smb_real[4])
        try:
            session.connect()
            with pytest.raises(SMBException) as exc:
                tree.connect()
            assert "Secure negotiate failed to verify server dialect, Actual: 770, Expected: 768" in str(exc.value)
        finally:
            connection.disconnect(True)

    def test_secure_ignore_negotiation_verification_failed(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_0_2)
        session = Session(connection, smb_real[0], smb_real[1])
        connection.dialect = Dialects.SMB_3_0_0
        tree = TreeConnect(session, smb_real[4])
        try:
            session.connect()
            tree.connect(False)
            assert not tree.encrypt_data
            assert not tree.is_ca_share
            assert not tree.is_dfs_share
            assert not tree.is_scaleout_share
            assert isinstance(tree.tree_connect_id, int)
        finally:
            connection.disconnect(True)
            tree.disconnect()  # test that disconnect can be run mutliple times

    @pytest.mark.parametrize(
        "cipher",
        [
            Ciphers.AES_128_CCM,
            Ciphers.AES_128_GCM,
            Ciphers.AES_256_CCM,
            Ciphers.AES_256_GCM,
        ],
        ids=["AES_128_CCM", "AES_128_GCM", "AES_256_CCM", "AES_256_GCM"],
    )
    def test_encryption(self, cipher, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(preferred_encryption_algos=[cipher])

        try:
            if connection.cipher_id == 0:
                pytest.skip("Server did not support encryption requested")

            assert connection.cipher_id == cipher

            session = Session(connection, smb_real[0], smb_real[1])
            tree = TreeConnect(session, smb_real[4])
            session.connect()
            tree.connect()

        finally:
            connection.disconnect(True)

    @pytest.mark.parametrize(
        "algo",
        [
            SigningAlgorithms.AES_GMAC,
            SigningAlgorithms.AES_CMAC,
            SigningAlgorithms.HMAC_SHA256,
        ],
        ids=["AES_GMAC", "AES_CMAC", "HMAC_SHA256"],
    )
    def test_signing(self, algo, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(preferred_signing_algos=[algo])

        try:
            if connection.signing_algorithm_id is None:
                pytest.skip("Server did not support signing algo requested")

            assert connection.signing_algorithm_id == algo

            session = Session(connection, smb_real[0], smb_real[1], require_encryption=False)
            tree = TreeConnect(session, smb_real[4])
            session.connect()
            tree.connect()

        finally:
            connection.disconnect(True)
