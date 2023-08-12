# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import logging

import pytest

import smbclient._io as io
import smbclient._pool as pool
from smbprotocol.dfs import DFSReferralResponse
from smbprotocol.exceptions import BadNetworkName, InvalidParameter, ObjectPathNotFound

from .conftest import DC_REFERRAL, DOMAIN_NAME, DOMAIN_REFERRAL


@pytest.fixture()
def reset_config():
    config = pool.ClientConfig()
    client_guid = config.client_guid
    username = config.username
    password = config.password
    domain_controller = config.domain_controller
    skip_dfs = config.skip_dfs

    yield

    config.set(
        client_guid=client_guid,
        username=username,
        password=password,
        skip_dfs=skip_dfs,
        domain_controller=domain_controller,
    )
    config._domain_cache = []
    config._referral_cache = []


def test_client_config_private_key(reset_config):
    with pytest.raises(ValueError, match="Cannot set private attribute _domain_controller"):
        pool.ClientConfig().set(_domain_controller="test")


def test_set_config_option(reset_config):
    pool.ClientConfig(username="test")
    assert pool.ClientConfig().username == "test"
    pool.ClientConfig(username=None)
    assert not pool.ClientConfig().username


def test_config_domain_cache(reset_config, monkeypatch, mocker):
    dfs_mock = mocker.MagicMock()
    dfs_mock.return_value = DOMAIN_REFERRAL
    monkeypatch.setattr(pool, "get_smb_tree", mocker.MagicMock())
    monkeypatch.setattr(pool, "dfs_request", dfs_mock)

    config = pool.ClientConfig()

    domain_referral = config.lookup_domain(DOMAIN_NAME)
    assert domain_referral is None

    config.domain_controller = DOMAIN_NAME
    domain_referral = config.lookup_domain(DOMAIN_NAME)
    assert domain_referral.domain_name == "\\%s" % DOMAIN_NAME
    assert dfs_mock.call_count == 1
    assert dfs_mock.call_args[0][1] == ""


def test_config_domain_cache_not_dfs_endpoint(reset_config, monkeypatch, mocker):
    dfs_mock = mocker.MagicMock()
    dfs_mock.side_effect = InvalidParameter()
    warning_mock = mocker.MagicMock()
    monkeypatch.setattr(pool, "get_smb_tree", mocker.MagicMock())
    monkeypatch.setattr(pool, "dfs_request", dfs_mock)
    monkeypatch.setattr(pool.log, "warning", warning_mock)

    config = pool.ClientConfig()
    config.domain_controller = DOMAIN_NAME

    domain_referral = config.lookup_domain(DOMAIN_NAME)
    assert domain_referral is None
    assert warning_mock.call_count == 1
    assert "cannot use as DFS domain cache source" in warning_mock.call_args[0][0]


def test_reset_connection_error_fail(mocker):
    connection_mock = mocker.MagicMock()
    connection_mock.disconnect.side_effect = Exception("exception")

    with pytest.raises(Exception, match="exception"):
        pool.reset_connection_cache(connection_cache={"conn": connection_mock})


def test_reset_connection_error_warning(mocker, caplog):
    connection_mock = mocker.MagicMock()
    connection_mock.disconnect.side_effect = Exception("exception")

    with caplog.at_level(logging.WARNING):
        pool.reset_connection_cache(fail_on_error=False, connection_cache={"conn": connection_mock})

        assert "Failed to close connection conn" in caplog.text


def test_dfs_referral_no_links_no_domain(reset_config, monkeypatch, mocker):
    no_referral = DFSReferralResponse()
    no_referral["path_consumed"] = 0
    no_referral["number_of_referrals"] = 0
    dfs_mock = mocker.MagicMock()
    dfs_mock.side_effect = [no_referral]

    tree_mock = mocker.MagicMock()
    tree_mock.side_effect = (BadNetworkName(), None)

    monkeypatch.setattr(pool, "dfs_request", dfs_mock)
    monkeypatch.setattr(pool.TreeConnect, "connect", tree_mock)
    monkeypatch.setattr(pool, "register_session", mocker.MagicMock())

    with pytest.raises(ObjectPathNotFound):
        pool.get_smb_tree(r"\\server\dfs")


def test_dfs_referral_no_links_from_domain(reset_config, monkeypatch, mocker):
    actual_get_smb_tree = pool.get_smb_tree

    no_referral = DFSReferralResponse()
    no_referral["path_consumed"] = 0
    no_referral["number_of_referrals"] = 0
    dfs_mock = mocker.MagicMock()
    dfs_mock.side_effect = [DOMAIN_REFERRAL, DC_REFERRAL, no_referral]

    monkeypatch.setattr(pool, "dfs_request", dfs_mock)
    monkeypatch.setattr(pool, "get_smb_tree", mocker.MagicMock())
    config = pool.ClientConfig()
    config.domain_controller = DOMAIN_NAME

    with pytest.raises(ObjectPathNotFound):
        actual_get_smb_tree(rf"\\{DOMAIN_NAME}\dfs")


def test_resolve_dfs_referral_no_links(reset_config, monkeypatch, mocker):
    no_referral = DFSReferralResponse()
    no_referral["path_consumed"] = 0
    no_referral["number_of_referrals"] = 0
    dfs_mock = mocker.MagicMock()
    dfs_mock.side_effect = [no_referral]
    monkeypatch.setattr(io, "dfs_request", dfs_mock)

    raw_io = mocker.MagicMock()
    raw_io.name = r"\\server\dfs"
    raw_io.fd.tree_connect.is_dfs_share = True

    with pytest.raises(ObjectPathNotFound):
        list(io._resolve_dfs(raw_io))
