# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os
import time

import pytest

from smbclient import ClientConfig, delete_session, mkdir
from smbclient.shutil import rmtree
from smbprotocol.dfs import DFSReferralResponse

DOMAIN_NAME = "domain.test"
DOMAIN_REFERRAL = DFSReferralResponse()
DOMAIN_REFERRAL.unpack(
    b"\x00\x00"
    b"\x02\x00"
    b"\x00\x00\x00\x00"
    b"\x03\x00"
    b"\x12\x00"
    b"\x00\x00"
    b"\x00\x00"
    b"\x58\x02\x00\x00"
    b"\x24\x00"
    b"\x00\x00"
    b"\x00\x00"
    b"\x03\x00"
    b"\x12\x00"
    b"\x00\x00"
    b"\x02\x00"
    b"\x58\x02\x00\x00"
    b"\x22\x00"
    b"\x00\x00"
    b"\x00\x00"
    b"\x5C\x00\x44\x00\x4F\x00\x4D\x00"
    b"\x41\x00\x49\x00\x4E\x00\x00\x00"
    b"\x5C\x00\x64\x00\x6F\x00\x6D\x00"
    b"\x61\x00\x69\x00\x6E\x00\x2E\x00"
    b"\x74\x00\x65\x00\x73\x00\x74\x00"
    b"\x00\x00"
)

DC_REFERRAL = DFSReferralResponse()
DC_REFERRAL.unpack(
    b"\x00\x00"
    b"\x01\x00"
    b"\x00\x00\x00\x00"
    b"\x03\x00"
    b"\x12\x00"
    b"\x00\x00"
    b"\x02\x00"
    b"\x58\x02\x00\x00"
    b"\x12\x00"
    b"\x02\x00"
    b"\x2C\x00"
    b"\x5C\x00\x64\x00\x6F\x00\x6D\x00"
    b"\x61\x00\x69\x00\x6E\x00\x2E\x00"
    b"\x74\x00\x65\x00\x73\x00\x74\x00"
    b"\x00\x00"
    b"\x5C\x00\x44\x00\x43\x00\x30\x00"
    b"\x31\x00\x2E\x00\x64\x00\x6F\x00"
    b"\x6D\x00\x61\x00\x69\x00\x6E\x00"
    b"\x2E\x00\x74\x00\x65\x00\x73\x00"
    b"\x74\x00\x00\x00"
    b"\x5C\x00\x44\x00\x43\x00\x30\x00"
    b"\x31\x00\x2E\x00\x64\x00\x6F\x00"
    b"\x6D\x00\x61\x00\x69\x00\x6E\x00"
    b"\x2E\x00\x74\x00\x65\x00\x73\x00"
    b"\x74\x00\x32\x00\x00\x00"
)


ROOT_REFERRAL = DFSReferralResponse()
ROOT_REFERRAL.unpack(
    b"\x20\x00"
    b"\x01\x00"
    b"\x03\x00\x00\x00"
    b"\x04\x00"
    b"\x22\x00"
    b"\x01\x00"
    b"\x04\x00"
    b"\x2C\x01\x00\x00"
    b"\x22\x00"
    b"\x44\x00"
    b"\x66\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x5C\x00\x64\x00\x6F\x00\x6D\x00"
    b"\x61\x00\x69\x00\x6E\x00\x2E\x00"
    b"\x74\x00\x65\x00\x73\x00\x74\x00"
    b"\x5C\x00\x64\x00\x66\x00\x73\x00"
    b"\x00\x00\x5C\x00\x64\x00\x6F\x00"
    b"\x6D\x00\x61\x00\x69\x00\x6E\x00"
    b"\x2E\x00\x74\x00\x65\x00\x73\x00"
    b"\x74\x00\x5C\x00\x64\x00\x66\x00"
    b"\x73\x00\x00\x00\x5C\x00\x53\x00"
    b"\x45\x00\x52\x00\x56\x00\x45\x00"
    b"\x52\x00\x32\x00\x30\x00\x31\x00"
    b"\x32\x00\x52\x00\x32\x00\x2E\x00"
    b"\x44\x00\x4F\x00\x4D\x00\x41\x00"
    b"\x49\x00\x4E\x00\x2E\x00\x54\x00"
    b"\x45\x00\x53\x00\x54\x00\x5C\x00"
    b"\x64\x00\x66\x00\x73\x00\x00\x00"
)


TARGET_REFERRAL = DFSReferralResponse()
TARGET_REFERRAL.unpack(
    b"\x26\x00"
    b"\x02\x00"
    b"\x02\x00\x00\x00"
    b"\x04\x00"
    b"\x22\x00"
    b"\x00\x00"
    b"\x04\x00"
    b"\x08\x07\x00\x00"
    b"\x44\x00"
    b"\x6C\x00"
    b"\x94\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x04\x00"
    b"\x22\x00"
    b"\x00\x00"
    b"\x00\x00"
    b"\x08\x07\x00\x00"
    b"\x22\x00"
    b"\x4A\x00"
    b"\x9C\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x5C\x00\x64\x00\x6F\x00\x6D\x00"
    b"\x61\x00\x69\x00\x6E\x00\x2E\x00"
    b"\x74\x00\x65\x00\x73\x00\x74\x00"
    b"\x5C\x00\x64\x00\x66\x00\x73\x00"
    b"\x5C\x00\x64\x00\x63\x00\x00\x00"
    b"\x5C\x00\x64\x00\x6F\x00\x6D\x00"
    b"\x61\x00\x69\x00\x6E\x00\x2E\x00"
    b"\x74\x00\x65\x00\x73\x00\x74\x00"
    b"\x5C\x00\x64\x00\x66\x00\x73\x00"
    b"\x5C\x00\x64\x00\x63\x00\x00\x00"
    b"\x5C\x00\x64\x00\x63\x00\x30\x00"
    b"\x31\x00\x2E\x00\x64\x00\x6F\x00"
    b"\x6D\x00\x61\x00\x69\x00\x6E\x00"
    b"\x2E\x00\x74\x00\x65\x00\x73\x00"
    b"\x74\x00\x5C\x00\x63\x00\x24\x00"
    b"\x00\x00\x5C\x00\x73\x00\x65\x00"
    b"\x72\x00\x76\x00\x65\x00\x72\x00"
    b"\x32\x00\x30\x00\x31\x00\x39\x00"
    b"\x2E\x00\x64\x00\x6F\x00\x6D\x00"
    b"\x61\x00\x69\x00\x6E\x00\x2E\x00"
    b"\x74\x00\x65\x00\x73\x00\x74\x00"
    b"\x5C\x00\x63\x00\x24\x00\x00\x00"
)


@pytest.fixture(scope="module")
def smb_real():
    # for these tests to work the server at SMB_SERVER must support dialect
    # 3.1.1, without this some checks will fail as we test 3.1.1 specific
    # features
    username = os.environ.get("SMB_USER", None)
    password = os.environ.get("SMB_PASSWORD", None)
    server = os.environ.get("SMB_SERVER", None)
    port = os.environ.get("SMB_PORT", 445)
    share = os.environ.get("SMB_SHARE", "share")

    if server:
        share = rf"\\{server}\{share}"
        encrypted_share = f"{share}-encrypted"
        return username, password, server, int(port), share, encrypted_share
    else:
        pytest.skip("The SMB_SHARE env var was not set, integration tests will be skipped")


@pytest.fixture(
    params=[
        ("share", 4),
        ("share-encrypted", 5),
    ],
    ids=["share", "share-encrypted"],
)
def smb_share(request, smb_real):
    # Use some non ASCII chars to test out edge cases by default.
    test_folder = f"Pýtæs†-[{time.time()}] 💩"
    share_path = rf"{smb_real[request.param[1]]}\{test_folder}"
    delete_session(smb_real[2])

    # Test out forward slashes also work with the share-encrypted test
    if request.param[0] == "share-encrypted":
        share_path = share_path.replace("\\", "/")

    mkdir(share_path, username=smb_real[0], password=smb_real[1], port=smb_real[3])
    try:
        yield share_path
    finally:
        rmtree(share_path, username=smb_real[0], password=smb_real[1], port=smb_real[3])


@pytest.fixture(
    params=[
        ("", None),  # Root, no referral targets
        ("share", 4),  # Simple referral to a single target
        ("share-encrypted", 5),  # Referral to 2 targets, first is known to be broken
    ],
    ids=["dfs-root", "dfs-single-target", "dfs-broken-target"],
)
def smb_dfs_share(request, smb_real):
    test_folder = f"Pýtæs†-[{time.time()}] 💩"

    if request.param[1]:
        target_share_path = rf"{smb_real[request.param[1]]}\{test_folder}"
        dfs_path = rf"\\{smb_real[2]}\dfs\{request.param[0]}\{test_folder}"

    else:
        target_share_path = rf"\\{smb_real[2]}\dfs\{test_folder}"
        dfs_path = target_share_path

    mkdir(target_share_path, username=smb_real[0], password=smb_real[1], port=smb_real[3])
    try:
        yield dfs_path
    finally:
        rmtree(target_share_path, username=smb_real[0], password=smb_real[1], port=smb_real[3])

        config = ClientConfig()
        config._domain_cache = []
        config._referral_cache = []
