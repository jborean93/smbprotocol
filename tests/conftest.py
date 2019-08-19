# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os
import time

import pytest


from smbclient import (
    mkdir,
    remove,
    rmdir,
    scandir,
)


def remove_tree(path):
    for dir_entry in scandir(path):
        if dir_entry.is_dir():
            if dir_entry.is_symlink():
                rmdir(dir_entry.path)
            else:
                remove_tree(dir_entry.path)
        else:
            remove(dir_entry.path)
    rmdir(path)


@pytest.fixture(scope='module')
def smb_real():
    # for these tests to work the server at SMB_SERVER must support dialect
    # 3.1.1, without this some checks will fail as we test 3.1.1 specific
    # features
    username = os.environ.get('SMB_USER', None)
    password = os.environ.get('SMB_PASSWORD', None)
    server = os.environ.get('SMB_SERVER', None)
    port = os.environ.get('SMB_PORT', 445)
    share = os.environ.get('SMB_SHARE', 'share')

    if username and password and server:
        share = r"\\%s\%s" % (server, share)
        encrypted_share = "%s-encrypted" % share
        return username, password, server, int(port), share, encrypted_share
    else:
        pytest.skip("SMB_USER, SMB_PASSWORD, SMB_PORT, SMB_SHARE, "
                    "environment variables were not set, integration tests "
                    "will be skipped")


@pytest.fixture(params=[
    ('share', 4),
    ('share-encrypted', 5),
])
def smb_share(request, smb_real):
    # Use some non ASCII chars to test out edge cases by default.
    share_path = u"%s\\%s" % (smb_real[request.param[1]], u"Pýtæs†-[%s] 💩" % time.time())

    # Test out forward slashes also work with the share-encrypted test
    if request.param[0] == 'share-encrypted':
        share_path = share_path.replace('\\', '/')

    mkdir(share_path, username=smb_real[0], password=smb_real[1], port=smb_real[3])
    try:
        yield share_path
    finally:
        remove_tree(share_path)
