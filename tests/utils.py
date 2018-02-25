import os

import pytest


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
