import os

import pytest


@pytest.fixture(scope='module')
def smb_real():
    username = os.environ.get('SMB_USER', None)
    password = os.environ.get('SMB_PASSWORD', None)
    server = os.environ.get('SMB_SERVER', None)
    port = os.environ.get('SMB_PORT', None)
    share = os.environ.get('SMB_SHARE', None)

    if username and password and server and port and share:
        return (username, password, server, int(port), share)
    else:
        pytest.skip("SMB_USER, SMB_PASSWORD, SMB_PORT, SMB_SHARE environment "
                    "variable was not set. Integration tests will be skipped")
