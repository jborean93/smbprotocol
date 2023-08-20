# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import pytest


def test_query_info_deprecation():
    with pytest.warns(DeprecationWarning) as record:
        from smbprotocol import query_info

    assert len(record) == 1
    assert (
        str(record.list[0].message) == "The smbprotocol.query_info file has been renamed to "
        "smbprotocol.file_info and will be removed in the next major release."
    )
