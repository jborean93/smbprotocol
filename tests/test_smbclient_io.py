from __future__ import division

import smbclient

def test_write_multiple_chunks(smb_share):
    smbclient.mkdir("%s\\dir2" % smb_share)
    with smbclient.open_file("%s\\file1" % smb_share, mode='w') as fd:
        fd.writeall(u"content" * 1024, max_write_size=1024)

    assert smbclient.stat("%s\\file1" % smb_share).st_size == len(u"content") * 1024

