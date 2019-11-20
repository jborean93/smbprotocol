# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import division

import os
import sys

import pytest
import re

from smbclient import open_file, mkdir, stat, symlink
from smbclient.path import exists
from smbclient.shutil import rmtree, copy, copytree


def test_rmtree(smb_share):
    mkdir("%s\\dir2" % smb_share)
    mkdir("%s\\dir2\\dir3" % smb_share)

    with open_file("%s\\dir2\\dir3\\file1" % smb_share, mode='w') as fd:
        fd.write(u"content")

    with open_file("%s\\dir2\\file2" % smb_share, mode='w') as fd:
        fd.write(u"content")

    if os.name == "nt" or os.environ.get('SMB_FORCE', False):
        symlink("%s\\dir2\\file2" % smb_share, "%s\\dir2\\file3" % smb_share)

    assert exists("%s\\dir2" % smb_share) is True

    rmtree("%s\\dir2" % smb_share)

    assert exists("%s\\dir2" % smb_share) is False


def test_rmtree_non_existing(smb_share):
    expected = "[NtStatus 0xc0000034] No such file or directory: "
    with pytest.raises(OSError, match=re.escape(expected)):
        rmtree("%s\\dir2" % smb_share)


def test_rmtree_non_existing_with_error_callback(smb_share):
    callback_args = []

    def callback(*args):
        callback_args.append(args)

    assert not callback_args

    rmtree("%s\\dir2" % smb_share, onerror=callback)

    assert callback_args


def test_rmtree_non_existing_ignore_errors(smb_share):
    rmtree("%s\\dir2" % smb_share, ignore_errors=True)


def test_copy(smb_share):
    mkdir("%s\\dir2" % smb_share)
    with open_file("%s\\file1" % smb_share, mode='w') as fd:
        fd.write(u"content")

    copy("%s\\file1" % smb_share, "%s\\dir2\\file1" % smb_share)

    src_stat = stat("%s\\file1" % smb_share)
    dst_stat = stat("%s\\dir2\\file1" % smb_share)

    assert src_stat.st_size == dst_stat.st_size


def test_copy_raises_when_source_and_target_identical(smb_share):
    mkdir("%s\\dir2" % smb_share)
    with open_file("%s\\file1" % smb_share, mode='w') as fd:
        fd.write(u"content")

    expected = 'are the same file'
    with pytest.raises(ValueError, match=re.escape(expected)):
        copy("%s\\file1" % smb_share, "%s\\file1" % smb_share)


def test_copy_with_dir_as_target(smb_share):
    mkdir("%s\\dir2" % smb_share)
    with open_file("%s\\file1" % smb_share, mode='w') as fd:
        fd.write(u"content")

    copy("%s\\file1" % smb_share, "%s\\dir2" % smb_share)

    src_stat = stat("%s\\file1" % smb_share)
    dst_stat = stat("%s\\dir2\\file1" % smb_share)

    assert src_stat.st_size == dst_stat.st_size


def test_copytree(smb_share):
    mkdir("%s\\dir2" % smb_share)
    mkdir("%s\\dir2\\dir3" % smb_share)

    with open_file("%s\\dir2\\dir3\\file1" % smb_share, mode='w') as fd:
        fd.write(u"content")

    with open_file("%s\\dir2\\file2" % smb_share, mode='w') as fd:
        fd.write(u"content")

    copytree("%s\\dir2" % smb_share, "%s\\dir4" % smb_share)

    src_stat = stat("%s\\dir2\\dir3\\file1" % smb_share)
    dst_stat = stat("%s\\dir4\\dir3\\file1" % smb_share)

    assert src_stat.st_size == dst_stat.st_size


def test_copytree_with_skip(smb_share):
    mkdir("%s\\dir2" % smb_share)
    mkdir("%s\\dir2\\dir3" % smb_share)

    with open_file("%s\\dir2\\dir3\\file1" % smb_share, mode='w') as fd:
        fd.write(u"content")

    with open_file("%s\\dir2\\file2" % smb_share, mode='w') as fd:
        fd.write(u"content")

    def ignore(src, names):
        return [name for name in names if name == "file2"]

    copytree("%s\\dir2" % smb_share, "%s\\dir4" % smb_share, ignore=ignore)

    assert exists("%s\\dir4\\dir3\\file1" % smb_share) is True
    assert exists("%s\\dir4\\file2" % smb_share) is False
