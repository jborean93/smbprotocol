# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import division

import sys

import pytest
import re
from time import sleep

import smbclient
from smbclient import open_file, mkdir, stat
from smbclient.path import exists, isdir
from smbclient.shutil import rmtree, copy2, copytree, Error, copyfile_server_side, copyfile


def test_rmtree(smb_share):
    mkdir("%s\\dir2" % smb_share)
    mkdir("%s\\dir2\\dir3" % smb_share)

    with open_file("%s\\dir2\\dir3\\file1" % smb_share, mode='w') as fd:
        fd.write(u"content")

    with open_file("%s\\dir2\\file2" % smb_share, mode='w') as fd:
        fd.write(u"content")

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


def test_copy2(smb_share):
    mkdir("%s\\dir2" % smb_share)
    with open_file("%s\\file1" % smb_share, mode='w') as fd:
        fd.write(u"content")

    sleep(0.1)
    copy2("%s\\file1" % smb_share, "%s\\dir2\\file1" % smb_share)

    src_stat = stat("%s\\file1" % smb_share)
    dst_stat = stat("%s\\dir2\\file1" % smb_share)
    assert src_stat.st_atime == dst_stat.st_atime
    assert src_stat.st_mtime == dst_stat.st_mtime
    assert src_stat.st_size == dst_stat.st_size


def test_copy2_raises_when_source_and_target_identical(smb_share):
    mkdir("%s\\dir2" % smb_share)
    with open_file("%s\\file1" % smb_share, mode='w') as fd:
        fd.write(u"content")

    sleep(0.1)
    if (sys.version_info > (3, 0)):
        expected = 'are the same file'
        context = pytest.raises(Error, match=re.escape(expected))
    else:
        context = pytest.raises(Error)

    with context:
        copy2("%s\\file1" % smb_share, "%s\\file1" % smb_share)


def test_copy2_with_dir_as_target(smb_share):
    mkdir("%s\\dir2" % smb_share)
    with open_file("%s\\file1" % smb_share, mode='w') as fd:
        fd.write(u"content")

    sleep(0.1)
    copy2("%s\\file1" % smb_share, "%s\\dir2" % smb_share)

    src_stat = stat("%s\\file1" % smb_share)
    dst_stat = stat("%s\\dir2\\file1" % smb_share)
    assert src_stat.st_atime == dst_stat.st_atime
    assert src_stat.st_mtime == dst_stat.st_mtime
    assert src_stat.st_size == dst_stat.st_size


def test_copytree(smb_share):
    mkdir("%s\\dir2" % smb_share)
    mkdir("%s\\dir2\\dir3" % smb_share)

    with open_file("%s\\dir2\\dir3\\file1" % smb_share, mode='w') as fd:
        fd.write(u"content")

    with open_file("%s\\dir2\\file2" % smb_share, mode='w') as fd:
        fd.write(u"content")

    sleep(0.01)
    copytree("%s\\dir2" % smb_share, "%s\\dir4" % smb_share)

    src_stat = stat("%s\\dir2\\dir3\\file1" % smb_share)
    dst_stat = stat("%s\\dir4\\dir3\\file1" % smb_share)
    assert src_stat.st_atime == dst_stat.st_atime
    assert src_stat.st_mtime == dst_stat.st_mtime
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

    sleep(0.01)
    copytree("%s\\dir2" % smb_share, "%s\\dir4" % smb_share, ignore=ignore)

    assert exists("%s\\dir4\\dir3\\file1" % smb_share) is True
    assert exists("%s\\dir4\\file2" % smb_share) is False


def test_copyfile_with_same_file(smb_share):
    if (sys.version_info > (3, 0)):
        expected = 'are the same file'
        context = pytest.raises(Error, match=re.escape(expected))
    else:
        context = pytest.raises(Error)

    with context:
        copyfile("%s\\file1" % smb_share, "%s\\file1" % smb_share)


def test_server_side_copy(smb_share):
    mkdir("%s\\dir2" % smb_share)
    with open_file("%s\\file1" % smb_share, mode='w') as fd:
        fd.write(u"content" * 1024)

    sleep(0.1)
    copy2("%s\\file1" % smb_share, "%s\\dir2\\file1" % smb_share, server_side_copy=True)

    src_stat = stat("%s\\file1" % smb_share)
    dst_stat = stat("%s\\dir2\\file1" % smb_share)
    assert src_stat.st_atime == dst_stat.st_atime
    assert src_stat.st_mtime == dst_stat.st_mtime
    assert src_stat.st_size == dst_stat.st_size


def test_server_side_copy_across_paths_raises():
    expected = 'Server side copy can only occur on the same drive'
    with pytest.raises(ValueError, match=re.escape(expected)):
        copyfile_server_side("//host/filer1/file1", "//host/filer2/file2")


def test_server_side_copy_target_exists(smb_share):
    with open_file("%s\\file1" % smb_share, mode='w') as fd:
        fd.write(u"content" * 1024)
    with open_file("%s\\file2" % smb_share, mode='w') as fd:
        fd.write(u"content" * 1024)

    if (sys.version_info > (3, 0)):
        expected = 'already exists'
        context = pytest.raises(ValueError, match=re.escape(expected))
    else:
        context = pytest.raises(ValueError)

    with context:
        copyfile_server_side("%s\\file1" % smb_share, "%s\\file2" % smb_share)


def test_server_side_copy_multiple_chunks(smb_share):
    mkdir("%s\\dir2" % smb_share)
    with open_file("%s\\file1" % smb_share, mode='w') as fd:
        fd.write(u"content" * 1024)

    smbclient.shutil.CHUNK_SIZE = 1024

    sleep(0.1)
    copy2("%s\\file1" % smb_share, "%s\\dir2\\file1" % smb_share, server_side_copy=True)

    src_stat = stat("%s\\file1" % smb_share)
    dst_stat = stat("%s\\dir2\\file1" % smb_share)
    assert src_stat.st_atime == dst_stat.st_atime
    assert src_stat.st_mtime == dst_stat.st_mtime
    assert src_stat.st_size == dst_stat.st_size
