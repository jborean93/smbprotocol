# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os
import re
import stat

import pytest

from smbclient import link, mkdir, open_file, stat, symlink
from smbclient.path import (
    exists,
    getatime,
    getctime,
    getmtime,
    getsize,
    isdir,
    isfile,
    islink,
    lexists,
    samefile,
)


def test_exists(smb_share):
    filename = "%s\\file.txt" % smb_share

    assert exists(filename) is False

    with open_file(filename, mode="w") as fd:
        fd.write("content")

    assert exists(filename) is True


def test_exists_missing_path(smb_share):
    assert exists("%s\\missing dir" % smb_share) is False
    assert exists("%s\\missing dir\\file.txt" % smb_share) is False


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_exists_broken_symlink(smb_share):
    src_filename = "%s\\file.txt" % smb_share
    dst_filename = "%s\\link.txt" % smb_share

    symlink(src_filename, dst_filename)

    assert exists(dst_filename) is False


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_exists_working_symlink(smb_share):
    src_filename = "%s\\file.txt" % smb_share
    dst_filename = "%s\\link.txt" % smb_share

    with open_file(src_filename, mode="w") as fd:
        fd.write("content")

    symlink(src_filename, dst_filename)

    assert exists(dst_filename) is True


def test_lexists(smb_share):
    filename = "%s\\file.txt" % smb_share

    assert exists(filename) is False

    with open_file(filename, mode="w") as fd:
        fd.write("content")

    assert lexists(filename) is True


def test_lexists_missing_path(smb_share):
    assert lexists("%s\\missing dir" % smb_share) is False
    assert lexists("%s\\missing dir\\file.txt" % smb_share) is False


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_lexists_broken_symlink(smb_share):
    src_filename = "%s\\file.txt" % smb_share
    dst_filename = "%s\\link.txt" % smb_share

    symlink(src_filename, dst_filename)

    assert lexists(dst_filename) is True


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_lexists_working_symlink(smb_share):
    src_filename = "%s\\file.txt" % smb_share
    dst_filename = "%s\\link.txt" % smb_share

    with open_file(src_filename, mode="w") as fd:
        fd.write("content")

    symlink(src_filename, dst_filename)

    assert lexists(dst_filename) is True


def test_getatime(smb_share):
    filename = "%s\\file.txt" % smb_share

    with open_file(filename, mode="w") as fd:
        fd.write("content")

    expected = stat(filename).st_atime
    assert getatime(filename) == expected


def test_getmtime(smb_share):
    filename = "%s\\file.txt" % smb_share

    with open_file(filename, mode="w") as fd:
        fd.write("content")

    expected = stat(filename).st_mtime
    assert getmtime(filename) == expected


def test_getctime(smb_share):
    filename = "%s\\file.txt" % smb_share

    with open_file(filename, mode="w") as fd:
        fd.write("content")

    expected = stat(filename).st_ctime
    assert getctime(filename) == expected


def test_getsize(smb_share):
    filename = "%s\\file.txt" % smb_share

    with open_file(filename, mode="wb") as fd:
        fd.write(b"\x00\x01\x02\x03")

    assert getsize(filename) == 4


def test_isfile_missing(smb_share):
    assert isfile("%s\\missing" % smb_share) is False


def test_isfile_no_path(smb_share):
    assert isfile("%s\\missing\\file.txt" % smb_share) is False


def test_isfile_with_file(smb_share):
    filename = "%s\\file.txt" % smb_share
    with open_file(filename, mode="w") as fd:
        fd.write("content")
    assert isfile(filename) is True


def test_isfile_with_dir(smb_share):
    dir_name = "%s\\dir" % smb_share
    mkdir(dir_name)
    assert isfile(dir_name) is False


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_isfile_with_link(smb_share):
    src_filename = "%s\\file.txt" % smb_share
    dst_filename = "%s\\link.txt" % smb_share

    with open_file(src_filename, mode="w") as fd:
        fd.write("content")
    symlink(src_filename, dst_filename)

    assert isfile(dst_filename) is True


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_isfile_with_broken_link(smb_share):
    src_filename = "%s\\file.txt" % smb_share
    dst_filename = "%s\\link.txt" % smb_share

    symlink(src_filename, dst_filename)

    assert isfile(dst_filename) is False


def test_isdir_missing(smb_share):
    assert isdir("%s\\missing" % smb_share) is False


def test_isdir_no_path(smb_share):
    assert isdir("%s\\missing\\dir" % smb_share) is False


def test_isdir_with_file(smb_share):
    filename = "%s\\file.txt" % smb_share
    with open_file(filename, mode="w") as fd:
        fd.write("content")
    assert isdir(filename) is False


def test_isdir_with_dir(smb_share):
    dir_name = "%s\\dir" % smb_share
    mkdir(dir_name)
    assert isdir(dir_name) is True


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_isdir_with_link(smb_share):
    src_dir_name = "%s\\dir" % smb_share
    dst_dir_name = "%s\\link" % smb_share

    mkdir(src_dir_name)
    symlink(src_dir_name, dst_dir_name)

    assert isdir(dst_dir_name) is True


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_isdir_with_broken_link(smb_share):
    src_dir_name = "%s\\dir" % smb_share
    dst_dir_name = "%s\\link" % smb_share

    symlink(src_dir_name, dst_dir_name, target_is_directory=True)

    assert isdir(dst_dir_name) is False


def test_islink_missing(smb_share):
    assert islink("%s\\missing" % smb_share) is False


def test_islink_no_path(smb_share):
    assert islink("%s\\missing\\dir" % smb_share) is False


def test_islink_with_file(smb_share):
    filename = "%s\\file.txt" % smb_share
    with open_file(filename, mode="w") as fd:
        fd.write("content")
    assert islink(filename) is False


def test_islink_with_dir(smb_share):
    dir_name = "%s\\dir" % smb_share
    mkdir(dir_name)
    assert islink(dir_name) is False


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_islink_with_file_link(smb_share):
    src_filename = "%s\\file.txt" % smb_share
    dst_filename = "%s\\link.txt" % smb_share

    with open_file(src_filename, mode="w") as fd:
        fd.write("content")
    symlink(src_filename, dst_filename)

    assert islink(dst_filename) is True


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_islink_with_broken_file_link(smb_share):
    src_filename = "%s\\file.txt" % smb_share
    dst_filename = "%s\\link.txt" % smb_share

    symlink(src_filename, dst_filename)

    assert islink(dst_filename) is True


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_islink_with_dir_link(smb_share):
    src_dir_name = "%s\\dir" % smb_share
    dst_dir_name = "%s\\link" % smb_share

    mkdir(src_dir_name)
    symlink(src_dir_name, dst_dir_name)

    assert islink(dst_dir_name) is True


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_islink_with_broken_dir_link(smb_share):
    src_dir_name = "%s\\dir" % smb_share
    dst_dir_name = "%s\\link" % smb_share

    symlink(src_dir_name, dst_dir_name, target_is_directory=True)

    assert islink(dst_dir_name) is True


def test_samefile_with_different_files(smb_share):
    file1 = "%s\\file1.txt" % smb_share
    file2 = "%s\\file2.txt" % smb_share

    with open_file(file1, mode="w") as fd:
        fd.write("content")

    with open_file(file2, mode="w") as fd:
        fd.write("content")

    assert samefile(file1, file2) is False


def test_samefile_with_hardlink(smb_share):
    file1 = "%s\\file1.txt" % smb_share
    file2 = "%s\\file2.txt" % smb_share

    with open_file(file1, mode="w") as fd:
        fd.write("content")

    link(file1, file2)

    assert samefile(file1, file2) is True


def test_samefile_missing_path1(smb_share):
    file1 = "%s\\file1.txt" % smb_share
    file2 = "%s\\file2.txt" % smb_share

    with open_file(file1, mode="w") as fd:
        fd.write("content")

    expected = "[NtStatus 0xc0000034] No such file or directory: "
    with pytest.raises(OSError, match=re.escape(expected)):
        samefile(file1, file2)


def test_samefile_missing_path2(smb_share):
    file1 = "%s\\file1.txt" % smb_share
    file2 = "%s\\file2.txt" % smb_share

    with open_file(file2, mode="w") as fd:
        fd.write("content")

    expected = "[NtStatus 0xc0000034] No such file or directory: "
    with pytest.raises(OSError, match=re.escape(expected)):
        samefile(file1, file2)


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_samefile_with_symlink(smb_share):
    file1 = "%s\\file1.txt" % smb_share
    file2 = "%s\\file2.txt" % smb_share

    with open_file(file1, mode="w") as fd:
        fd.write("content")

    symlink(file1, file2)

    assert samefile(file1, file2) is True


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_samefile_with_broken_symlink(smb_share):
    file1 = "%s\\file1.txt" % smb_share
    file2 = "%s\\file2.txt" % smb_share

    symlink(file1, file2)

    expected = "[NtStatus 0xc0000034] No such file or directory: "
    with pytest.raises(OSError, match=re.escape(expected)):
        samefile(file1, file2)
