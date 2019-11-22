# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import division

import ntpath
import os
import pytest
import re
import shutil
import stat
import sys

from smbclient import (
    listdir,
    makedirs,
    mkdir,
    open_file,
    readlink,
    remove,
    rmdir,
    stat as smbclient_stat,
    symlink,
    utime,
)

from smbclient._io import (
    set_info,
    SMBFileTransaction,
    SMBRawIO,
)

from smbclient.path import (
    exists,
    islink,
    samefile,
)

from smbclient.shutil import (
    copy,
    copy2,
    copyfile,
    copymode,
    copystat,
    copytree,
    rmtree,
)

from smbprotocol.exceptions import (
    SMBOSError,
)

from smbprotocol.file_info import (
    FileBasicInformation,
)

from smbprotocol.open import (
    CreateOptions,
    FileAttributes,
    FilePipePrinterAccessMask,
)


def _set_file_attributes(path, attributes):
    with SMBRawIO(path, mode='rb', create_options=CreateOptions.FILE_OPEN_REPARSE_POINT,
                  desired_access=FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES) as fd:
        with SMBFileTransaction(fd) as transaction:
            basic_info = FileBasicInformation()
            basic_info['file_attributes'] = attributes
            set_info(transaction, basic_info)


def test_copy(smb_share):
    src_filename = "%s\\source.txt" % smb_share
    dst_filename = "%s\\target.txt" % smb_share

    with open_file(src_filename, mode='w', file_attributes=FileAttributes.FILE_ATTRIBUTE_READONLY) as fd:
        fd.write(u"content")

    actual = copy(src_filename, dst_filename)
    assert actual == dst_filename

    with open_file(dst_filename) as fd:
        assert fd.read() == u"content"

    src_stat = smbclient_stat(src_filename)

    actual = smbclient_stat(dst_filename)
    assert actual.st_atime != src_stat.st_atime
    assert actual.st_mtime != src_stat.st_mtime
    assert actual.st_ctime != src_stat.st_ctime
    assert actual.st_chgtime != src_stat.st_chgtime
    assert actual.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == FileAttributes.FILE_ATTRIBUTE_READONLY


def test_copy_with_dir_as_target(smb_share):
    src_filename = "%s\\source.txt" % smb_share
    dst_filename = "%s\\directory" % smb_share
    mkdir(dst_filename)

    with open_file(src_filename, mode='w') as fd:
        fd.write(u"content")

    actual = copy(src_filename, dst_filename)
    assert actual == ntpath.join(dst_filename, "source.txt")

    with open_file("%s\\source.txt" % dst_filename) as fd:
        assert fd.read() == u"content"

    src_stat = smbclient_stat(src_filename)

    actual = smbclient_stat("%s\\source.txt" % dst_filename)
    assert actual.st_atime != src_stat.st_atime
    assert actual.st_mtime != src_stat.st_mtime
    assert actual.st_ctime != src_stat.st_ctime
    assert actual.st_chgtime != src_stat.st_chgtime
    assert actual.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == 0


def test_copy_raises_when_source_and_target_identical_remote(smb_share):
    filename = "%s\\file.txt" % smb_share
    with open_file(filename, mode='w') as fd:
        fd.write(u"content")

    expected = "are the same file"
    with pytest.raises(Exception, match=re.escape(expected)):
        copy(filename, filename)


def test_copy_raises_when_source_and_target_identical_local(tmpdir):
    test_dir = tmpdir.mkdir('test').strpath
    filename = os.path.join(test_dir, 'file.txt')
    with open(filename, mode='w') as fd:
        fd.write(u"content")

    expected = "are the same file"
    with pytest.raises(Exception, match=re.escape(expected)):
        copy(filename, filename)


@pytest.mark.skipif(os.name != "nt" and not os.environ.get('SMB_FORCE', False),
                    reason="Samba does not update timestamps")
def test_copy2(smb_share):
    src_filename = "%s\\source.txt" % smb_share
    dst_filename = "%s\\target.txt" % smb_share

    with open_file(src_filename, mode='w', file_attributes=FileAttributes.FILE_ATTRIBUTE_READONLY) as fd:
        fd.write(u"content")
    utime(src_filename, times=(1024, 1024))

    actual = copy2(src_filename, dst_filename)
    assert actual == dst_filename

    with open_file(dst_filename) as fd:
        assert fd.read() == u"content"

    src_stat = smbclient_stat(src_filename)

    actual = smbclient_stat(dst_filename)
    assert actual.st_atime == 1024
    assert actual.st_mtime == 1024
    assert actual.st_ctime != src_stat.st_ctime
    assert actual.st_chgtime != src_stat.st_chgtime
    assert actual.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == FileAttributes.FILE_ATTRIBUTE_READONLY


@pytest.mark.skipif(os.name != "nt" and not os.environ.get('SMB_FORCE', False),
                    reason="Samba does not update timestamps")
def test_copy2_with_dir_as_target(smb_share):
    src_filename = "%s\\source.txt" % smb_share
    dst_filename = "%s\\directory" % smb_share
    mkdir(dst_filename)

    with open_file(src_filename, mode='w') as fd:
        fd.write(u"content")
    utime(src_filename, times=(1024, 1024))

    actual = copy2(src_filename, dst_filename)
    assert actual == ntpath.join(dst_filename, "source.txt")

    with open_file("%s\\source.txt" % dst_filename) as fd:
        assert fd.read() == u"content"

    src_stat = smbclient_stat(src_filename)

    actual = smbclient_stat("%s\\source.txt" % dst_filename)
    assert actual.st_atime == 1024
    assert actual.st_mtime == 1024
    assert actual.st_ctime != src_stat.st_ctime
    assert actual.st_chgtime != src_stat.st_chgtime
    assert actual.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == 0


def test_copy2_raises_when_source_and_target_identical_remote(smb_share):
    filename = "%s\\file.txt" % smb_share
    with open_file(filename, mode='w') as fd:
        fd.write(u"content")

    expected = "are the same file"
    with pytest.raises(Exception, match=re.escape(expected)):
        copy2(filename, filename)


def test_copy2_raises_when_source_and_target_identical_local(tmpdir):
    test_dir = tmpdir.mkdir('test').strpath
    filename = os.path.join(test_dir, 'file.txt')
    with open(filename, mode='w') as fd:
        fd.write(u"content")

    expected = "are the same file"
    with pytest.raises(Exception, match=re.escape(expected)):
        copy2(filename, filename)


def test_copyfile_identical(smb_share):
    filename = "%s\\file.txt" % smb_share
    with open_file(filename, mode='w') as fd:
        fd.write(u"content")

    expected = "are the same file"
    with pytest.raises(Exception, match=re.escape(expected)):
        copyfile(filename, filename)


def test_copyfile_remote_to_remote(smb_share):
    src_filename = "%s\\source.txt" % smb_share
    dst_filename = "%s\\target.txt" % smb_share

    with open_file(src_filename, mode='w') as fd:
        fd.write(u"content")

    actual = copyfile(src_filename, dst_filename)
    assert actual == dst_filename

    with open_file(dst_filename) as fd:
        assert fd.read() == u"content"


def test_copyfile_remote_to_remote_existing(smb_share):
    src_filename = "%s\\source.txt" % smb_share
    dst_filename = "%s\\target.txt" % smb_share

    with open_file(src_filename, mode='w') as fd:
        fd.write(u"content")

    with open_file(dst_filename, mode='w') as fd:
        fd.write(u"something different")

    actual = copyfile(src_filename, dst_filename)
    assert actual == dst_filename

    with open_file(dst_filename) as fd:
        assert fd.read() == u"content"


def test_copyfile_local_to_remote(smb_share, tmpdir):
    test_dir = tmpdir.mkdir("test")
    src_filename = "%s\\source.txt" % test_dir
    dst_filename = "%s\\target.txt" % smb_share

    with open(src_filename, mode='w') as fd:
        fd.write(u"content")

    actual = copyfile(src_filename, dst_filename)
    assert actual == dst_filename

    with open_file(dst_filename) as fd:
        assert fd.read() == u"content"


def test_copyfile_remote_to_local(smb_share, tmpdir):
    test_dir = tmpdir.mkdir("test")
    src_filename = "%s\\source.txt" % smb_share
    dst_filename = "%s\\target.txt" % test_dir

    with open_file(src_filename, mode='w') as fd:
        fd.write(u"content")

    actual = copyfile(src_filename, dst_filename)
    assert actual == dst_filename

    with open(dst_filename) as fd:
        assert fd.read() == u"content"


def test_copyfile_local_to_local(tmpdir):
    test_dir = tmpdir.mkdir("test")
    src_filename = "%s\\source.txt" % test_dir
    dst_filename = "%s\\target.txt" % test_dir

    with open(src_filename, mode='w') as fd:
        fd.write(u"content")

    actual = copyfile(src_filename, dst_filename)
    assert actual == dst_filename

    with open(dst_filename) as fd:
        assert fd.read() == u"content"


def test_copyfile_fail_src_is_dir(smb_share):
    src_filename = "%s\\source" % smb_share
    dst_filename = "%s\\target.txt" % smb_share

    mkdir(src_filename)

    expected = "[NtStatus 0xc00000ba] Is a directory: "
    with pytest.raises(OSError, match=re.escape(expected)):
        copyfile(src_filename, dst_filename)


def test_copyfile_fail_dst_is_dir(smb_share):
    src_filename = "%s\\source.txt" % smb_share
    dst_filename = "%s\\target" % smb_share

    with open_file(src_filename, mode='w') as fd:
        fd.write(u"content")

    mkdir(dst_filename)

    expected = "[NtStatus 0xc00000ba] Is a directory: "
    with pytest.raises(OSError, match=re.escape(expected)):
        copyfile(src_filename, dst_filename)


@pytest.mark.skipif(os.name != "nt" and not os.environ.get('SMB_FORCE', False),
                    reason="cannot create symlinks on Samba")
def test_copyfile_symlink_follow(smb_share):
    src_filename = "%s\\source.txt" % smb_share
    src_link = "%s\\source-link.txt" % smb_share
    dst_filename = "%s\\target.txt" % smb_share

    with open_file(src_filename, mode='w') as fd:
        fd.write(u"content")

    symlink(src_filename, src_link)
    actual = copyfile(src_link, dst_filename)
    assert actual == dst_filename

    with open_file(dst_filename, mode='r') as fd:
        assert fd.read() == u"content"

    assert not islink(dst_filename)


@pytest.mark.skipif(os.name != "nt" and not os.environ.get('SMB_FORCE', False),
                    reason="cannot create symlinks on Samba")
def test_copyfile_symlink_dont_follow(smb_share):
    src_filename = "%s\\source.txt" % smb_share
    src_link = "%s\\source-link.txt" % smb_share
    dst_filename = "%s\\target.txt" % smb_share

    with open_file(src_filename, mode='w') as fd:
        fd.write(u"content")

    symlink(src_filename, src_link)
    actual = copyfile(src_link, dst_filename, follow_symlinks=False)
    assert actual == dst_filename

    with open_file(dst_filename, mode='r') as fd:
        assert fd.read() == u"content"

    assert islink(dst_filename)
    assert readlink(dst_filename) == ntpath.normpath(src_filename)


@pytest.mark.skipif(os.name != "nt" and not os.environ.get('SMB_FORCE', False),
                    reason="cannot create symlinks on Samba")
def test_copyfile_symlink_across_boundary_fail(smb_share):
    src_filename = "%s\\link" % smb_share

    symlink("%s\\missing" % smb_share, src_filename)

    expected = "Cannot copy a symlink on different roots."
    with pytest.raises(ValueError, match=re.escape(expected)):
        copyfile(src_filename, "/tmp", follow_symlinks=False)


def test_copymode_of_file(smb_share):
    src_filename = "%s\\source.txt" % smb_share
    dst_filename = "%s\\target.txt" % smb_share

    with open_file(src_filename, mode='w', file_attributes=FileAttributes.FILE_ATTRIBUTE_READONLY) as fd:
        fd.write(u"content")

    with open_file(dst_filename, mode='w') as fd:
        fd.write(u"content")

    copymode(src_filename, dst_filename)

    actual = smbclient_stat(dst_filename).st_file_attributes
    assert actual & FileAttributes.FILE_ATTRIBUTE_READONLY == FileAttributes.FILE_ATTRIBUTE_READONLY

    remove(src_filename)

    with open_file(src_filename, mode='w') as fd:
        fd.write(u"content")

    copymode(src_filename, dst_filename)

    actual = smbclient_stat(dst_filename).st_file_attributes
    assert actual & FileAttributes.FILE_ATTRIBUTE_READONLY == 0


def test_copymode_of_file_with_no_attributes(smb_share):
    src_filename = "%s\\source.txt" % smb_share
    dst_filename = "%s\\target.txt" % smb_share

    with open_file(src_filename, mode='w', file_attributes=FileAttributes.FILE_ATTRIBUTE_READONLY) as fd:
        fd.write(u"content")

    with open_file(dst_filename, mode='w') as fd:
        fd.write(u"content")

    copymode(src_filename, dst_filename)

    actual = smbclient_stat(dst_filename).st_file_attributes
    assert actual & FileAttributes.FILE_ATTRIBUTE_READONLY == FileAttributes.FILE_ATTRIBUTE_READONLY

    remove(src_filename)

    with open_file(src_filename, mode='w') as fd:
        fd.write(u"content")

    # Remove the Archive attribute on the dest file to simulate the file having only just READONLY.
    _set_file_attributes(dst_filename, FileAttributes.FILE_ATTRIBUTE_READONLY)

    copymode(src_filename, dst_filename)

    actual = smbclient_stat(dst_filename).st_file_attributes
    assert actual == FileAttributes.FILE_ATTRIBUTE_NORMAL


def test_copymode_of_dir(smb_share):
    src_dirname = "%s\\source" % smb_share
    dst_dirname = "%s\\target" % smb_share

    with open_file(src_dirname, mode='xb', file_type='dir', file_attributes=FileAttributes.FILE_ATTRIBUTE_READONLY,
                   buffering=0):
        pass
    mkdir(dst_dirname)

    copymode(src_dirname, dst_dirname)

    actual = smbclient_stat(dst_dirname).st_file_attributes
    assert actual & FileAttributes.FILE_ATTRIBUTE_READONLY == FileAttributes.FILE_ATTRIBUTE_READONLY

    rmdir(src_dirname)
    mkdir(src_dirname)

    copymode(src_dirname, dst_dirname)

    actual = smbclient_stat(dst_dirname).st_file_attributes
    assert actual & FileAttributes.FILE_ATTRIBUTE_READONLY == 0


def test_copymode_local_to_remote(smb_share, tmpdir):
    test_dir = tmpdir.mkdir("test")
    src_filename = "%s\\source.txt" % test_dir
    dst_filename = "%s\\target.txt" % smb_share

    with open(src_filename, mode='w') as fd:
        fd.write(u"content")
    os.chmod(src_filename, stat.S_IREAD)

    with open_file(dst_filename, mode='w') as fd:
        fd.write(u"content")

    copymode(src_filename, dst_filename)

    actual = smbclient_stat(dst_filename).st_file_attributes
    assert actual & FileAttributes.FILE_ATTRIBUTE_READONLY == FileAttributes.FILE_ATTRIBUTE_READONLY

    os.chmod(src_filename, stat.S_IWRITE)  # Needed when running on Windows as os.remove will fail to remove.
    os.remove(src_filename)
    with open(src_filename, mode='w') as fd:
        fd.write(u"content")

    copymode(src_filename, dst_filename)

    actual = smbclient_stat(dst_filename).st_file_attributes
    assert actual & FileAttributes.FILE_ATTRIBUTE_READONLY == 0


def test_copymode_remote_to_local(smb_share, tmpdir):
    test_dir = tmpdir.mkdir("test")
    src_filename = "%s\\source.txt" % smb_share
    dst_filename = "%s\\target.txt" % test_dir

    with open_file(src_filename, mode='w', file_attributes=FileAttributes.FILE_ATTRIBUTE_READONLY) as fd:
        fd.write(u"content")

    with open(dst_filename, mode='w') as fd:
        fd.write(u"content")

    copymode(src_filename, dst_filename)

    actual = os.stat(dst_filename).st_mode
    assert stat.S_IMODE(actual) & stat.S_IWRITE == 0

    remove(src_filename)
    with open_file(src_filename, mode='w') as fd:
        fd.write(u"content")

    copymode(src_filename, dst_filename)

    actual = os.stat(dst_filename).st_mode
    assert stat.S_IMODE(actual) & stat.S_IWRITE == stat.S_IWRITE


def test_copymode_local_to_local(tmpdir):
    test_dir = tmpdir.mkdir("test")
    src_filename = "%s\\source.txt" % test_dir
    dst_filename = "%s\\target.txt" % test_dir

    with open(src_filename, mode='w') as fd:
        fd.write(u"content")
    os.chmod(src_filename, stat.S_IREAD)

    with open(dst_filename, mode='w') as fd:
        fd.write(u"content")

    copymode(src_filename, dst_filename)

    actual = os.stat(dst_filename).st_mode
    assert stat.S_IMODE(actual) & stat.S_IWRITE == 0

    os.chmod(src_filename, stat.S_IWRITE)  # Needed when running on Windows as os.remove will fail to remove.
    os.remove(src_filename)
    with open(src_filename, mode='w') as fd:
        fd.write(u"content")

    copymode(src_filename, dst_filename)

    actual = os.stat(dst_filename).st_mode
    assert stat.S_IMODE(actual) & stat.S_IWRITE == stat.S_IWRITE


@pytest.mark.skipif(os.name == 'nt',
                    reason="Windows and local symlinks fall flat with local paths.")
def test_copymode_local_to_local_symlink_follow(tmpdir):
    test_dir = tmpdir.mkdir('test')
    src_filename = "%s\\source.txt" % test_dir
    dst_filename = "%s\\target.txt" % test_dir

    with open(src_filename, mode='w') as fd:
        fd.write(u"content")
    os.chmod(src_filename, stat.S_IREAD)

    with open(dst_filename, mode='w') as fd:
        fd.write(u"content")

    src_link = "%s\\source-link.txt" % test_dir
    dst_link = "%s\\target-link.txt" % test_dir

    os.symlink(src_filename, src_link)
    os.symlink(dst_filename, dst_link)

    copymode(src_link, dst_link)

    actual_file = os.stat(dst_filename).st_mode
    assert stat.S_IMODE(actual_file) & stat.S_IWRITE == 0

    actual_link = os.lstat(dst_link).st_mode
    assert stat.S_IMODE(actual_link) & stat.S_IWRITE == stat.S_IWRITE

    os.chmod(src_filename, stat.S_IWRITE)  # Needed when running on Windows as os.remove will fail to remove.
    os.remove(src_filename)
    with open(src_filename, mode='w') as fd:
        fd.write(u"content")

    copymode(src_link, dst_link)

    actual_file = os.stat(dst_filename).st_mode
    assert stat.S_IMODE(actual_file) & stat.S_IWRITE == stat.S_IWRITE

    actual_link = os.lstat(dst_link).st_mode
    assert stat.S_IMODE(actual_link) & stat.S_IWRITE == stat.S_IWRITE


@pytest.mark.skipif((os.name == 'nt' and sys.version_info[0] < 3) or
                    (sys.version_info[0] == 3 and sys.version_info[1] == 5),
                    reason="Python 3.5 errors out on os.chmod(follow_symlinks=False)")
def test_copymode_local_to_local_symlink_dont_follow(tmpdir):
    test_dir = tmpdir.mkdir('test')
    src_filename = "%s\\source.txt" % test_dir
    dst_filename = "%s\\target.txt" % test_dir

    with open(src_filename, mode='w') as fd:
        fd.write(u"content")
    os.chmod(src_filename, stat.S_IREAD)

    with open(dst_filename, mode='w') as fd:
        fd.write(u"content")

    src_link = "%s\\source-link.txt" % test_dir
    dst_link = "%s\\target-link.txt" % test_dir

    os.symlink(src_filename, src_link)
    os.symlink(dst_filename, dst_link)

    expected = "chmod: follow_symlinks unavailable on this platform"
    with pytest.raises(NotImplementedError, match=re.escape(expected)):
        copymode(src_link, dst_link, follow_symlinks=False)


def test_copymode_missing_src(smb_share):
    with pytest.raises(OSError):
        copymode("%s\\missing.txt", smb_share)


def test_copymode_missing_dst(smb_share):
    with pytest.raises(OSError):
        copymode(smb_share, "%s\\missing.txt" % smb_share)


@pytest.mark.skipif(os.name != "nt" and not os.environ.get('SMB_FORCE', False),
                    reason="cannot create symlinks on Samba")
def test_copymode_symlink_follow(smb_share):
    src_filename = "%s\\source.txt" % smb_share
    dst_filename = "%s\\target.txt" % smb_share

    with open_file(src_filename, mode='w', file_attributes=FileAttributes.FILE_ATTRIBUTE_READONLY) as fd:
        fd.write(u"content")

    with open_file(dst_filename, mode='w') as fd:
        fd.write(u"content")

    src_link = "%s\\source-link.txt" % smb_share
    dst_link = "%s\\target-link.txt" % smb_share

    symlink(src_filename, src_link)
    symlink(dst_filename, dst_link)

    copymode(src_link, dst_link)

    actual_file = smbclient_stat(dst_link).st_file_attributes
    assert actual_file & FileAttributes.FILE_ATTRIBUTE_READONLY == FileAttributes.FILE_ATTRIBUTE_READONLY

    actual_link = smbclient_stat(dst_link, follow_symlinks=False).st_file_attributes
    assert actual_link & FileAttributes.FILE_ATTRIBUTE_READONLY == 0

    remove(src_filename)
    with open_file(src_filename, mode='w') as fd:
        fd.write(u"content")

    copymode(src_link, dst_link)

    actual_file = smbclient_stat(dst_link).st_file_attributes
    assert actual_file & FileAttributes.FILE_ATTRIBUTE_READONLY == 0

    actual_link = smbclient_stat(dst_link, follow_symlinks=False).st_file_attributes
    assert actual_link & FileAttributes.FILE_ATTRIBUTE_READONLY == 0


@pytest.mark.skipif(os.name != "nt" and not os.environ.get('SMB_FORCE', False),
                    reason="cannot create symlinks on Samba")
def test_copymode_symlink_dont_follow(smb_share):
    src_filename = "%s\\source.txt" % smb_share
    dst_filename = "%s\\target.txt" % smb_share

    with open_file(src_filename, mode='w') as fd:
        fd.write(u"content")

    with open_file(dst_filename, mode='w') as fd:
        fd.write(u"content")

    src_link = "%s\\source-link.txt" % smb_share
    dst_link = "%s\\target-link.txt" % smb_share

    symlink(src_filename, src_link)
    symlink(dst_filename, dst_link)

    copymode(src_link, dst_link, follow_symlinks=False)

    actual_file = smbclient_stat(dst_filename).st_file_attributes
    assert actual_file & FileAttributes.FILE_ATTRIBUTE_READONLY == 0

    actual_link = smbclient_stat(dst_link, follow_symlinks=False).st_file_attributes
    assert actual_link & FileAttributes.FILE_ATTRIBUTE_READONLY == 0

    remove(src_filename)

    _set_file_attributes(src_link, FileAttributes.FILE_ATTRIBUTE_READONLY)

    copymode(src_link, dst_link, follow_symlinks=False)

    actual_file = smbclient_stat(dst_link).st_file_attributes
    assert actual_file & FileAttributes.FILE_ATTRIBUTE_READONLY == 0

    actual_link = smbclient_stat(dst_link, follow_symlinks=False).st_file_attributes
    assert actual_link & FileAttributes.FILE_ATTRIBUTE_READONLY == FileAttributes.FILE_ATTRIBUTE_READONLY


@pytest.mark.skipif(os.name != "nt" and not os.environ.get('SMB_FORCE', False),
                    reason="Samba does not update timestamps")
def test_copystat_of_file(smb_share):
    src_filename = "%s\\source.txt" % smb_share
    dst_filename = "%s\\target.txt" % smb_share

    with open_file(src_filename, mode='w', file_attributes=FileAttributes.FILE_ATTRIBUTE_READONLY) as fd:
        fd.write(u"content")
    utime(src_filename, (1024, 1024))

    with open_file(dst_filename, mode='w') as fd:
        fd.write(u"content")

    copystat(src_filename, dst_filename)

    actual = smbclient_stat(dst_filename)
    assert actual.st_atime == 1024
    assert actual.st_mtime == 1024
    assert actual.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == FileAttributes.FILE_ATTRIBUTE_READONLY


@pytest.mark.skipif(os.name != "nt" and not os.environ.get('SMB_FORCE', False),
                    reason="Samba does not update timestamps")
def test_copystat_of_dir(smb_share):
    src_dirname = "%s\\source" % smb_share
    dst_dirname = "%s\\target" % smb_share

    with open_file(src_dirname, mode='xb', file_type='dir', file_attributes=FileAttributes.FILE_ATTRIBUTE_READONLY,
                   buffering=0):
        pass
    utime(src_dirname, (-1024, -1024))  # Test out dates earlier than EPOCH.

    mkdir(dst_dirname)

    copystat(src_dirname, dst_dirname)

    actual = smbclient_stat(dst_dirname)
    assert actual.st_atime == -1024
    assert actual.st_mtime == -1024
    assert actual.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == FileAttributes.FILE_ATTRIBUTE_READONLY


@pytest.mark.skipif(os.name != "nt" and not os.environ.get('SMB_FORCE', False),
                    reason="Samba does not update timestamps")
def test_copystat_local_to_remote(smb_share, tmpdir):
    test_dir = tmpdir.mkdir("test")
    src_filename = "%s\\source.txt" % test_dir
    dst_filename = "%s\\target.txt" % smb_share

    with open(src_filename, mode='w') as fd:
        fd.write(u"content")
    os.chmod(src_filename, stat.S_IREAD)
    os.utime(src_filename, (1024, 1024))

    with open_file(dst_filename, mode='w') as fd:
        fd.write(u"content")

    copystat(src_filename, dst_filename)

    actual = smbclient_stat(dst_filename)
    assert actual.st_atime == 1024
    assert actual.st_mtime == 1024
    assert actual.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == FileAttributes.FILE_ATTRIBUTE_READONLY


@pytest.mark.skipif(os.name != "nt" and not os.environ.get('SMB_FORCE', False),
                    reason="Samba does not update timestamps")
def test_copystat_remote_to_local(smb_share, tmpdir):
    test_dir = tmpdir.mkdir("test")
    src_filename = "%s\\source.txt" % smb_share
    dst_filename = "%s\\target.txt" % test_dir

    with open_file(src_filename, mode='w', file_attributes=FileAttributes.FILE_ATTRIBUTE_READONLY) as fd:
        fd.write(u"content")
    utime(src_filename, times=(1024, 1024))

    with open(dst_filename, mode='w') as fd:
        fd.write(u"content")

    copystat(src_filename, dst_filename)

    actual = os.stat(dst_filename)
    assert actual.st_atime == 1024
    assert actual.st_mtime == 1024
    assert stat.S_IMODE(actual.st_mode) & stat.S_IWRITE == 0


def test_copystat_local_to_local(tmpdir):
    test_dir = tmpdir.mkdir("test")
    src_filename = "%s\\source.txt" % test_dir
    dst_filename = "%s\\target.txt" % test_dir

    with open(src_filename, mode='w') as fd:
        fd.write(u"content")
    os.chmod(src_filename, stat.S_IREAD)
    os.utime(src_filename, (1024, 1024))

    with open(dst_filename, mode='w') as fd:
        fd.write(u"content")

    copystat(src_filename, dst_filename)

    actual = os.stat(dst_filename)
    assert actual.st_atime == 1024
    assert actual.st_mtime == 1024
    assert stat.S_IMODE(actual.st_mode) & stat.S_IWRITE == 0


@pytest.mark.skipif(os.name == 'nt',
                    reason="Windows and local symlinks fall flat with local paths.")
def test_copystat_local_to_local_symlink_follow(tmpdir):
    test_dir = tmpdir.mkdir('test')
    src_filename = "%s\\source.txt" % test_dir
    dst_filename = "%s\\target.txt" % test_dir

    with open(src_filename, mode='w') as fd:
        fd.write(u"content")
    os.chmod(src_filename, stat.S_IREAD)
    os.utime(src_filename, (1024, 1024))

    with open(dst_filename, mode='w') as fd:
        fd.write(u"content")

    src_link = "%s\\source-link.txt" % test_dir
    dst_link = "%s\\target-link.txt" % test_dir

    os.symlink(src_filename, src_link)
    os.symlink(dst_filename, dst_link)

    copystat(src_link, dst_link)

    actual_file = os.stat(dst_filename)
    assert actual_file.st_atime == 1024
    assert actual_file.st_mtime == 1024
    assert stat.S_IMODE(actual_file.st_mode) & stat.S_IWRITE == 0

    actual_link = os.lstat(dst_link)
    assert actual_link.st_atime != 1024
    assert actual_link.st_mtime != 1024
    assert stat.S_IMODE(actual_link.st_mode) & stat.S_IWRITE == stat.S_IWRITE


@pytest.mark.skipif((os.name == 'nt' and sys.version_info[0] < 3) or
                    (sys.version_info[0] == 3 and sys.version_info[1] == 5),
                    reason="Python 3.5 errors out on os.chmod(follow_symlinks=False)")
def test_copystat_local_to_local_symlink_dont_follow_fail(tmpdir):
    test_dir = tmpdir.mkdir('test')
    src_filename = "%s\\source.txt" % test_dir
    dst_filename = "%s\\target.txt" % test_dir

    with open(src_filename, mode='w') as fd:
        fd.write(u"content")
    os.chmod(src_filename, stat.S_IREAD)

    with open(dst_filename, mode='w') as fd:
        fd.write(u"content")

    src_link = "%s\\source-link.txt" % test_dir
    dst_link = "%s\\target-link.txt" % test_dir

    os.symlink(src_filename, src_link)
    os.symlink(dst_filename, dst_link)

    expected = "follow_symlinks unavailable on this platform"
    with pytest.raises(NotImplementedError, match=re.escape(expected)):
        copystat(src_link, dst_link, follow_symlinks=False)


@pytest.mark.skipif(os.name != "nt" and not os.environ.get('SMB_FORCE', False),
                    reason="cannot create symlinks on Samba")
def test_copystat_symlink_follow(smb_share):
    src_filename = "%s\\source.txt" % smb_share
    dst_filename = "%s\\target.txt" % smb_share

    with open_file(src_filename, mode='w', file_attributes=FileAttributes.FILE_ATTRIBUTE_READONLY) as fd:
        fd.write(u"content")
    utime(src_filename, times=(1024, 1024))

    with open_file(dst_filename, mode='w') as fd:
        fd.write(u"content")

    src_link = "%s\\source-link.txt" % smb_share
    dst_link = "%s\\target-link.txt" % smb_share

    symlink(src_filename, src_link)
    symlink(dst_filename, dst_link)

    copystat(src_link, dst_link)

    actual_file = smbclient_stat(dst_link)
    assert actual_file.st_atime == 1024
    assert actual_file.st_mtime == 1024
    assert actual_file.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == \
        FileAttributes.FILE_ATTRIBUTE_READONLY

    actual_link = smbclient_stat(dst_link, follow_symlinks=False)
    assert actual_link.st_atime != 1024
    assert actual_link.st_mtime != 1024
    assert actual_link.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == 0


@pytest.mark.skipif(os.name != "nt" and not os.environ.get('SMB_FORCE', False),
                    reason="cannot create symlinks on Samba")
def test_copystat_symlink_dont_follow(smb_share):
    src_filename = "%s\\source.txt" % smb_share
    dst_filename = "%s\\target.txt" % smb_share

    with open_file(src_filename, mode='w') as fd:
        fd.write(u"content")

    with open_file(dst_filename, mode='w') as fd:
        fd.write(u"content")

    src_link = "%s\\source-link.txt" % smb_share
    dst_link = "%s\\target-link.txt" % smb_share

    symlink(src_filename, src_link)
    symlink(dst_filename, dst_link)

    _set_file_attributes(src_link, FileAttributes.FILE_ATTRIBUTE_READONLY)
    utime(src_link, times=(1024, 1024), follow_symlinks=False)

    copystat(src_link, dst_link, follow_symlinks=False)

    actual_file = smbclient_stat(dst_link)
    assert actual_file.st_atime != 1024
    assert actual_file.st_mtime != 1024
    assert actual_file.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == 0

    actual_link = smbclient_stat(dst_link, follow_symlinks=False)
    assert actual_link.st_atime == 1024
    assert actual_link.st_mtime == 1024
    assert actual_link.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == \
        FileAttributes.FILE_ATTRIBUTE_READONLY


def test_copystat_missing_src(smb_share):
    with pytest.raises(OSError):
        copystat("%s\\missing.txt", smb_share)


def test_copystat_missing_dst(smb_share):
    with pytest.raises(OSError):
        copystat(smb_share, "%s\\missing.txt" % smb_share)


def test_copytree_missing_src_fail(smb_share):
    expected = "[NtStatus 0xc0000034] No such file or directory: "
    with pytest.raises(OSError, match=re.escape(expected)):
        copytree("%s\\missing" % smb_share, smb_share)


def test_copytree_missing_dst(smb_share):
    src_dirname = "%s\\source" % smb_share
    dst_dirname = "%s\\sub-folder\\target" % smb_share

    makedirs("%s\\dir1\\subdir1\\subdir2" % src_dirname)

    _set_file_attributes("%s\\dir1\\subdir1" % src_dirname, FileAttributes.FILE_ATTRIBUTE_READONLY)

    utime("%s\\dir1\\subdir1\\subdir2" % src_dirname, times=(1024, 1024))

    with open_file("%s\\file1.txt" % src_dirname, mode='w',
                   file_attributes=FileAttributes.FILE_ATTRIBUTE_READONLY) as fd:
        fd.write(u"file1.txt")

    with open_file("%s\\dir1\\file2.txt" % src_dirname, mode='w') as fd:
        fd.write(u"file2.txt")
    utime("%s\\dir1\\file2.txt" % src_dirname, times=(1024, 1024))

    with open_file("%s\\dir1\\subdir1\\file3.txt" % src_dirname, mode='w',
                   file_attributes=FileAttributes.FILE_ATTRIBUTE_READONLY) as fd:
        fd.write(u"file3.txt")

    actual = copytree(src_dirname, dst_dirname)

    assert actual == dst_dirname

    assert sorted(list(listdir(dst_dirname))) == ["dir1", "file1.txt"]
    assert sorted(list(listdir("%s\\dir1" % dst_dirname))) == ["file2.txt", "subdir1"]
    assert sorted(list(listdir("%s\\dir1\\subdir1" % dst_dirname))) == ["file3.txt", "subdir2"]
    assert sorted(list(listdir("%s\\dir1\\subdir1\\subdir2" % dst_dirname))) == []

    with open_file("%s\\file1.txt" % dst_dirname) as fd:
        assert fd.read() == u"file1.txt"
    with open_file("%s\\dir1\\file2.txt" % dst_dirname) as fd:
        assert fd.read() == u"file2.txt"
    with open_file("%s\\dir1\\subdir1\\file3.txt" % dst_dirname) as fd:
        assert fd.read() == u"file3.txt"

    file1_stat = smbclient_stat("%s\\file1.txt" % dst_dirname)
    assert file1_stat.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == \
        FileAttributes.FILE_ATTRIBUTE_READONLY

    file2_stat = smbclient_stat("%s\\dir1\\file2.txt" % dst_dirname)
    assert file2_stat.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == 0

    file3_stat = smbclient_stat("%s\\dir1\\subdir1\\file3.txt" % dst_dirname)
    assert file3_stat.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == \
        FileAttributes.FILE_ATTRIBUTE_READONLY

    dir1_stat = smbclient_stat("%s\\dir1" % dst_dirname)
    assert dir1_stat.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == 0

    subdir1_stat = smbclient_stat("%s\\dir1\\subdir1" % dst_dirname)
    assert subdir1_stat.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == \
        FileAttributes.FILE_ATTRIBUTE_READONLY

    subdir2_stat = smbclient_stat("%s\\dir1\\subdir1\\subdir2" % dst_dirname)
    assert subdir2_stat.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == 0

    # Samba server's cannot set the datetime so only run this if the server is supported.
    if os.name == 'nt' or os.environ.get('SMB_FORCE', False):
        assert file1_stat.st_atime != 1024
        assert file1_stat.st_mtime != 1024

        assert file2_stat.st_atime == 1024
        assert file2_stat.st_mtime == 1024

        assert file3_stat.st_atime != 1024
        assert file3_stat.st_mtime != 1024

        assert dir1_stat.st_atime != 1024
        assert dir1_stat.st_mtime != 1024

        assert subdir1_stat.st_atime != 1024
        assert subdir1_stat.st_mtime != 1024

        assert subdir2_stat.st_atime == 1024
        assert subdir2_stat.st_mtime == 1024


def test_copytree_existing_dst_fail(smb_share):
    src_dirname = "%s\\source" % smb_share
    dst_dirname = "%s\\target" % smb_share

    mkdir(src_dirname)
    mkdir(dst_dirname)

    expected = "[NtStatus 0xc0000035] File exists: "
    with pytest.raises(OSError, match=re.escape(expected)):
        copytree(src_dirname, dst_dirname)


def test_copytree_existing_dst_ignore(smb_share):
    src_dirname = "%s\\source" % smb_share
    dst_dirname = "%s\\target" % smb_share

    mkdir(src_dirname)

    with open_file("%s\\file1.txt" % src_dirname, mode='w') as fd:
        fd.write(u"file1.txt")

    with open_file("%s\\file2.txt" % src_dirname, mode='w') as fd:
        fd.write(u"file2.txt")

    with open_file("%s\\file3.txt" % src_dirname, mode='w') as fd:
        fd.write(u"file3.txt")

    actual = copytree(src_dirname, dst_dirname)
    assert actual == dst_dirname

    _set_file_attributes("%s\\file1.txt" % src_dirname, FileAttributes.FILE_ATTRIBUTE_NORMAL)
    remove("%s\\file2.txt" % dst_dirname)
    _set_file_attributes("%s\\file3.txt" % src_dirname, FileAttributes.FILE_ATTRIBUTE_READONLY)

    actual = copytree(src_dirname, dst_dirname, dirs_exist_ok=True)
    assert actual == dst_dirname

    file1_stat = smbclient_stat("%s\\file1.txt" % dst_dirname)
    assert file1_stat.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == 0

    file2_stat = smbclient_stat("%s\\file2.txt" % dst_dirname)
    assert file2_stat.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == 0

    file3_stat = smbclient_stat("%s\\file3.txt" % dst_dirname)
    assert file3_stat.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == \
        FileAttributes.FILE_ATTRIBUTE_READONLY


def test_copytree_with_ignore(smb_share):
    def ignore(name, children):
        if name.endswith(u'source'):
            assert sorted(children) == ['dir1', 'file1.txt']
            return ['file1.txt']
        elif name.endswith(u'subdir1'):
            assert sorted(children) == ['file3.txt', 'subdir2']
            return ['subdir2']
        else:
            assert sorted(children) == ['file2.txt', 'subdir1']
            return []

    src_dirname = "%s\\source" % smb_share
    dst_dirname = "%s\\target" % smb_share

    makedirs("%s\\dir1\\subdir1\\subdir2" % src_dirname)
    with open_file("%s\\file1.txt" % src_dirname, mode='w') as fd:
        fd.write(u"file1.txt")
    with open_file("%s\\dir1\\file2.txt" % src_dirname, mode='w') as fd:
        fd.write(u"file2.txt")
    with open_file("%s\\dir1\\subdir1\\file3.txt" % src_dirname, mode='w') as fd:
        fd.write(u"file3.txt")

    actual = copytree(src_dirname, dst_dirname, ignore=ignore)
    assert actual == dst_dirname

    assert sorted(list(listdir(dst_dirname))) == ["dir1"]
    assert sorted(list(listdir("%s\\dir1" % dst_dirname))) == ["file2.txt", "subdir1"]
    assert sorted(list(listdir("%s\\dir1\\subdir1" % dst_dirname))) == ["file3.txt"]

    with open_file("%s\\dir1\\file2.txt" % dst_dirname) as fd:
        assert fd.read() == u"file2.txt"
    with open_file("%s\\dir1\\subdir1\\file3.txt" % dst_dirname) as fd:
        assert fd.read() == u"file3.txt"


@pytest.mark.skipif(os.name != "nt" and not os.environ.get('SMB_FORCE', False),
                    reason="Samba does not update timestamps")
def test_copytree_with_copy(smb_share):
    src_dirname = "%s\\source" % smb_share
    dst_dirname = "%s\\sub-folder\\target" % smb_share

    makedirs("%s\\dir1\\subdir1\\subdir2" % src_dirname)

    _set_file_attributes("%s\\dir1\\subdir1" % src_dirname, FileAttributes.FILE_ATTRIBUTE_READONLY)

    utime("%s\\dir1\\subdir1\\subdir2" % src_dirname, times=(1024, 1024))

    with open_file("%s\\file1.txt" % src_dirname, mode='w',
                   file_attributes=FileAttributes.FILE_ATTRIBUTE_READONLY) as fd:
        fd.write(u"file1.txt")

    with open_file("%s\\dir1\\file2.txt" % src_dirname, mode='w') as fd:
        fd.write(u"file2.txt")
    utime("%s\\dir1\\file2.txt" % src_dirname, times=(1024, 1024))

    with open_file("%s\\dir1\\subdir1\\file3.txt" % src_dirname, mode='w',
                   file_attributes=FileAttributes.FILE_ATTRIBUTE_READONLY) as fd:
        fd.write(u"file3.txt")

    actual = copytree(src_dirname, dst_dirname, copy_function=copy)

    assert actual == dst_dirname

    assert sorted(list(listdir(dst_dirname))) == ["dir1", "file1.txt"]
    assert sorted(list(listdir("%s\\dir1" % dst_dirname))) == ["file2.txt", "subdir1"]
    assert sorted(list(listdir("%s\\dir1\\subdir1" % dst_dirname))) == ["file3.txt", "subdir2"]
    assert sorted(list(listdir("%s\\dir1\\subdir1\\subdir2" % dst_dirname))) == []

    with open_file("%s\\file1.txt" % dst_dirname) as fd:
        assert fd.read() == u"file1.txt"
    with open_file("%s\\dir1\\file2.txt" % dst_dirname) as fd:
        assert fd.read() == u"file2.txt"
    with open_file("%s\\dir1\\subdir1\\file3.txt" % dst_dirname) as fd:
        assert fd.read() == u"file3.txt"

    file1_stat = smbclient_stat("%s\\file1.txt" % dst_dirname)
    assert file1_stat.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == \
        FileAttributes.FILE_ATTRIBUTE_READONLY
    assert file1_stat.st_atime != 1024
    assert file1_stat.st_mtime != 1024

    file2_stat = smbclient_stat("%s\\dir1\\file2.txt" % dst_dirname)
    assert file2_stat.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == 0
    assert file2_stat.st_atime != 1024
    assert file2_stat.st_mtime != 1024

    file3_stat = smbclient_stat("%s\\dir1\\subdir1\\file3.txt" % dst_dirname)
    assert file3_stat.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == \
        FileAttributes.FILE_ATTRIBUTE_READONLY
    assert file3_stat.st_atime != 1024
    assert file3_stat.st_mtime != 1024

    dir1_stat = smbclient_stat("%s\\dir1" % dst_dirname)
    assert dir1_stat.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == 0
    assert dir1_stat.st_atime != 1024
    assert dir1_stat.st_mtime != 1024

    subdir1_stat = smbclient_stat("%s\\dir1\\subdir1" % dst_dirname)
    assert subdir1_stat.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == \
        FileAttributes.FILE_ATTRIBUTE_READONLY
    assert subdir1_stat.st_atime != 1024
    assert subdir1_stat.st_mtime != 1024

    subdir2_stat = smbclient_stat("%s\\dir1\\subdir1\\subdir2" % dst_dirname)
    assert subdir2_stat.st_file_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == 0
    # While files are copied with copy(), the directories are still copied with copystat()
    assert subdir2_stat.st_atime == 1024
    assert subdir2_stat.st_mtime == 1024


def test_copytree_with_errors_raises(smb_share):
    src_dirname = "%s\\source" % smb_share
    dst_dirname = "%s\\target" % smb_share

    makedirs("%s\\dir1" % src_dirname)

    with open_file("%s\\file1.txt" % src_dirname, mode='w') as fd:
        fd.write(u"file1.txt")

    with open_file("%s\\dir1\\file2.txt" % src_dirname, mode='w') as fd:
        fd.write(u"file2.txt")

    actual = copytree(src_dirname, dst_dirname)
    assert actual == dst_dirname

    # Doing this will force a failure as we cannot run copyfile against a target with this flag (access is denied).
    _set_file_attributes("%s\\file1.txt" % dst_dirname, FileAttributes.FILE_ATTRIBUTE_READONLY)
    _set_file_attributes("%s\\dir1\\file2.txt" % dst_dirname, FileAttributes.FILE_ATTRIBUTE_READONLY)

    with pytest.raises(shutil.Error) as actual:
        copytree(src_dirname, dst_dirname, dirs_exist_ok=True)

    assert len(actual.value.args[0]) == 2
    err1 = actual.value.args[0][0]
    assert err1[0] == "%s\\dir1\\file2.txt" % src_dirname
    assert err1[1] == "%s\\dir1\\file2.txt" % dst_dirname
    assert "STATUS_ACCESS_DENIED" in err1[2]

    err2 = actual.value.args[0][1]
    assert err2[0] == "%s\\file1.txt" % src_dirname
    assert err2[1] == "%s\\file1.txt" % dst_dirname
    assert "STATUS_ACCESS_DENIED" in err2[2]


@pytest.mark.skipif(os.name != "nt" and not os.environ.get('SMB_FORCE', False),
                    reason="cannot create symlinks on Samba")
def test_copytree_with_symlink_and_not_flag(smb_share):
    src_dirname = "%s\\source" % smb_share
    dst_dirname = "%s\\target" % smb_share

    makedirs("%s\\dir" % src_dirname)
    symlink("%s\\dir" % src_dirname, "%s\\link" % src_dirname)

    with open_file("%s\\file.txt" % src_dirname, mode='w') as fd:
        fd.write(u"1")
    symlink("%s\\file.txt" % src_dirname, "%s\\link.txt" % src_dirname)

    with open_file("%s\\dir\\file.txt" % src_dirname, mode='w') as fd:
        fd.write(u"2")

    actual = copytree(src_dirname, dst_dirname)
    assert actual == dst_dirname

    assert not islink("%s\\link.txt" % dst_dirname)
    with open_file("%s\\link.txt" % dst_dirname) as fd:
        assert fd.read() == u"1"

    assert not samefile("%s\\link.txt" % dst_dirname, "%s\\file.txt" % src_dirname)
    assert not samefile("%s\\link.txt" % dst_dirname, "%s\\file.txt" % dst_dirname)

    assert not islink("%s\\link" % dst_dirname)
    with open_file("%s\\link\\file.txt" % dst_dirname) as fd:
        assert fd.read() == u"2"

    assert not samefile("%s\\link\\file.txt" % dst_dirname, "%s\\dir\\file.txt" % src_dirname)
    assert not samefile("%s\\link\\file.txt" % dst_dirname, "%s\\dir\\file.txt" % dst_dirname)


@pytest.mark.skipif(os.name != "nt" and not os.environ.get('SMB_FORCE', False),
                    reason="cannot create symlinks on Samba")
def test_copytree_with_symlink_and_flag(smb_share):
    src_dirname = "%s\\source" % smb_share
    dst_dirname = "%s\\target" % smb_share

    makedirs("%s\\dir" % src_dirname)
    symlink("%s\\dir" % src_dirname, "%s\\link" % src_dirname)

    with open_file("%s\\file.txt" % src_dirname, mode='w') as fd:
        fd.write(u"content")
    symlink("%s\\file.txt" % src_dirname, "%s\\link.txt" % src_dirname)

    with open_file("%s\\dir\\file.txt" % src_dirname, mode='w') as fd:
        fd.write(u"content")

    actual = copytree(src_dirname, dst_dirname, symlinks=True)
    assert actual == dst_dirname

    assert islink("%s\\link" % dst_dirname)
    assert ntpath.normpath(readlink("%s\\link" % dst_dirname)) == ntpath.normpath("%s\\dir" % src_dirname)
    assert samefile("%s\\link\\file.txt" % dst_dirname, "%s\\dir\\file.txt" % src_dirname)
    assert not samefile("%s\\link\\file.txt" % dst_dirname, "%s\\dir\\file.txt" % dst_dirname)

    assert islink("%s\\link.txt" % dst_dirname)
    assert ntpath.normpath(readlink("%s\\link.txt" % dst_dirname)) == ntpath.normpath("%s\\file.txt" % src_dirname)
    assert samefile("%s\\link.txt" % dst_dirname, "%s\\file.txt" % src_dirname)
    assert not samefile("%s\\link.txt" % dst_dirname, "%s\\file.txt" % dst_dirname)


@pytest.mark.skipif(os.name != "nt" and not os.environ.get('SMB_FORCE', False),
                    reason="cannot create symlinks on Samba")
def test_copytree_with_broken_symlink_fail(smb_share):
    src_dirname = "%s\\source" % smb_share
    dst_dirname = "%s\\target" % smb_share

    mkdir(src_dirname)
    symlink("%s\\dir" % src_dirname, "%s\\link" % src_dirname, target_is_directory=True)
    symlink("%s\\file.txt" % src_dirname, "%s\\link.txt" % src_dirname)

    with pytest.raises(shutil.Error) as actual:
        copytree(src_dirname, dst_dirname)

    assert len(actual.value.args[0]) == 2
    err1 = actual.value.args[0][0]
    err2 = actual.value.args[0][1]

    assert err1[0] == "%s\\link" % src_dirname
    assert err1[1] == "%s\\link" % dst_dirname
    assert "No such file or directory" in err1[2]

    assert err2[0] == "%s\\link.txt" % src_dirname
    assert err2[1] == "%s\\link.txt" % dst_dirname
    assert "No such file or directory" in err2[2]


@pytest.mark.skipif(os.name != "nt" and not os.environ.get('SMB_FORCE', False),
                    reason="cannot create symlinks on Samba")
def test_copytree_with_broken_symlink_ignore(smb_share):
    src_dirname = "%s\\source" % smb_share
    dst_dirname = "%s\\target" % smb_share

    makedirs("%s\\other-dir" % src_dirname)
    symlink("%s\\dir" % src_dirname, "%s\\link" % src_dirname, target_is_directory=True)
    symlink("%s\\file.txt" % src_dirname, "%s\\link.txt" % src_dirname)

    actual = copytree(src_dirname, dst_dirname, ignore_dangling_symlinks=True)
    assert actual == dst_dirname

    assert listdir(dst_dirname) == ["other-dir"]


def test_rmtree(smb_share):
    mkdir("%s\\dir2" % smb_share)
    mkdir("%s\\dir2\\dir3" % smb_share)

    with open_file("%s\\dir2\\dir3\\file1" % smb_share, mode='w') as fd:
        fd.write(u"content")

    with open_file("%s\\dir2\\file2" % smb_share, mode='w') as fd:
        fd.write(u"content")

    if os.name == "nt" or os.environ.get('SMB_FORCE', False):
        # File symlink
        symlink("%s\\dir2\\file2" % smb_share, "%s\\dir2\\file3" % smb_share)
        symlink("missing", "%s\\dir2\\file3-broken" % smb_share)

        # Dir symlink
        symlink("%s\\dir2\\dir3" % smb_share, "%s\\dir2\\dir-link" % smb_share)
        symlink("missing", "%s\\dir2\\dir-link-broken" % smb_share, target_is_directory=True)

    assert exists("%s\\dir2" % smb_share) is True

    rmtree("%s\\dir2" % smb_share)

    assert exists("%s\\dir2" % smb_share) is False


def test_rmtree_non_existing(smb_share):
    dir_name = "%s\\dir2" % smb_share

    expected = "[NtStatus 0xc0000034] No such file or directory: "
    with pytest.raises(OSError, match=re.escape(expected)):
        rmtree(dir_name)

    rmtree(dir_name, ignore_errors=True)

    callback_args = []

    def callback(*args):
        callback_args.append(args)

    rmtree(dir_name, onerror=callback)
    assert len(callback_args) == 2
    assert callback_args[0][0].__name__ == 'scandir'
    assert callback_args[0][1] == dir_name
    assert isinstance(callback_args[0][2][1], SMBOSError)
    assert callback_args[1][0].__name__ == 'rmdir'
    assert callback_args[1][1] == dir_name
    assert isinstance(callback_args[1][2][1], SMBOSError)


def test_rmtree_as_file(smb_share):
    filename = "%s\\file.txt" % smb_share
    with open_file(filename, mode='w') as fd:
        fd.write(u"content")

    expected = "[NtStatus 0xc0000103] Not a directory: "
    with pytest.raises(OSError, match=re.escape(expected)):
        rmtree(filename)

    rmtree(filename, ignore_errors=True)

    callback_args = []

    def callback(*args):
        callback_args.append(args)

    rmtree(filename, onerror=callback)
    assert len(callback_args) == 2
    assert callback_args[0][0].__name__ == 'scandir'
    assert callback_args[0][1] == filename
    assert isinstance(callback_args[0][2][1], SMBOSError)
    assert callback_args[1][0].__name__ == 'rmdir'
    assert callback_args[1][1] == filename
    assert isinstance(callback_args[1][2][1], SMBOSError)


@pytest.mark.skipif(os.name != "nt" and not os.environ.get('SMB_FORCE', False),
                    reason="cannot create symlinks on Samba")
def test_rmtree_symlink_as_dir(smb_share):
    src_dirname = "%s\\dir" % smb_share
    dst_dirname = "%s\\target" % smb_share
    mkdir(src_dirname)
    symlink("dir", dst_dirname)

    expected = "Cannot call rmtree on a symbolic link"
    with pytest.raises(OSError, match=re.escape(expected)):
        rmtree(dst_dirname)

    assert exists(src_dirname)
    assert exists(dst_dirname)

    rmtree(dst_dirname, ignore_errors=True)

    callback_args = []

    def callback(*args):
        callback_args.append(args)

    rmtree(dst_dirname, onerror=callback)
    assert len(callback_args) == 1
    assert callback_args[0][0].__name__ == 'islink'
    assert callback_args[0][1] == dst_dirname
    assert isinstance(callback_args[0][2][1], OSError)
