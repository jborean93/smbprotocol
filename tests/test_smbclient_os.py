# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import datetime
import io
import locale
import ntpath
import os
import re
import stat
import time

import pytest

import smbclient  # Tests that we expose this in smbclient/__init__.py
from smbclient._io import SMBFileTransaction, query_info
from smbclient._os import SMBDirectoryIO, SMBDirEntry, SMBFileIO
from smbclient.shutil import rmtree
from smbprotocol.exceptions import SMBAuthenticationError, SMBOSError
from smbprotocol.file_info import FileAttributes, FileStreamInformation
from smbprotocol.reparse_point import ReparseDataBuffer, ReparseTags


@pytest.mark.parametrize(
    "path",
    [
        "\\\\only_server",
        "\\\\server_slash\\",
    ],
)
def test_open_bad_path(path):
    expected = "The SMB path specified must contain the server and share to connect to"
    with pytest.raises(ValueError, match=expected):
        smbclient.open_file(path)


def test_reset_connection(smb_share):
    smbclient.reset_connection_cache()

    # Once we've reset the connection it should fail because we didn't set any credentials.
    # Won't work on Windows as implicit auth is available.
    if os.name != "nt":
        expected = "Failed to authenticate with server"
        with pytest.raises(SMBAuthenticationError, match=expected):
            smbclient.stat(smb_share)


def test_delete_session(smb_share):
    server = ntpath.normpath(smb_share).split("\\")[2]
    smbclient.delete_session(server)

    # Once we've closed the connection it should fail because we didn't set any credentials
    if os.name != "nt":
        expected = "Failed to authenticate with server"
        with pytest.raises(SMBAuthenticationError, match=expected):
            smbclient.stat(smb_share)


def test_copy_across_paths_raises(smb_share):
    expected = "Cannot copy a file to a different host than the src."
    with pytest.raises(ValueError, match=re.escape(expected)):
        smbclient.copyfile("%s\\file" % smb_share, "//host/filer2/file2")


def test_copyfile_src_not_unc():
    expected = "src must be an absolute path to where the file should be copied from."
    with pytest.raises(ValueError, match=re.escape(expected)):
        smbclient.copyfile("file", "\\\\server\\share\\file")


def test_copyfile_dst_not_unc():
    expected = "dst must be an absolute path to where the file should be copied to."
    with pytest.raises(ValueError, match=re.escape(expected)):
        smbclient.copyfile("\\\\server\\share\\file", "file")


def test_server_side_copy_multiple_chunks(smb_share):
    smbclient.mkdir("%s\\dir2" % smb_share)
    with smbclient.open_file("%s\\file1" % smb_share, mode="w") as fd:
        fd.write("content" * 1024)

    smbclient.copyfile("%s\\file1" % smb_share, "%s\\dir2\\file1" % smb_share)

    src_stat = smbclient.stat("%s\\file1" % smb_share)
    dst_stat = smbclient.stat("%s\\dir2\\file1" % smb_share)

    assert src_stat.st_size == dst_stat.st_size


def test_write_large_bytes(smb_share):
    with smbclient.open_file("%s\\file1" % smb_share, mode="wb") as fd:
        content = b"a" * (fd.raw.fd.connection.max_write_size + 1024)
        assert isinstance(fd, io.BufferedWriter)
        assert fd.write(content) == len(content)

    assert smbclient.stat("%s\\file1" % smb_share).st_size == len(content)
    with smbclient.open_file("%s\\file1" % smb_share, mode="rb") as fd:
        assert fd.read() == content


def test_write_large_text(smb_share):
    with smbclient.open_file("%s\\file1" % smb_share, mode="w") as fd:
        content = "a" * (fd.buffer.raw.fd.connection.max_write_size + 1024)
        assert isinstance(fd, io.TextIOWrapper)
        assert fd.write(content) == len(content)

    assert smbclient.stat("%s\\file1" % smb_share).st_size == len(content)
    with smbclient.open_file("%s\\file1" % smb_share, mode="r") as fd:
        assert fd.read() == content


def test_server_side_copy_large_file(smb_share):
    src_filename = "%s\\file1" % smb_share
    dst_filename = "%s\\file2" % smb_share

    # Actually reading and writing more than 16MB takes too long for the tests so just test the file length
    expected_length = 1024 * 1024 * 17

    with smbclient.open_file(src_filename, mode="wb") as fd:
        fd.truncate(expected_length)

    smbclient.copyfile(src_filename, dst_filename)
    smbclient.copyfile(src_filename, dst_filename)

    with smbclient.open_file(dst_filename, mode="rb") as fd:
        assert fd.seek(0, smbclient.SEEK_END)
        assert fd.tell() == expected_length


def test_link_relative_path_fail(smb_share):
    expected = "src must be the absolute path to where the file is hard linked to."
    with pytest.raises(ValueError, match=expected):
        smbclient.link("file", smb_share)


def test_link_different_root_fail(smb_share):
    expected = "Cannot hardlink a file to a different root than the src."
    with pytest.raises(ValueError, match=expected):
        smbclient.link("\\\\other\\share\\file.txt", smb_share)


def test_link_dir_fail(smb_share):
    expected = "[NtStatus 0xc00000ba] Is a directory"
    with pytest.raises(SMBOSError, match=re.escape(expected)):
        smbclient.link(smb_share, ntpath.join(smb_share, "file.txt"))


def test_link_existing_file_failed(smb_share):
    file_data = "content"
    link_src = ntpath.join(smb_share, "src.txt")
    with smbclient.open_file(link_src, mode="w") as fd:
        fd.write(file_data)

    link_dst = ntpath.join(smb_share, "dst.txt")
    with smbclient.open_file(link_dst, mode="w") as fd:
        fd.write(file_data)

    expected = "[NtStatus 0xc0000035] File exists:"
    with pytest.raises(OSError, match=re.escape(expected)):
        smbclient.link(link_src, link_dst)


def test_link_missing_src_fail(smb_share):
    link_src = ntpath.join(smb_share, "src.txt")
    link_dst = ntpath.join(smb_share, "dst.txt")

    expected = "[NtStatus 0xc0000034] No such file or directory"
    with pytest.raises(OSError, match=re.escape(expected)):
        smbclient.link(link_src, link_dst)


def test_link_to_file(smb_share):
    file_data = "content"
    link_src = ntpath.join(smb_share, "src.txt")
    with smbclient.open_file(link_src, mode="w") as fd:
        fd.write(file_data)

    link_dst = ntpath.join(smb_share, "dst.txt")
    smbclient.link(link_src, link_dst)

    with smbclient.open_file(link_dst, mode="r") as fd:
        actual_data = fd.read()

    assert actual_data == file_data

    src_stat = smbclient.stat(link_src)
    dst_stat = smbclient.stat(link_dst)
    assert src_stat.st_ino == dst_stat.st_ino
    assert src_stat.st_dev == dst_stat.st_dev
    assert src_stat.st_nlink == 2
    assert dst_stat.st_nlink == 2


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_link_to_symbolic_link_follows(smb_share):
    normal_filename = "%s\\file.txt" % smb_share
    link_filename = "%s\\link.txt" % smb_share
    hard_filename = "%s\\hard.txt" % smb_share

    with smbclient.open_file(normal_filename, mode="w") as fd:
        fd.write("content")

    smbclient.symlink(normal_filename, link_filename)
    smbclient.link(link_filename, hard_filename)

    actual_normal = smbclient.lstat(normal_filename)
    actual_hard = smbclient.lstat(normal_filename)

    assert actual_hard.st_ino == actual_normal.st_ino


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_link_to_symbolic_link_not_follows(smb_share):
    normal_filename = "%s\\file.txt" % smb_share
    link_filename = "%s\\link.txt" % smb_share
    hard_filename = "%s\\hard.txt" % smb_share

    with smbclient.open_file(normal_filename, mode="w") as fd:
        fd.write("content")

    smbclient.symlink(normal_filename, link_filename)
    smbclient.link(link_filename, hard_filename, follow_symlinks=False)

    actual_link = smbclient.lstat(normal_filename)
    actual_hard = smbclient.lstat(normal_filename)

    assert actual_hard.st_ino == actual_link.st_ino


@pytest.mark.parametrize(
    "dirpath, ntstatus",
    [
        ("missing", "0xc0000034"),
        ("missing\\missing_sub", "0xc000003a"),
    ],
)
def test_listdir_missing(dirpath, ntstatus, smb_share):
    expected = "[NtStatus %s] No such file or directory" % ntstatus
    with pytest.raises(SMBOSError, match=re.escape(expected)):
        smbclient.listdir(ntpath.join(smb_share, dirpath))


def test_listdir_file_fail(smb_share):
    filename = ntpath.join(smb_share, "file.txt")
    with smbclient.open_file(filename, mode="w") as fd:
        fd.write("data")

    expected = "[NtStatus 0xc0000103] Not a directory"
    with pytest.raises(SMBOSError, match=re.escape(expected)):
        smbclient.listdir(filename)


@pytest.mark.parametrize(
    "dirname",
    [
        ("",),  # Requires different special perms on Windows, this makes sure we can still enum the root share.
        ("subdir",),
    ],
)
def test_listdir(dirname, smb_share):
    dirpath = ntpath.join(smb_share, dirname[0])
    smbclient.makedirs(dirpath, exist_ok=True)

    for name in ["file.txt", "unicode †[💩].txt"]:
        with smbclient.open_file(ntpath.join(dirpath, name), mode="w") as fd:
            fd.write("content")

    for name in ["subdir1", "subdir2", "unicode dir †[💩]", "subdir1\\sub"]:
        smbclient.mkdir(ntpath.join(dirpath, name))

    actual = smbclient.listdir(dirpath)
    assert len(actual) == 5
    assert "unicode †[💩].txt" in actual
    assert "unicode dir †[💩]" in actual
    assert "subdir2" in actual
    assert "subdir1" in actual
    assert "file.txt" in actual


def test_listdir_with_pattern(smb_share):
    for filename in ["file.txt", "file-test1.txt", "file-test1a.txt"]:
        with smbclient.open_file(rf"{smb_share}\{filename}", mode="w") as fd:
            fd.write("content")

    actual = smbclient.listdir(smb_share, search_pattern="file-test*.txt")
    assert len(actual) == 2
    assert "file-test1.txt" in actual
    assert "file-test1a.txt" in actual

    assert smbclient.listdir(smb_share, search_pattern="file-test?.txt") == ["file-test1.txt"]


def test_listdir_with_pattern_no_match(smb_share):
    actual = smbclient.listdir(smb_share, search_pattern="no matching file")
    assert actual == []


def test_lstat_on_file(smb_share):
    filename = ntpath.join(smb_share, "file.txt")
    with smbclient.open_file(filename, mode="w") as fd:
        fd.write("Content")

    actual = smbclient.lstat(filename)
    assert isinstance(actual, smbclient.SMBStatResult)
    assert actual.st_atime == actual.st_atime_ns / 1000000000
    assert actual.st_mtime == actual.st_mtime_ns / 1000000000
    assert actual.st_ctime == actual.st_ctime_ns / 1000000000
    assert actual.st_chgtime == actual.st_chgtime_ns / 1000000000
    assert actual.st_dev is not None
    assert actual.st_file_attributes == FileAttributes.FILE_ATTRIBUTE_ARCHIVE
    assert actual.st_gid == 0
    assert actual.st_uid == 0
    assert actual.st_ino is not None
    assert actual.st_mode == stat.S_IFREG | 0o666
    assert actual.st_nlink == 1
    assert actual.st_size == 7
    assert actual.st_uid == 0
    assert actual.st_reparse_tag == 0


def test_lstat_on_dir(smb_share):
    dirname = ntpath.join(smb_share, "dir")
    smbclient.mkdir(dirname)

    actual = smbclient.lstat(dirname)
    assert isinstance(actual, smbclient.SMBStatResult)
    assert actual.st_atime == actual.st_atime_ns / 1000000000
    assert actual.st_mtime == actual.st_mtime_ns / 1000000000
    assert actual.st_ctime == actual.st_ctime_ns / 1000000000
    assert actual.st_chgtime == actual.st_chgtime_ns / 1000000000
    assert actual.st_dev is not None
    assert actual.st_file_attributes == FileAttributes.FILE_ATTRIBUTE_DIRECTORY
    assert actual.st_gid == 0
    assert actual.st_uid == 0
    assert actual.st_ino is not None
    assert actual.st_mode == stat.S_IFDIR | 0o777
    assert actual.st_nlink == 1
    assert actual.st_size == 0
    assert actual.st_uid == 0
    assert actual.st_reparse_tag == 0


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_lstat_on_symlink_file(smb_share):
    src_filename = "%s\\file.txt" % smb_share
    dst_filename = "%s\\link.txt" % smb_share

    with smbclient.open_file(src_filename, mode="w") as fd:
        fd.write("content")

    smbclient.symlink(src_filename, dst_filename)

    actual_src = smbclient.stat(src_filename)
    actual = smbclient.lstat(dst_filename)
    assert actual.st_ino != actual_src.st_ino
    assert stat.S_ISLNK(actual.st_mode)
    assert actual.st_reparse_tag == ReparseTags.IO_REPARSE_TAG_SYMLINK


def test_mkdir(smb_share):
    dirname = ntpath.join(smb_share, "dir")
    smbclient.mkdir(dirname)
    actual = smbclient.stat(dirname)
    assert stat.S_ISDIR(actual.st_mode)

    expected = "[NtStatus 0xc0000035] File exists:"
    with pytest.raises(SMBOSError, match=re.escape(expected)):
        smbclient.mkdir(dirname)


def test_mkdir_missing_parent_fail(smb_share):
    dirname = ntpath.join(smb_share, "dir", "subdir")
    expected = "[NtStatus 0xc000003a] No such file or directory"
    with pytest.raises(SMBOSError, match=re.escape(expected)):
        smbclient.mkdir(dirname)


def test_mkdir_path_is_file_fail(smb_share):
    filename = ntpath.join(smb_share, "test.txt")
    with smbclient.open_file(filename, mode="w") as fd:
        fd.write("content")

    expected = "[NtStatus 0xc0000035] File exists:"
    with pytest.raises(SMBOSError, match=re.escape(expected)):
        smbclient.mkdir(filename)


def test_makedirs_existing_parent(smb_share):
    dirpath = ntpath.join(smb_share, "folder")
    smbclient.makedirs(dirpath)
    assert smbclient.listdir(smb_share) == ["folder"]


def test_makedirs_exist_ok(smb_share):
    dirpath = ntpath.join(smb_share, "folder")
    smbclient.makedirs(dirpath)

    expected = "[NtStatus 0xc0000035] File exists:"
    with pytest.raises(OSError, match=re.escape(expected)):
        smbclient.makedirs(dirpath)

    smbclient.makedirs(dirpath, exist_ok=True)


def test_makedirs_missing_parents(smb_share):
    dirpath = ntpath.join(smb_share, "missing", "missing", "folder")
    smbclient.makedirs(dirpath)
    assert stat.S_ISDIR(smbclient.stat(dirpath).st_mode)


def test_makedirs_file_as_parent(smb_share):
    filepath = ntpath.join(smb_share, "file.txt")
    with smbclient.open_file(filepath, "w") as fd:
        fd.write("text")

    expected = "[NtStatus 0xc0000035] File exists:"
    with pytest.raises(OSError, match=re.escape(expected)):
        smbclient.makedirs(filepath)

    dirpath = ntpath.join(filepath, "folder")
    expected = "[NtStatus 0xc000003a] No such file or directory:"
    with pytest.raises(OSError, match=re.escape(expected)):
        smbclient.makedirs(dirpath)


def test_read_text_file(smb_share):
    file_path = rf"{smb_share}\file.txt"
    file_contents = "File Contents\nNewline"

    expected = "[NtStatus 0xc0000034] No such file or directory"
    with pytest.raises(SMBOSError, match=re.escape(expected)):
        smbclient.open_file(file_path, mode="rb")

    with smbclient.open_file(file_path, mode="wb") as fd:
        fd.write(file_contents.encode("utf-8"))

    with smbclient.open_file(file_path) as fd:
        assert isinstance(fd, io.TextIOWrapper)
        assert fd.closed is False
        assert fd.encoding == locale.getpreferredencoding()
        assert fd.errors == "strict"
        assert fd.line_buffering is False
        assert fd.name == file_path
        assert fd.newlines is None

        actual = fd.read()
        assert actual == file_contents

        actual = fd.read()
        assert actual == ""

        fd.seek(0)
        actual = fd.readlines()

        expected_lines = file_contents.split("\n")
        expected = [l + "\n" if idx != len(expected_lines) - 1 else l for idx, l in enumerate(expected_lines)]
        assert actual == expected

        assert int(fd.tell()) == len(file_contents)

        with pytest.raises(IOError):
            fd.write("Fail")

    assert fd.closed


def test_read_byte_file(smb_share):
    file_path = rf"{smb_share}\file.txt"
    file_contents = b"\x00\x01\x02\x03"

    expected = "[NtStatus 0xc0000034] No such file or directory"
    with pytest.raises(SMBOSError, match=re.escape(expected)):
        smbclient.open_file(file_path, mode="rb")

    with smbclient.open_file(file_path, mode="wb") as fd:
        fd.write(file_contents)

    with smbclient.open_file(file_path, mode="rb") as fd:
        assert isinstance(fd, io.BufferedReader)
        assert fd.closed is False
        assert fd.name == file_path

        actual = fd.read()
        assert actual == file_contents

        actual = fd.read()
        assert actual == b""

        fd.seek(0)
        actual = fd.read()
        assert actual == file_contents

        with pytest.raises(IOError):
            fd.write(b"Fail")
    assert fd.closed


def test_write_text_file(smb_share):
    file_path = rf"{smb_share}\file.txt"
    file_contents = "File Contents\nNewline"

    with smbclient.open_file(file_path, mode="w") as fd:
        assert isinstance(fd, io.TextIOWrapper)
        assert fd.closed is False

        with pytest.raises(IOError):
            fd.read()

        assert fd.tell() == 0
        fd.write(file_contents)
        assert int(fd.tell()) == (len(file_contents) - 1 + len(os.linesep))

    assert fd.closed is True

    with smbclient.open_file(file_path, mode="r") as fd:
        assert fd.read() == file_contents

    with smbclient.open_file(file_path, mode="w") as fd:
        assert fd.tell() == 0
        assert fd.write("abc")
        assert fd.tell() == 3

    with smbclient.open_file(file_path, mode="r") as fd:
        assert fd.read() == "abc"


def test_write_byte_file(smb_share):
    file_path = rf"{smb_share}\file.txt"
    file_contents = b"File Contents\nNewline"

    with smbclient.open_file(file_path, mode="wb") as fd:
        assert isinstance(fd, io.BufferedWriter)
        assert fd.closed is False

        with pytest.raises(IOError):
            fd.read()

        assert fd.tell() == 0
        fd.write(file_contents)
        assert fd.tell() == len(file_contents)

    assert fd.closed is True

    with smbclient.open_file(file_path, mode="rb") as fd:
        assert fd.read() == file_contents

    with smbclient.open_file(file_path, mode="wb") as fd:
        assert fd.tell() == 0
        assert fd.write(b"abc")
        assert fd.tell() == 3
        fd.flush()

    with smbclient.open_file(file_path, mode="rb") as fd:
        assert fd.read() == b"abc"


# https://github.com/jborean93/smbprotocol/issues/20
def test_read_large_text_file(smb_share):
    file_path = rf"{smb_share}\file.txt"
    file_contents = "a" * 131074

    with smbclient.open_file(file_path, mode="w") as fd:
        fd.write(file_contents)

    with smbclient.open_file(file_path) as fd:
        actual = fd.read()
        assert len(actual) == 131074


def test_write_exclusive_text_file(smb_share):
    file_path = rf"{smb_share}\file.txt"
    file_contents = "File Contents\nNewline"

    with smbclient.open_file(file_path, mode="x") as fd:
        assert isinstance(fd, io.TextIOWrapper)
        assert fd.closed is False

        with pytest.raises(IOError):
            fd.read()

        assert fd.tell() == 0
        fd.write(file_contents)
        assert int(fd.tell()) == (len(file_contents) - 1 + len(os.linesep))

    assert fd.closed is True

    with smbclient.open_file(file_path, mode="r") as fd:
        assert fd.read() == file_contents

    with pytest.raises(OSError, match=re.escape("[NtStatus 0xc0000035] File exists: ")):
        smbclient.open_file(file_path, mode="x")

    assert fd.closed is True


def test_write_exclusive_byte_file(smb_share):
    file_path = rf"{smb_share}\file.txt"
    file_contents = b"File Contents\nNewline"

    with smbclient.open_file(file_path, mode="xb") as fd:
        assert isinstance(fd, io.BufferedWriter)
        assert fd.closed is False

        with pytest.raises(IOError):
            fd.read()

        assert fd.tell() == 0
        fd.write(file_contents)
        assert fd.tell() == len(file_contents)

    assert fd.closed is True

    with smbclient.open_file(file_path, mode="rb") as fd:
        assert fd.read() == file_contents

    with pytest.raises(OSError, match=re.escape("[NtStatus 0xc0000035] File exists: ")):
        smbclient.open_file(file_path, mode="xb")

    assert fd.closed is True


def test_append_text_file(smb_share):
    file_path = rf"{smb_share}\file.txt"

    with smbclient.open_file(file_path, mode="a") as fd:
        assert isinstance(fd, io.TextIOWrapper)

        with pytest.raises(IOError):
            fd.read()

        fd.write("abc")
        assert fd.tell() == 3

    with smbclient.open_file(file_path, mode="a") as fd:
        assert fd.tell() == 3
        fd.write("def")
        assert fd.tell() == 6

    with smbclient.open_file(file_path, mode="r") as fd:
        assert fd.read() == "abcdef"


def test_append_byte_file(smb_share):
    file_path = rf"{smb_share}\file.txt"

    with smbclient.open_file(file_path, mode="ab") as fd:
        assert isinstance(fd, io.BufferedWriter)

        with pytest.raises(IOError):
            fd.read()

        fd.write(b"abc")
        assert fd.tell() == 3

    with smbclient.open_file(file_path, mode="ab") as fd:
        assert fd.tell() == 3
        fd.write(b"def")
        assert fd.tell() == 6

    with smbclient.open_file(file_path, mode="rb") as fd:
        assert fd.read() == b"abcdef"


def test_read_write_text_file(smb_share):
    file_path = rf"{smb_share}\file.txt"

    with smbclient.open_file(file_path, mode="w+") as fd:
        fd.write("abc")
        assert fd.tell() == 3
        assert fd.read() == ""
        fd.seek(0)
        assert fd.read() == "abc"


def test_read_write_byte_file(smb_share):
    file_path = rf"{smb_share}\file.txt"

    with smbclient.open_file(file_path, mode="bw+") as fd:
        fd.write(b"abc")
        assert fd.tell() == 3
        assert fd.read() == b""
        fd.seek(0)
        assert fd.read() == b"abc"


def test_open_directory_fail(smb_share):
    dir_path = rf"{smb_share}\dir"
    smbclient.mkdir(dir_path)

    with pytest.raises(OSError, match=re.escape("[NtStatus 0xc00000ba] Is a directory: ")):
        smbclient.open_file(dir_path)


def test_open_directory_with_correct_file_type(smb_share):
    dir_name = "%s\\dir" % smb_share
    smbclient.mkdir(dir_name)

    with smbclient.open_file(dir_name, mode="rb", buffering=0, file_type="dir") as fd:
        assert isinstance(fd, SMBDirectoryIO)
        assert fd.readable() is False
        assert fd.writable() is False
        assert fd.seekable() is False


def test_open_file_in_missing_dir(smb_share):
    file_path = rf"{smb_share}\dir\file.txt"

    with pytest.raises(OSError, match=re.escape("[NtStatus 0xc000003a] No such file or directory: ")):
        smbclient.open_file(file_path)


def test_open_file_with_read_share_access(smb_share):
    file_path = rf"{smb_share}\file.txt"

    with smbclient.open_file(file_path, mode="w") as fd:
        fd.write("contents")

    with smbclient.open_file(file_path):
        expected = (
            "[NtStatus 0xc0000043] The process cannot access the file because it is being used by another process"
        )
        with pytest.raises(OSError, match=re.escape(expected)):
            smbclient.open_file(file_path)

    with smbclient.open_file(file_path, share_access="r") as fd:
        assert fd.read() == "contents"
        with smbclient.open_file(file_path, share_access="r") as fd_child:
            assert fd_child.read() == "contents"

        with pytest.raises(OSError):
            smbclient.open_file(file_path, mode="a")


def test_open_file_with_write_share_access(smb_share):
    file_path = rf"{smb_share}\file.txt"

    with smbclient.open_file(file_path, mode="w") as fd:
        expected = (
            "[NtStatus 0xc0000043] The process cannot access the file because it is being used by another process: "
        )
        with pytest.raises(OSError, match=re.escape(expected)):
            smbclient.open_file(file_path, mode="a")

    with smbclient.open_file(file_path, mode="w", share_access="w") as fd:
        fd.write("contents")
        fd.flush()

        with pytest.raises(OSError):
            smbclient.open_file(file_path, mode="r")

        with smbclient.open_file(file_path, mode="a", share_access="w") as fd_child:
            fd_child.write("\nnewline")

    with smbclient.open_file(file_path, mode="r") as fd:
        assert fd.read() == "contents\nnewline"


def test_open_file_with_read_write_access(smb_share):
    file_path = rf"{smb_share}\file.txt"

    with smbclient.open_file(file_path, mode="w", share_access="rw") as fd:
        fd.write("content")
        fd.flush()

        with smbclient.open_file(file_path, mode="a", share_access="rw") as fd_child:
            fd_child.write("\nnewline")

        with smbclient.open_file(file_path, mode="r", share_access="rw") as fd_child:
            assert fd_child.read() == "content\nnewline"


def test_open_file_invalid_share_access(smb_share):
    with pytest.raises(ValueError, match=re.escape("Invalid share_access char z, can only be d, r, w")):
        smbclient.open_file(smb_share, share_access="z")


def test_open_file_invalid_mode_char(smb_share):
    with pytest.raises(ValueError, match=re.escape("Invalid mode char z, can only be +, a, b, r, t, w, x")):
        smbclient.open_file(smb_share, mode="z")


def test_open_file_invalid_mode(smb_share):
    with pytest.raises(ValueError, match=re.escape("Invalid mode value b, must contain at least r, w, x, or a")):
        smbclient.open_file(smb_share, mode="b")


def test_open_file_case_sensitive(smb_share):
    filename = "%s\\File.txt" % smb_share

    with smbclient.open_file(filename, mode="w") as fd:
        fd.write("content")

    assert smbclient.listdir(smb_share) == ["File.txt"]


def test_open_file_unbuffered(smb_share):
    filename = "%s\\file.txt" % smb_share

    with smbclient.open_file(filename, mode="wb", buffering=0) as fd:
        assert isinstance(fd, SMBFileIO)
        fd.write(b"abc")
        fd.flush()

    with smbclient.open_file(filename, mode="rb", buffering=0) as fd:
        assert isinstance(fd, SMBFileIO)
        assert fd.read() == b"abc"


def test_open_file_unbuffered_text_file(smb_share):
    expected = "can't have unbuffered text I/O"
    with pytest.raises(ValueError, match=re.escape(expected)):
        smbclient.open_file("%s\\file.txt" % smb_share, mode="w", buffering=0)


def test_open_file_with_ads(smb_share):
    filename = "%s\\file.txt" % smb_share
    with smbclient.open_file(filename, mode="w") as fd:
        fd.write("default")

    with smbclient.open_file(filename + ":ads", mode="w") as fd:
        fd.write("ads")

    with smbclient.open_file(filename) as fd:
        assert fd.read() == "default"

    with smbclient.open_file(filename + ":ads") as fd:
        assert fd.read() == "ads"

    assert smbclient.listdir(smb_share) == ["file.txt"]

    with smbclient.open_file(filename, buffering=0, mode="rb") as fd, SMBFileTransaction(fd) as trans:
        query_info(trans, FileStreamInformation, output_buffer_length=1024)

    actual = sorted([s["stream_name"].get_value() for s in trans.results[0]])
    assert actual == ["::$DATA", ":ads:$DATA"]


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_open_symlink_file(smb_share):
    src_filename = "%s\\file.txt" % smb_share
    dst_filename = "%s\\link.txt" % smb_share

    with smbclient.open_file(src_filename, mode="w") as fd:
        fd.write("content")

    smbclient.symlink(src_filename, dst_filename)

    with smbclient.open_file(dst_filename) as fd:
        assert fd.read() == "content"


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_open_file_in_symlink_dir(smb_share):
    filename = "%s\\link\\file.txt" % smb_share

    smbclient.mkdir("%s\\dir" % smb_share)
    with smbclient.open_file("%s\\dir\\file.txt" % smb_share, mode="w") as fd:
        fd.write("content")

    smbclient.symlink("%s\\dir" % smb_share, "%s\\link" % smb_share)

    with smbclient.open_file(filename) as fd:
        assert fd.read() == "content"


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_readlink_that_is_normal_file(smb_share):
    src_filename = "%s\\file.txt" % smb_share
    dst_filename = "%s\\link.txt" % smb_share

    smbclient.symlink(src_filename, dst_filename)

    actual = smbclient.readlink(dst_filename)
    assert ntpath.normcase(actual) == ntpath.normcase(src_filename)


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_readlink_that_is_normal_dir(smb_share):
    src_dirname = "%s\\dir" % smb_share
    dst_dirname = "%s\\link" % smb_share

    smbclient.symlink(src_dirname, dst_dirname, target_is_directory=True)

    actual = smbclient.readlink(dst_dirname)
    assert ntpath.normcase(actual) == ntpath.normcase(src_dirname)


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_readlink_relative_path(smb_share):
    src_filename = "%s\\dir1\\file.txt" % smb_share
    dst_filename = "%s\\dir2\\link.txt" % smb_share
    smbclient.mkdir("%s\\dir2" % smb_share)

    smbclient.symlink("..\\dir1\\file.txt", dst_filename)

    actual = smbclient.readlink(dst_filename)
    assert ntpath.normcase(actual) == ntpath.normcase(src_filename)


def test_readlink_normal_file(smb_share):
    filename = "%s\\file.txt" % smb_share
    with smbclient.open_file(filename, mode="w") as fd:
        fd.write("content")

    expected = "[NtStatus 0xc0000275] The file or directory is not a reparse point"
    with pytest.raises(OSError, match=re.escape(expected)):
        smbclient.readlink(filename)


def test_readlink_not_symlink(monkeypatch):
    def a(*args, **kwargs):
        buffer = ReparseDataBuffer()
        buffer["reparse_tag"] = 1
        buffer["data_buffer"] = b""
        return buffer

    monkeypatch.setattr(smbclient._os, "_get_reparse_point", a)

    expected = "Cannot read link of reparse point with tag (1) IO_REPARSE_TAG_RESERVED_ONE at 'path'"
    with pytest.raises(ValueError, match=re.escape(expected)):
        smbclient.readlink("path")


def test_remove_file(smb_share):
    filename = "%s\\delete-me.txt" % smb_share

    with smbclient.open_file(filename, mode="wb") as fd:
        fd.write(b"Content")
    assert smbclient.listdir(smb_share) == ["delete-me.txt"]

    smbclient.remove(filename)
    assert smbclient.listdir(smb_share) == []


def test_remove_file_that_is_opened(smb_share):
    filename = "%s\\delete-me.txt" % smb_share

    with smbclient.open_file(filename, mode="wb", share_access="d") as fd:
        fd.write(b"Content")
        assert smbclient.listdir(smb_share) == ["delete-me.txt"]

        # Remove the file but because the file is opened by another process (us) it won't be deleted straight away
        smbclient.remove(filename)
        assert smbclient.listdir(smb_share) == ["delete-me.txt"]

    # After closing our handle we can then verify the file was deleted
    assert smbclient.listdir(smb_share) == []


def test_remove_file_that_is_opened_without_delete_access(smb_share):
    filename = "%s\\delete-me.txt" % smb_share
    with smbclient.open_file(filename, mode="wb") as fd:
        fd.write(b"Content")
        assert smbclient.listdir(smb_share) == ["delete-me.txt"]

        # Because our other handle does not have the d share_access set, this should fail
        expected = "The process cannot access the file because it is being used by another process"
        with pytest.raises(SMBOSError, match=re.escape(expected)):
            smbclient.remove(filename)


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_remove_symlink_missing_src(smb_share):
    src_filename = "%s\\file.txt" % smb_share
    dst_filename = "%s\\link.txt" % smb_share

    smbclient.symlink(src_filename, dst_filename)

    smbclient.remove(dst_filename)
    assert smbclient.listdir(smb_share) == []


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_remove_symlink_with_src(smb_share):
    src_filename = "%s\\file.txt" % smb_share
    dst_filename = "%s\\link.txt" % smb_share

    with smbclient.open_file(src_filename, mode="w") as fd:
        fd.write("content")

    smbclient.symlink(src_filename, dst_filename)

    smbclient.remove(dst_filename)
    assert smbclient.listdir(smb_share) == ["file.txt"]


def test_removedirs(smb_share):
    # first create a dir that isn't empty for our basedir that will fail
    parent_dir = "%s\\directory" % smb_share
    smbclient.mkdir(parent_dir)

    with smbclient.open_file("%s\\file.txt" % parent_dir, mode="w") as fd:
        fd.write("content")

    smbclient.mkdir("%s\\dir1" % parent_dir)
    smbclient.mkdir("%s\\dir1\\dir2" % parent_dir)

    smbclient.removedirs("%s\\dir1\\dir2" % parent_dir)

    assert smbclient.listdir(parent_dir) == ["file.txt"]


def test_rename_file(smb_share):
    filename = "%s\\file.txt" % smb_share
    with smbclient.open_file(filename, mode="w") as fd:
        fd.write("Content")

    newname = "%s\\file2.txt" % smb_share
    smbclient.rename(filename, newname)

    assert smbclient.listdir(smb_share) == ["file2.txt"]


def test_rename_folder(smb_share):
    dirname = "%s\\folder" % smb_share
    smbclient.mkdir(dirname)

    newname = "%s\\folder2" % smb_share
    smbclient.rename(dirname, newname)

    assert smbclient.listdir(smb_share) == ["folder2"]


def test_rename_fail_dst_not_absolute(smb_share):
    expected = "dst must be an absolute path to where the file or directory should be renamed."
    with pytest.raises(ValueError, match=re.escape(expected)):
        smbclient.rename(smb_share, "not_absolute")


def test_rename_fail_dst_different_root(smb_share):
    expected = "Cannot rename a file to a different root than the src."
    server = [p for p in ntpath.normpath(smb_share).split("\\") if p][0]

    with pytest.raises(ValueError, match=re.escape(expected)):
        smbclient.rename(smb_share, "\\\\%s\\dfs\\dst" % server)


def test_rename_dir(smb_share):
    src_dir = ntpath.join(smb_share, "src")
    dst_dir = ntpath.join(smb_share, "dst")

    smbclient.mkdir(src_dir)
    with smbclient.open_file(ntpath.join(src_dir, "file.txt"), mode="wb") as fd:
        fd.write(b"test data")

    smbclient.rename(src_dir, dst_dir)

    assert smbclient.listdir(smb_share) == ["dst"]
    assert smbclient.listdir(dst_dir) == ["file.txt"]
    with smbclient.open_file(ntpath.join(dst_dir, "file.txt"), mode="rb") as fd:
        assert fd.read() == b"test data"


def test_renames(smb_share):
    parent_src_dir = "%s\\directory" % smb_share
    smbclient.mkdir(parent_src_dir)

    with smbclient.open_file("%s\\file.txt" % parent_src_dir, mode="w") as fd:
        fd.write("content")

    src_dir = "%s\\subdir\\directory" % parent_src_dir
    smbclient.makedirs("%s\\sub-folder" % src_dir)
    with smbclient.open_file("%s\\sub-file.txt" % src_dir, mode="w") as fd:
        fd.write("content")

    target_dir = "%s\\target" % smb_share
    smbclient.renames(src_dir, target_dir)

    assert smbclient.listdir(parent_src_dir) == ["file.txt"]
    actual = smbclient.listdir(target_dir)
    assert len(actual)
    assert "sub-folder" in actual
    assert "sub-file.txt" in actual

    with smbclient.open_file("%s\\sub-file.txt" % target_dir, mode="r") as fd:
        assert fd.read() == "content"


def test_replace_file(smb_share):
    filename = "%s\\file.txt" % smb_share
    with smbclient.open_file(filename, mode="w") as fd:
        fd.write("Content")

    newname = "%s\\file2.txt" % smb_share
    smbclient.replace(filename, newname)

    assert smbclient.listdir(smb_share) == ["file2.txt"]
    with smbclient.open_file(newname, mode="r") as fd:
        actual = fd.read()
    assert actual == "Content"

    with smbclient.open_file(filename, mode="w") as fd:
        fd.write("To be replaced")

    smbclient.replace(newname, filename)
    assert smbclient.listdir(smb_share) == ["file.txt"]
    with smbclient.open_file(filename, mode="r") as fd:
        actual = fd.read()
    assert actual == "Content"


def test_replace_sharing_violation(smb_share):
    src_file = ntpath.join(smb_share, "src.txt")
    dst_file = ntpath.join(smb_share, "dst.txt")

    with smbclient.open_file(src_file, mode="wb") as fd:
        fd.write(b"test data")

    expected = re.escape("The process cannot access the file because it is being used by another process")
    with smbclient.open_file(dst_file, mode="wb"):
        with pytest.raises(SMBOSError, match=expected):
            smbclient.replace(src_file, dst_file)


def test_rmdir(smb_share):
    dir_name = "%s\\directory" % smb_share

    smbclient.mkdir(dir_name)
    assert smbclient.listdir(smb_share) == ["directory"]
    smbclient.rmdir(dir_name)
    assert smbclient.listdir(smb_share) == []

    expected = "[NtStatus 0xc0000034] No such file or directory: "
    with pytest.raises(OSError, match=re.escape(expected)):
        smbclient.rmdir(dir_name)


def test_rmdir_non_empty_dir(smb_share):
    dir_name = "%s\\directory" % smb_share

    smbclient.mkdir(dir_name)

    with smbclient.open_file("%s\\file.txt" % dir_name, mode="w") as fd:
        fd.write("content")

    expected = "[NtStatus 0xc0000101] Directory not empty: "
    with pytest.raises(OSError, match=re.escape(expected)):
        smbclient.rmdir(dir_name)


def test_rmdir_file(smb_share):
    filename = "%s\\file.txt" % smb_share
    with smbclient.open_file(filename, mode="w") as fd:
        fd.write("content")

    expected = "[NtStatus 0xc0000103] Not a directory: "
    with pytest.raises(OSError, match=re.escape(expected)):
        smbclient.rmdir(filename)


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_rmdir_symlink_missing_src(smb_share):
    src_dirname = "%s\\dir" % smb_share
    dst_dirname = "%s\\link" % smb_share

    smbclient.symlink(src_dirname, dst_dirname, target_is_directory=True)

    smbclient.rmdir(dst_dirname)
    assert smbclient.listdir(smb_share) == []


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_rmdir_symlink_with_src(smb_share):
    src_dirname = "%s\\dir" % smb_share
    dst_dirname = "%s\\link" % smb_share

    smbclient.mkdir(src_dirname)
    smbclient.symlink(src_dirname, dst_dirname)

    smbclient.rmdir(dst_dirname)
    assert smbclient.listdir(smb_share) == ["dir"]


def test_scandir_large(smb_share):
    dir_path = ntpath.join(smb_share, "directory")

    # Create lots of directories with the maximum name possible to ensure they won't be returned in 1 request.
    smbclient.mkdir(dir_path)
    for i in range(150):
        dirname = str(i).zfill(255)
        smbclient.mkdir(ntpath.join(smb_share, "directory", dirname))

    actual = []
    for entry in smbclient.scandir(dir_path):
        actual.append(entry.path)

    # Just a test optimisation, remove all the dirs so we don't have to re-enumerate them again in rmtree.
    for path in actual:
        smbclient.rmdir(path)

    assert len(actual) == 150


def test_scandir(smb_share):
    dir_path = ntpath.join(smb_share, "directory")
    smbclient.makedirs(dir_path, exist_ok=True)

    for name in ["file.txt", "unicode †[💩].txt"]:
        with smbclient.open_file(ntpath.join(dir_path, name), mode="w") as fd:
            fd.write("content")

    for name in ["subdir1", "subdir2", "unicode dir †[💩]", "subdir1\\sub"]:
        smbclient.mkdir(ntpath.join(dir_path, name))

    count = 0
    names = []
    for dir_entry in smbclient.scandir(dir_path):
        assert isinstance(dir_entry, SMBDirEntry)
        names.append(dir_entry.name)

        entry_info = dir_entry.smb_info
        assert isinstance(entry_info, smbclient.SMBDirEntryInformation)
        assert isinstance(entry_info.creation_time, datetime.datetime)
        assert isinstance(entry_info.last_access_time, datetime.datetime)
        assert isinstance(entry_info.last_write_time, datetime.datetime)
        assert isinstance(entry_info.change_time, datetime.datetime)
        assert isinstance(entry_info.end_of_file, int)
        assert isinstance(entry_info.allocation_size, int)
        assert isinstance(entry_info.file_attributes, int)
        assert isinstance(entry_info.ea_size, int)
        assert isinstance(entry_info.file_id, int)
        assert isinstance(entry_info.file_name, str)

        # Test out dir_entry for specific file and dir examples
        if dir_entry.name == "subdir1":
            assert str(dir_entry) == "<SMBDirEntry: 'subdir1'>"
            assert dir_entry.is_dir() is True
            assert dir_entry.is_file() is False
            assert dir_entry.stat(follow_symlinks=False).st_ino == dir_entry.inode()
            assert dir_entry.stat().st_ino == dir_entry.inode()
        elif dir_entry.name == "file.txt":
            assert str(dir_entry) == "<SMBDirEntry: 'file.txt'>"
            assert dir_entry.is_dir() is False
            assert dir_entry.is_file() is True
            assert dir_entry.stat().st_ino == dir_entry.inode()
            assert dir_entry.stat(follow_symlinks=False).st_ino == dir_entry.inode()

        assert dir_entry.is_symlink() is False
        assert dir_entry.inode() is not None
        assert dir_entry.inode() == dir_entry.stat().st_ino

        count += 1

    assert count == 5
    assert "unicode †[💩].txt" in names
    assert "unicode dir †[💩]" in names
    assert "subdir2" in names
    assert "subdir1" in names
    assert "file.txt" in names


def test_scandir_with_pattern(smb_share):
    for filename in ["file.txt", "file-test1.txt", "file-test1a.txt"]:
        with smbclient.open_file(rf"{smb_share}\{filename}", mode="w") as fd:
            fd.write("content")

    count = 0
    names = []
    for dir_entry in smbclient.scandir(smb_share, search_pattern="file-test*.txt"):
        names.append(dir_entry.name)
        count += 1

    assert count == 2
    assert "file-test1.txt" in names
    assert "file-test1a.txt" in names

    names = []
    for dir_entry in smbclient.scandir(smb_share, search_pattern="file-test?.txt"):
        names.append(dir_entry.name)

    assert names == ["file-test1.txt"]


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_scandir_with_symlink(smb_share):
    with smbclient.open_file("%s\\file.txt" % smb_share, mode="w") as fd:
        fd.write("content")
    smbclient.symlink("%s\\file.txt" % smb_share, "%s\\link.txt" % smb_share)

    smbclient.mkdir("%s\\dir" % smb_share)
    smbclient.symlink("%s\\dir" % smb_share, "%s\\link-dir" % smb_share, target_is_directory=True)

    for entry in smbclient.scandir(smb_share):
        # This is tested in other tests, we only care about symlinks.
        if entry.name in ["file.txt", "dir"]:
            continue

        assert entry.is_symlink()
        assert entry.is_dir(follow_symlinks=False) is False
        assert entry.is_file(follow_symlinks=False) is False

        if entry.name == "link.txt":
            assert entry.is_dir() is False
            assert entry.is_file() is True
        else:
            assert entry.is_dir() is True
            assert entry.is_file() is False


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_scandir_with_broken_symlink(smb_share):
    smbclient.symlink("%s\\file.txt" % smb_share, "%s\\link.txt" % smb_share)
    smbclient.symlink("%s\\dir" % smb_share, "%s\\link-dir" % smb_share, target_is_directory=True)

    for entry in smbclient.scandir(smb_share):
        assert entry.is_symlink()
        assert entry.is_dir() is False
        assert entry.is_dir(follow_symlinks=False) is False  # broken link target
        assert entry.is_file() is False
        assert entry.is_file(follow_symlinks=False) is False  # broken link target


def test_scandir_with_cache(smb_real):
    share = smb_real[4]
    test_folder = f"Pýtæs†-[{time.time()}] 💩"
    share_path = rf"{share}\{test_folder}"
    cache = {}
    smbclient.mkdir(share_path, username=smb_real[0], password=smb_real[1], port=smb_real[3], connection_cache=cache)

    try:
        dir_path = ntpath.join(share_path, "directory")
        smbclient.makedirs(dir_path, exist_ok=True, connection_cache=cache)

        for name in ["file.txt", "unicode †[💩].txt"]:
            with smbclient.open_file(ntpath.join(dir_path, name), mode="w", connection_cache=cache) as fd:
                fd.write("content")

        for name in ["subdir1", "subdir2", "unicode dir †[💩]", "subdir1\\sub"]:
            smbclient.mkdir(ntpath.join(dir_path, name), connection_cache=cache)

        count = 0
        names = []
        for dir_entry in smbclient.scandir(dir_path, connection_cache=cache):
            assert isinstance(dir_entry, SMBDirEntry)
            names.append(dir_entry.name)

            # Test out dir_entry for specific file and dir examples
            if dir_entry.name == "subdir1":
                assert str(dir_entry) == "<SMBDirEntry: 'subdir1'>"
                assert dir_entry.is_dir() is True
                assert dir_entry.is_file() is False
                assert dir_entry.stat(follow_symlinks=False).st_ino == dir_entry.inode()
                assert dir_entry.stat().st_ino == dir_entry.inode()
            elif dir_entry.name == "file.txt":
                assert str(dir_entry) == "<SMBDirEntry: 'file.txt'>"
                assert dir_entry.is_dir() is False
                assert dir_entry.is_file() is True
                assert dir_entry.stat().st_ino == dir_entry.inode()
                assert dir_entry.stat(follow_symlinks=False).st_ino == dir_entry.inode()

            assert dir_entry.is_symlink() is False
            assert dir_entry.inode() is not None
            assert dir_entry.inode() == dir_entry.stat().st_ino

            count += 1

        assert count == 5
        assert "unicode †[💩].txt" in names
        assert "unicode dir †[💩]" in names
        assert "subdir2" in names
        assert "subdir1" in names
        assert "file.txt" in names

    finally:
        rmtree(share_path, connection_cache=cache)
        smbclient.reset_connection_cache(connection_cache=cache)


def test_stat_directory(smb_share):
    actual = smbclient.stat(smb_share)
    assert isinstance(actual, smbclient.SMBStatResult)
    assert actual[0] == actual.st_mode
    assert actual[1] == actual.st_ino
    assert actual[2] == actual.st_dev
    assert actual[3] == actual.st_nlink
    assert actual[4] == actual.st_uid
    assert actual[5] == actual.st_gid
    assert actual[6] == actual.st_size
    assert actual[7] == actual.st_atime
    assert actual[8] == actual.st_mtime
    assert actual[9] == actual.st_ctime
    assert actual[10] == actual.st_chgtime
    assert actual[11] == actual.st_atime_ns
    assert actual[12] == actual.st_mtime_ns
    assert actual[13] == actual.st_ctime_ns
    assert actual[14] == actual.st_chgtime_ns
    assert actual[15] == actual.st_file_attributes
    assert actual[16] == actual.st_reparse_tag

    assert stat.S_ISDIR(actual.st_mode)
    assert not stat.S_ISREG(actual.st_mode)
    assert not stat.S_ISLNK(actual.st_mode)
    assert actual.st_nlink == 1
    assert actual.st_gid == 0
    assert actual.st_uid == 0
    assert actual.st_size == 0
    assert actual.st_ctime is not None
    assert actual.st_chgtime is not None
    assert actual.st_atime is not None
    assert actual.st_mtime is not None
    assert actual.st_ctime_ns is not None
    assert actual.st_chgtime_ns is not None
    assert actual.st_atime_ns is not None
    assert actual.st_mtime_ns is not None
    assert actual.st_file_attributes == FileAttributes.FILE_ATTRIBUTE_DIRECTORY
    assert actual.st_reparse_tag == 0


def test_stat_file(smb_share):
    filename = "%s\\file.txt" % smb_share
    with smbclient.open_file(filename, mode="w") as fd:
        fd.write("content")

    actual = smbclient.stat(filename)
    assert isinstance(actual, smbclient.SMBStatResult)
    assert actual[0] == actual.st_mode
    assert actual[1] == actual.st_ino
    assert actual[2] == actual.st_dev
    assert actual[3] == actual.st_nlink
    assert actual[4] == actual.st_uid
    assert actual[5] == actual.st_gid
    assert actual[6] == actual.st_size
    assert actual[7] == actual.st_atime
    assert actual[8] == actual.st_mtime
    assert actual[9] == actual.st_ctime
    assert actual[10] == actual.st_chgtime
    assert actual[11] == actual.st_atime_ns
    assert actual[12] == actual.st_mtime_ns
    assert actual[13] == actual.st_ctime_ns
    assert actual[14] == actual.st_chgtime_ns
    assert actual[15] == actual.st_file_attributes
    assert actual[16] == actual.st_reparse_tag

    assert not stat.S_ISDIR(actual.st_mode)
    assert stat.S_ISREG(actual.st_mode)
    assert not stat.S_ISLNK(actual.st_mode)
    assert actual.st_nlink == 1
    assert actual.st_gid == 0
    assert actual.st_uid == 0
    assert actual.st_size == 7
    assert actual.st_ctime is not None
    assert actual.st_chgtime is not None
    assert actual.st_atime is not None
    assert actual.st_mtime is not None
    assert actual.st_ctime_ns is not None
    assert actual.st_chgtime_ns is not None
    assert actual.st_atime_ns is not None
    assert actual.st_mtime_ns is not None
    assert actual.st_file_attributes == FileAttributes.FILE_ATTRIBUTE_ARCHIVE
    assert actual.st_reparse_tag == 0


def test_stat_readonly(smb_share):
    filename = "%s\\file.txt" % smb_share

    with smbclient.open_file(filename, mode="w", file_attributes=FileAttributes.FILE_ATTRIBUTE_READONLY) as fd:
        fd.write("content")

    actual = smbclient.stat(filename)
    assert actual.st_file_attributes == 33


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_stat_symlink_follow(smb_share):
    src_filename = "%s\\file.txt" % smb_share
    dst_filename = "%s\\link.txt" % smb_share

    with smbclient.open_file(src_filename, mode="w") as fd:
        fd.write("content")

    smbclient.symlink(src_filename, dst_filename)

    actual_src = smbclient.stat(src_filename)
    actual = smbclient.stat(dst_filename)
    assert actual.st_ino == actual_src.st_ino


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_stat_symlink_follow_no_target(smb_share):
    src_filename = "%s\\file.txt" % smb_share
    dst_filename = "%s\\link.txt" % smb_share

    smbclient.symlink(src_filename, dst_filename)

    expected = "[NtStatus 0xc0000034] No such file or directory: "
    with pytest.raises(OSError, match=re.escape(expected)):
        smbclient.stat(dst_filename)


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_stat_symlink_dont_follow(smb_share):
    src_filename = "%s\\file.txt" % smb_share
    dst_filename = "%s\\link.txt" % smb_share

    with smbclient.open_file(src_filename, mode="w") as fd:
        fd.write("content")

    smbclient.symlink(src_filename, dst_filename)

    actual_src = smbclient.stat(src_filename)
    actual = smbclient.stat(dst_filename, follow_symlinks=False)
    assert actual.st_ino != actual_src.st_ino
    assert stat.S_ISLNK(actual.st_mode)


def test_stat_volume(smb_share):
    actual = smbclient.stat_volume(smb_share)

    assert isinstance(actual, smbclient.SMBStatVolumeResult)
    assert isinstance(actual.actual_available_size, int)
    assert isinstance(actual.total_size, int)
    assert isinstance(actual.caller_available_size, int)


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_symlink_file_missing_src(smb_share):
    src_filename = "%s\\file.txt" % smb_share
    dst_filename = "%s\\link.txt" % smb_share

    smbclient.symlink(src_filename, dst_filename)

    assert smbclient.listdir(smb_share) == ["link.txt"]
    actual = smbclient.lstat(dst_filename)
    assert stat.S_ISLNK(actual.st_mode)
    assert actual.st_file_attributes == (
        FileAttributes.FILE_ATTRIBUTE_REPARSE_POINT | FileAttributes.FILE_ATTRIBUTE_ARCHIVE
    )


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_symlink_file_existing_src(smb_share):
    src_filename = "%s\\file.txt" % smb_share
    dst_filename = "%s\\link.txt" % smb_share

    with smbclient.open_file(src_filename, mode="w") as fd:
        fd.write("content")

    smbclient.symlink(src_filename, dst_filename)

    actual_files = smbclient.listdir(smb_share)
    assert "link.txt" in actual_files
    assert "file.txt" in actual_files

    actual = smbclient.lstat(dst_filename)
    assert stat.S_ISLNK(actual.st_mode)
    assert actual.st_file_attributes == (
        FileAttributes.FILE_ATTRIBUTE_REPARSE_POINT | FileAttributes.FILE_ATTRIBUTE_ARCHIVE
    )


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_symlink_dir_missing_src(smb_share):
    src_dirname = "%s\\dir" % smb_share
    dst_dirname = "%s\\link" % smb_share

    smbclient.symlink(src_dirname, dst_dirname, target_is_directory=True)

    assert smbclient.listdir(smb_share) == ["link"]
    actual = smbclient.lstat(dst_dirname)
    assert stat.S_ISLNK(actual.st_mode)
    assert actual.st_file_attributes == (
        FileAttributes.FILE_ATTRIBUTE_DIRECTORY | FileAttributes.FILE_ATTRIBUTE_REPARSE_POINT
    )


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_symlink_dir_existing_src(smb_share):
    src_dirname = "%s\\dir" % smb_share
    dst_dirname = "%s\\link" % smb_share

    smbclient.mkdir(src_dirname)

    smbclient.symlink(src_dirname, dst_dirname)

    actual_dirs = smbclient.listdir(smb_share)
    assert "link" in actual_dirs
    assert "dir" in actual_dirs
    actual = smbclient.lstat(dst_dirname)
    assert stat.S_ISLNK(actual.st_mode)
    assert actual.st_file_attributes == (
        FileAttributes.FILE_ATTRIBUTE_DIRECTORY | FileAttributes.FILE_ATTRIBUTE_REPARSE_POINT
    )


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_symlink_relative_src(smb_share):
    src_filename = "%s\\dir1\\file.txt" % smb_share
    dst_filename = "%s\\dir2\\link.txt" % smb_share

    smbclient.mkdir("%s\\dir1" % smb_share)
    smbclient.mkdir("%s\\dir2" % smb_share)

    with smbclient.open_file(src_filename, mode="w") as fd:
        fd.write("content")

    smbclient.symlink("..\\dir1\\file.txt", dst_filename)

    with smbclient.open_file(dst_filename) as fd:
        assert fd.read() == "content"

    actual = smbclient.lstat(dst_filename)
    assert stat.S_ISLNK(actual.st_mode)
    assert actual.st_file_attributes == (
        FileAttributes.FILE_ATTRIBUTE_REPARSE_POINT | FileAttributes.FILE_ATTRIBUTE_ARCHIVE
    )


def test_symlink_fail_not_absolute_dst(smb_share):
    expected = "The link dst must be an absolute UNC path for where the link is to be created"
    with pytest.raises(ValueError, match=re.escape(expected)):
        smbclient.symlink("source", "link")


def test_symlink_fail_relative_different_root(smb_share):
    expected = "Resolved link src root '\\\\server2\\share_name' must be the same as the dst root"
    with pytest.raises(ValueError, match=re.escape(expected)):
        smbclient.symlink("\\\\server2\\share_name", smb_share)


def test_truncate_file(smb_share):
    filename = "%s\\file.txt" % smb_share
    with smbclient.open_file(filename, mode="wb") as fd:
        fd.write(b"\x01\x02\x03\x04")

    smbclient.truncate(filename, 2)
    with smbclient.open_file(filename, mode="rb") as fd:
        actual = fd.read()
    assert actual == b"\x01\x02"

    smbclient.truncate(filename, 4)
    with smbclient.open_file(filename, mode="rb") as fd:
        actual = fd.read()
    assert actual == b"\x01\x02\x00\x00"


def test_unlink_file(smb_share):
    filename = "%s\\delete-me.txt" % smb_share

    with smbclient.open_file(filename, mode="wb") as fd:
        fd.write(b"Content")
    assert smbclient.listdir(smb_share) == ["delete-me.txt"]

    smbclient.unlink(filename)
    assert smbclient.listdir(smb_share) == []


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="Samba does not update timestamps"
)
def test_set_utime_file(smb_share):
    filename = "%s\\file.txt" % smb_share

    with smbclient.open_file(filename, mode="w") as fd:
        fd.write("abc")

    before_stat = smbclient.stat(filename)
    smbclient.utime(filename, times=(1, 1))
    actual = smbclient.stat(filename)

    assert actual.st_atime == 1.0
    assert actual.st_atime_ns == 1000000000
    assert actual.st_ctime == before_stat.st_ctime
    assert actual.st_ctime_ns == before_stat.st_ctime_ns
    assert actual.st_mtime == 1.0
    assert actual.st_mtime_ns == 1000000000


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="Samba does not update timestamps"
)
def test_set_utime_file_negative(smb_share):
    filename = "%s\\file.txt" % smb_share

    with smbclient.open_file(filename, mode="w") as fd:
        fd.write("abc")

    before_stat = smbclient.stat(filename)
    smbclient.utime(filename, times=(-1, -1))
    actual = smbclient.stat(filename)

    assert actual.st_atime == -1.0
    assert actual.st_atime_ns == -1000000000
    assert actual.st_ctime == before_stat.st_ctime
    assert actual.st_ctime_ns == before_stat.st_ctime_ns
    assert actual.st_mtime == -1.0
    assert actual.st_mtime_ns == -1000000000


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="Samba does not update timestamps"
)
def test_set_utime_directory(smb_share):
    dirname = "%s\\directory" % smb_share

    smbclient.mkdir(dirname)

    before_stat = smbclient.stat(dirname)
    smbclient.utime(dirname, times=(1, 1))
    actual = smbclient.stat(dirname)

    assert actual.st_atime == 1.0
    assert actual.st_atime_ns == 1000000000
    assert actual.st_ctime == before_stat.st_ctime
    assert actual.st_ctime_ns == before_stat.st_ctime_ns
    assert actual.st_mtime == 1.0
    assert actual.st_mtime_ns == 1000000000


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="Samba does not update timestamps"
)
def test_set_utime_ns(smb_share):
    filename = "%s\\file.txt" % smb_share

    with smbclient.open_file(filename, mode="w") as fd:
        fd.write("abc")

    before_stat = smbclient.stat(filename)
    smbclient.utime(filename, ns=(1000000000, 1000000000))
    actual = smbclient.stat(filename)

    assert actual.st_atime == 1.0
    assert actual.st_atime_ns == 1000000000
    assert actual.st_ctime == before_stat.st_ctime
    assert actual.st_ctime_ns == before_stat.st_ctime_ns
    assert actual.st_mtime == 1.0
    assert actual.st_mtime_ns == 1000000000


def test_set_utime_both_fail():
    with pytest.raises(ValueError, match="Both times and ns have been set for utime"):
        smbclient.utime("", times=(0, 0), ns=(0, 0))


def test_set_utime_bad_tuple():
    expected = "The time tuple should be a 2-tuple of the form (atime, mtime)"
    with pytest.raises(ValueError, match=re.escape(expected)):
        smbclient.utime("", times=(0, 0, 0))


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="Samba does not update timestamps"
)
def test_set_utime_touch(smb_share):
    filename = "%s\\file.txt" % smb_share

    with smbclient.open_file(filename, mode="w") as fd:
        fd.write("abc")

    # Set to EPOCH for baseline
    smbclient.utime(filename, times=(0, 0))
    before_stat = smbclient.stat(filename)
    smbclient.utime(filename)
    actual = smbclient.stat(filename)

    assert actual.st_atime > before_stat.st_atime
    assert actual.st_atime_ns > before_stat.st_atime_ns
    assert actual.st_ctime == before_stat.st_ctime
    assert actual.st_ctime_ns == before_stat.st_ctime_ns
    assert actual.st_mtime > before_stat.st_mtime
    assert actual.st_mtime_ns > before_stat.st_mtime_ns


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_set_utime_follow(smb_share):
    src_filename = "%s\\file.txt" % smb_share
    dst_filename = "%s\\link.txt" % smb_share

    with smbclient.open_file(src_filename, mode="w") as fd:
        fd.write("content")

    smbclient.symlink(src_filename, dst_filename)

    smbclient.utime(dst_filename, times=(1, 1))

    actual_link = smbclient.lstat(dst_filename)
    actual_file = smbclient.lstat(src_filename)

    assert actual_link.st_atime != 1.0
    assert actual_link.st_mtime != 1.0
    assert actual_file.st_atime == 1.0
    assert actual_file.st_mtime == 1.0


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_set_utime_dont_follow(smb_share):
    src_filename = "%s\\file.txt" % smb_share
    dst_filename = "%s\\link.txt" % smb_share

    with smbclient.open_file(src_filename, mode="w") as fd:
        fd.write("content")

    smbclient.symlink(src_filename, dst_filename)

    smbclient.utime(dst_filename, times=(1, 1), follow_symlinks=False)

    actual_link = smbclient.lstat(dst_filename)
    actual_file = smbclient.lstat(src_filename)

    assert actual_link.st_atime == 1.0
    assert actual_link.st_mtime == 1.0
    assert actual_file.st_atime != 1.0
    assert actual_file.st_mtime != 1.0


def test_walk_topdown(smb_share):
    smbclient.makedirs("%s\\dir1\\dir2\\dir3" % smb_share)

    for name in ["file1.txt", "dir1\\file2.txt", "dir1\\dir2\\file3.txt", "dir1\\dir2\\dir3\\file4.txt"]:
        with smbclient.open_file(rf"{smb_share}\{name}", mode="w") as fd:
            fd.write("content")

    scanned_files = []
    scanned_dirs = []
    for root, dirs, files in smbclient.walk(smb_share):
        scanned_dirs.append(dirs[0])

        # Test out removing a dir entry will affect the further walks.
        if files == ["file3.txt"]:
            del dirs[0]
        scanned_files.append(files[0])

    assert scanned_files == ["file1.txt", "file2.txt", "file3.txt"]
    assert scanned_dirs == ["dir1", "dir2", "dir3"]


def test_walk_bottomup(smb_share):
    smbclient.makedirs("%s\\dir1\\dir2\\dir3" % smb_share)

    for name in ["file1.txt", "dir1\\file2.txt", "dir1\\dir2\\file3.txt", "dir1\\dir2\\dir3\\file4.txt"]:
        with smbclient.open_file(rf"{smb_share}\{name}", mode="w") as fd:
            fd.write("content")

    scanned_files = []
    scanned_dirs = []
    for root, dirs, files in smbclient.walk(smb_share, topdown=False):
        if dirs:
            scanned_dirs.append(dirs[0])
        scanned_files.append(files[0])

    assert scanned_files == ["file4.txt", "file3.txt", "file2.txt", "file1.txt"]
    assert scanned_dirs == ["dir3", "dir2", "dir1"]


def test_walk_no_dir(smb_share):
    fake_dir = "%s\\fake-dir" % smb_share
    had_result = False
    for _ in smbclient.walk(fake_dir):
        had_result = True
    assert not had_result


def test_walk_no_dir_on_error(smb_share):
    fake_dir = "%s\\fake-dir" % smb_share

    def on_error(err):
        raise err

    expected = "[Error 2] [NtStatus 0xc0000034] No such file or directory: "
    with pytest.raises(SMBOSError, match=re.escape(expected)):
        for _ in smbclient.walk(fake_dir, onerror=on_error):
            pass


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_walk_with_symlink_follow(smb_share):
    src_dirname = "%s\\dir" % smb_share
    dst_dirname = "%s\\link" % smb_share
    smbclient.mkdir(src_dirname)
    smbclient.symlink(src_dirname, dst_dirname)

    with smbclient.open_file("%s\\file.txt" % src_dirname, mode="w") as fd:
        fd.write("content")

    scanned_roots = {}
    for root, dirs, files in smbclient.walk(smb_share, follow_symlinks=True):
        scanned_roots[root] = {"dirs": dirs, "files": files}

    assert len(scanned_roots) == 3
    assert "dir" in scanned_roots[smb_share]["dirs"]
    assert "link" in scanned_roots[smb_share]["dirs"]
    assert scanned_roots[smb_share]["files"] == []

    assert scanned_roots[src_dirname]["dirs"] == []
    assert scanned_roots[src_dirname]["files"] == ["file.txt"]

    assert scanned_roots[dst_dirname]["dirs"] == []
    assert scanned_roots[dst_dirname]["files"] == ["file.txt"]


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_walk_with_symlink_dont_follow(smb_share):
    src_dirname = "%s\\dir" % smb_share
    dst_dirname = "%s\\link" % smb_share
    smbclient.mkdir(src_dirname)
    smbclient.symlink(src_dirname, dst_dirname)

    with smbclient.open_file("%s\\file.txt" % src_dirname, mode="w") as fd:
        fd.write("content")

    scanned_roots = {}
    for root, dirs, files in smbclient.walk(smb_share):
        scanned_roots[root] = {"dirs": dirs, "files": files}

    assert len(scanned_roots) == 2
    assert "dir" in scanned_roots[smb_share]["dirs"]
    assert "link" in scanned_roots[smb_share]["dirs"]
    assert scanned_roots[smb_share]["files"] == []

    assert scanned_roots[src_dirname]["dirs"] == []
    assert scanned_roots[src_dirname]["files"] == ["file.txt"]


def test_xattr_file(smb_share):
    filename = "%s\\file.txt" % smb_share

    with smbclient.open_file(filename, mode="w") as fd:
        fd.write("content")

    assert smbclient.listxattr(filename) == []

    smbclient.setxattr(filename, b"KEY", b"VALUE")
    assert smbclient.listxattr(filename) == [b"KEY"]
    assert smbclient.getxattr(filename, b"KEY") == b"VALUE"

    smbclient.removexattr(filename, b"KEY")
    assert smbclient.listxattr(filename) == []

    smbclient.setxattr(filename, b"KEY", b"VALUE")

    expected = "[NtStatus 0xc0000011]"
    with pytest.raises(OSError, match=re.escape(expected)):
        smbclient.getxattr(filename, b"MISSING")

    expected = "[NtStatus 0xc0000035] File exists: "
    with pytest.raises(OSError, match=re.escape(expected)):
        smbclient.setxattr(filename, b"KEY", b"VALUE", smbclient.XATTR_CREATE)

    expected = "NtStatus 0xc0000034] No such file or directory: "
    with pytest.raises(OSError, match=re.escape(expected)):
        smbclient.setxattr(filename, b"MISSING", b"VALUE", smbclient.XATTR_REPLACE)

    smbclient.setxattr(filename, b"NEW", b"VALUE", smbclient.XATTR_CREATE)
    assert smbclient.getxattr(filename, b"NEW") == b"VALUE"
    smbclient.setxattr(filename, b"NEW", b"REPLACE", smbclient.XATTR_REPLACE)
    assert smbclient.getxattr(filename, b"NEW") == b"REPLACE"

    assert smbclient.listxattr(filename) == [b"KEY", b"NEW"]


def test_xattr_missing_file(smb_share):
    filename = "%s\\file.txt" % smb_share

    expected = "[Error 2] [NtStatus 0xc0000034] No such file or directory: "
    with pytest.raises(SMBOSError, match=re.escape(expected)):
        smbclient.listxattr(filename)


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_xattr_follow(smb_share):
    src_filename = "%s\\file.txt" % smb_share
    dst_filename = "%s\\link.txt" % smb_share

    with smbclient.open_file(src_filename, mode="w") as fd:
        fd.write("content")

    smbclient.symlink(src_filename, dst_filename)

    smbclient.setxattr(dst_filename, b"KEY", b"VALUE")
    assert smbclient.listxattr(dst_filename) == [b"KEY"]
    assert smbclient.listxattr(dst_filename, follow_symlinks=False) == []
    assert smbclient.listxattr(src_filename) == [b"KEY"]
    assert smbclient.getxattr(dst_filename, b"KEY") == b"VALUE"

    smbclient.removexattr(dst_filename, b"KEY")
    assert smbclient.listxattr(dst_filename) == []


@pytest.mark.skipif(
    os.name != "nt" and not os.environ.get("SMB_FORCE", False), reason="cannot create symlinks on Samba"
)
def test_xattr_dont_follow(smb_share):
    src_filename = "%s\\file.txt" % smb_share
    dst_filename = "%s\\link.txt" % smb_share

    with smbclient.open_file(src_filename, mode="w") as fd:
        fd.write("content")

    smbclient.symlink(src_filename, dst_filename)

    smbclient.setxattr(dst_filename, b"KEY", b"VALUE", follow_symlinks=False)
    assert smbclient.listxattr(dst_filename) == []
    assert smbclient.listxattr(dst_filename, follow_symlinks=False) == [b"KEY"]
    assert smbclient.listxattr(src_filename) == []
    assert smbclient.getxattr(dst_filename, b"KEY", follow_symlinks=False) == b"VALUE"

    smbclient.removexattr(dst_filename, b"KEY", follow_symlinks=False)
    assert smbclient.listxattr(dst_filename, follow_symlinks=False) == []


def test_credit_calculation_with_compound_requests(smb_share):
    filename = ntpath.join(smb_share, "file.txt")

    connection = None
    with smbclient.open_file(filename, mode="wb") as fd:
        connection = fd.raw.fd.connection

    # Sending a compound message to make our client credit window out of wack. A stat calls has 5 requests in 1 which
    # based on the older faulty logic added 4 extra credits we did not have. This should no longer be the case but we
    # want to test this logic to ensure it doesn't regress in the future.
    assert smbclient.stat(filename).st_size == 0

    # Write data that should fit in the credits that we have available.
    available_credits = connection.sequence_window["high"] - connection.sequence_window["low"]
    large_length = available_credits * 65536
    with smbclient.open_file(filename, buffering=0, mode="wb") as fd:
        fd.write(b"a" * large_length)

    assert smbclient.stat(filename).st_size == large_length


def test_dfs_path(smb_dfs_share):
    actual_listdir = smbclient.listdir(smb_dfs_share)
    assert actual_listdir == []

    test_dir = ntpath.join(smb_dfs_share, "test folder")
    smbclient.mkdir(test_dir)

    test_file = ntpath.join(smb_dfs_share, "test file.txt")
    with smbclient.open_file(test_file, mode="wb") as fd:
        fd.write(b"test data")

    for info in smbclient.scandir(smb_dfs_share):
        if info.name == "test file.txt":
            assert info.path == test_file
            assert not info.is_dir()
            assert info.is_file()

        else:
            assert info.path == test_dir
            assert info.is_dir()
            assert not info.is_file()


def test_dfs_path_rename(smb_dfs_share):
    test_dir = ntpath.join(smb_dfs_share, "test folder")
    smbclient.mkdir(test_dir)

    test_file = ntpath.join(smb_dfs_share, "test file.txt")
    with smbclient.open_file(test_file, mode="wb") as fd:
        fd.write(b"test data")

    dst_dfs_path = ntpath.join(test_dir, "target renamed.txt")
    smbclient.rename(test_file, dst_dfs_path)

    assert smbclient.listdir(smb_dfs_share) == ["test folder"]
    assert smbclient.listdir(test_dir) == ["target renamed.txt"]

    with smbclient.open_file(dst_dfs_path, mode="rb") as fd:
        assert fd.read() == b"test data"


def test_dfs_path_replace(smb_dfs_share):
    test_dir = ntpath.join(smb_dfs_share, "test folder")
    smbclient.mkdir(test_dir)

    test_file = ntpath.join(smb_dfs_share, "test file.txt")
    with smbclient.open_file(test_file, mode="wb") as fd:
        fd.write(b"other data")

    dst_dfs_path = ntpath.join(test_dir, "target renamed.txt")
    with smbclient.open_file(dst_dfs_path, mode="wb") as fd:
        fd.write(b"test data")

    smbclient.replace(dst_dfs_path, test_file)

    actual_contents = smbclient.listdir(smb_dfs_share)
    assert "test folder" in actual_contents
    assert "test file.txt" in actual_contents

    assert smbclient.listdir(test_dir) == []

    with smbclient.open_file(test_file, mode="rb") as fd:
        assert fd.read() == b"test data"


def test_broken_dfs_path(smb_real):
    dfs_path = "\\\\" + ntpath.join(smb_real[2], "dfs", "broken")

    # The message returned differs based on whether the server is Samba or Windows. Just make sure we do raise an
    # error and that it doesn't continuously loop.
    with pytest.raises(SMBOSError):
        smbclient.listdir(dfs_path, username=smb_real[0], password=smb_real[1], port=smb_real[3])


def test_dfs_nonexisting_path(smb_dfs_share):
    fake_file = ntpath.join(smb_dfs_share, "missing file.txt")

    with pytest.raises(SMBOSError):
        smbclient.lstat(fake_file)
