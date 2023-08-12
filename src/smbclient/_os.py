# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import collections
import errno
import io
import ntpath
import operator
import os
import stat as py_stat
import time

from smbclient._io import (
    SMBDirectoryIO,
    SMBFileIO,
    SMBFileTransaction,
    SMBPipeIO,
    SMBRawIO,
    ioctl_request,
    query_info,
    set_info,
)
from smbprotocol import MAX_PAYLOAD_SIZE
from smbprotocol._text import to_bytes, to_text
from smbprotocol.exceptions import NoSuchFile, SMBOSError, SMBResponseException
from smbprotocol.file_info import (
    FileAttributeTagInformation,
    FileBasicInformation,
    FileDispositionInformation,
    FileFsFullSizeInformation,
    FileFsVolumeInformation,
    FileFullEaInformation,
    FileIdFullDirectoryInformation,
    FileInformationClass,
    FileInternalInformation,
    FileLinkInformation,
    FileRenameInformation,
    FileStandardInformation,
)
from smbprotocol.header import NtStatus
from smbprotocol.ioctl import (
    CtlCode,
    IOCTLFlags,
    SMB2SrvCopyChunk,
    SMB2SrvCopyChunkCopy,
    SMB2SrvCopyChunkResponse,
    SMB2SrvRequestResumeKey,
)
from smbprotocol.open import (
    CreateOptions,
    FileAttributes,
    FilePipePrinterAccessMask,
    QueryInfoFlags,
)
from smbprotocol.reparse_point import (
    ReparseDataBuffer,
    ReparseTags,
    SymbolicLinkFlags,
    SymbolicLinkReparseDataBuffer,
)
from smbprotocol.structure import DateTimeField

XATTR_CREATE = getattr(os, "XATTR_CREATE", 1)
XATTR_REPLACE = getattr(os, "XATTR_REPLACE", 2)

MAX_COPY_CHUNK_SIZE = 1 * 1024 * 1024  # maximum chunksize 1M from 3.3.3 in MS-SMB documentation
MAX_COPY_CHUNK_COUNT = 16  # maximum total chunksize 16M from 3.3.3 in MS-SMB documentation

SMBStatResult = collections.namedtuple(
    "SMBStatResult",
    [
        "st_mode",
        "st_ino",
        "st_dev",
        "st_nlink",
        "st_uid",
        "st_gid",
        "st_size",
        "st_atime",
        "st_mtime",
        "st_ctime",
        # Extra attributes not part of the base stat_result
        "st_chgtime",  # ChangeTime, change of file metadata and not just data (mtime)
        "st_atime_ns",
        "st_mtime_ns",
        "st_ctime_ns",
        "st_chgtime_ns",
        "st_file_attributes",
        "st_reparse_tag",
    ],
)


SMBStatVolumeResult = collections.namedtuple(
    "SMBStatVolumeResult",
    [
        "total_size",
        "caller_available_size",
        "actual_available_size",
    ],
)


def is_remote_path(path: str) -> bool:
    """
    Returns True iff the given path is a remote SMB path (rather than a local path).

    :param path: The filepath.
    :return: True iff the given path is a remote SMB path.
    """
    return path.startswith("\\\\") or path.startswith("//")


def copyfile(src, dst, **kwargs):
    """
    Copy a file to a different location on the same server. This will fail if the src and dst paths are to a different
    server. This will replace the file at dst if it already exists.

    This is not normally part of the builtin os package but because it relies on some SMB IOCTL commands it is useful
    to expose here.

    :param src: The full UNC path of the source file.
    :param dst: The full UNC path of the target file.
    :param kwargs: Common SMB Session arguments for smbclient.
    """
    norm_src = ntpath.normpath(src)
    norm_dst = ntpath.normpath(dst)

    if not is_remote_path(norm_src):
        raise ValueError("src must be an absolute path to where the file should be copied from.")

    if not is_remote_path(norm_dst):
        raise ValueError("dst must be an absolute path to where the file should be copied to.")

    src_host = ntpath.splitdrive(norm_src)[0].split("\\")[2]
    dst_host = ntpath.splitdrive(norm_dst)[0].split("\\")[2]
    if src_host.lower() != dst_host.lower():
        raise ValueError("Cannot copy a file to a different host than the src.")

    with open_file(norm_src, mode="rb", share_access="r", buffering=0, **kwargs) as src_fd:
        with SMBFileTransaction(src_fd) as transaction_src:
            ioctl_request(
                transaction_src,
                CtlCode.FSCTL_SRV_REQUEST_RESUME_KEY,
                flags=IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL,
                output_size=32,
            )

        resume_response = SMB2SrvRequestResumeKey()
        resume_response.unpack(transaction_src.results[0])
        resume_key = resume_response["resume_key"].get_value()

        chunks = []
        offset = 0
        while offset < src_fd.fd.end_of_file:
            copychunk_struct = SMB2SrvCopyChunk()
            copychunk_struct["source_offset"] = offset
            copychunk_struct["target_offset"] = offset
            copychunk_struct["length"] = min(MAX_COPY_CHUNK_SIZE, src_fd.fd.end_of_file - offset)

            chunks.append(copychunk_struct)
            offset += MAX_COPY_CHUNK_SIZE

        with open_file(norm_dst, mode="wb", share_access="r", buffering=0, **kwargs) as dst_fd:
            for i in range(0, len(chunks), MAX_COPY_CHUNK_COUNT):
                batch = chunks[i : i + MAX_COPY_CHUNK_COUNT]
                with SMBFileTransaction(dst_fd) as transaction_dst:
                    copychunkcopy_struct = SMB2SrvCopyChunkCopy()
                    copychunkcopy_struct["source_key"] = resume_key
                    copychunkcopy_struct["chunks"] = batch

                    ioctl_request(
                        transaction_dst,
                        CtlCode.FSCTL_SRV_COPYCHUNK_WRITE,
                        flags=IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL,
                        output_size=12,
                        input_buffer=copychunkcopy_struct,
                    )

                for result in transaction_dst.results:
                    copychunk_response = SMB2SrvCopyChunkResponse()
                    copychunk_response.unpack(result)
                    if copychunk_response["chunks_written"].get_value() != len(batch):
                        raise OSError(
                            f"Failed to copy all the chunks in a server side copyfile: '{norm_src}' -> '{norm_dst}'"
                        )


def link(src, dst, follow_symlinks=True, **kwargs):
    """
    Create a hard link pointing to src named dst. The dst argument must be an absolute path in the same share as
    src.

    :param src: The full UNC path to used as the source of the hard link.
    :param dst: The full UNC path to create the hard link at.
    :param follow_symlinks: Whether to link to the src target (True) or src itself (False) if src is a symlink.
    :param kwargs: Common arguments used to build the SMB Session.
    """
    norm_src = ntpath.normpath(src)
    norm_dst = ntpath.normpath(dst)

    if not is_remote_path(norm_src):
        raise ValueError("src must be the absolute path to where the file is hard linked to.")

    src_root = ntpath.splitdrive(norm_src)[0]
    dst_root, dst_name = ntpath.splitdrive(norm_dst)
    if src_root.lower() != dst_root.lower():
        raise ValueError("Cannot hardlink a file to a different root than the src.")

    raw = SMBFileIO(
        norm_src,
        mode="r",
        share_access="rwd",
        desired_access=FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES,
        create_options=0 if follow_symlinks else CreateOptions.FILE_OPEN_REPARSE_POINT,
        **kwargs,
    )
    with SMBFileTransaction(raw) as transaction:
        link_info = FileLinkInformation()
        link_info["replace_if_exists"] = False
        link_info["file_name"] = to_text(dst_name[1:])
        set_info(transaction, link_info)


def listdir(path, search_pattern="*", **kwargs):
    """
    Return a list containing the names of the entries in the directory given by path. The list is in arbitrary order,
    and does not include the special entries '.' and '..' even if they are present in the directory.

    :param path: The path to the directory to list.
    :param search_pattern: THe search string to match against the names of directories or files. This pattern can use
        '*' as a wildcard for multiple chars and '?' as a wildcard for a single char. Does not support regex patterns.
    :param kwargs: Common SMB Session arguments for smbclient.
    :return: A list containing the names of the entries in the directory.
    """
    with SMBDirectoryIO(path, mode="r", share_access="r", **kwargs) as dir_fd:
        try:
            raw_filenames = dir_fd.query_directory(search_pattern, FileInformationClass.FILE_NAMES_INFORMATION)
            return list(
                e["file_name"].get_value().decode("utf-16-le")
                for e in raw_filenames
                if e["file_name"].get_value().decode("utf-16-le") not in [".", ".."]
            )
        except NoSuchFile:
            return []


def lstat(path, **kwargs):
    """
    Perform the equivalent of an lstat() system call on the given path. Similar to stat(), but does not follow
    symbolic links.

    :param path: The path to the file or directory to stat.
    :param kwargs: Common SMB Session arguments for smbclient.
    :return: See stat() for the return values.
    """
    return stat(path, follow_symlinks=False, **kwargs)


def mkdir(path, **kwargs):
    """
    Create a directory named path. If the directory already exists, OSError(errno.EEXIST) is raised.

    :param path: The path to the directory to create.
    :param kwargs: Common SMB Session arguments for smbclient.
    """
    raw = SMBDirectoryIO(path, mode="x", **kwargs)
    with SMBFileTransaction(raw):
        pass


def makedirs(path, exist_ok=False, **kwargs):
    """
    Recursive directory creation function. Like mkdir(), but makes all intermediate-level directories needed to contain
    the leaf directory.

    If exist_ok is False (the default), an OSError is raised if the target directory already exists.

    :param path: The path to the directory to create.
    :param exist_ok: Set to True to not fail if the target directory already exists.
    :param kwargs: Common SMB Session arguments for smbclient.
    """
    create_queue = [ntpath.normpath(path)]
    present_parent = None
    while create_queue:
        mkdir_path = create_queue[-1]
        try:
            mkdir(mkdir_path, **kwargs)
        except OSError as err:
            if err.errno == errno.EEXIST:
                present_parent = mkdir_path
                create_queue.pop(-1)
                if not create_queue and not exist_ok:
                    raise
            elif err.errno == errno.ENOENT:
                # Check if the parent path has already been created to avoid getting in an endless loop.
                parent_path = ntpath.dirname(mkdir_path)
                if present_parent == parent_path:
                    raise
                else:
                    create_queue.append(parent_path)
            else:
                raise
        else:
            create_queue.pop(-1)


def open_file(
    path,
    mode="r",
    buffering=-1,
    encoding=None,
    errors=None,
    newline=None,
    share_access=None,
    desired_access=None,
    file_attributes=None,
    file_type="file",
    **kwargs,
):
    """
    Open a file on an SMB share and return a corresponding file object. If the file cannot be opened, an OSError is
    raised. This function is designed to mimic the builtin open() function but limits some functionality based on
    what is available over SMB.

    It is recommended to call this function with a 'with' statement to ensure the file is closed when not required:

        with smbclient.open_file("\\\\server\\share\\file.txt") as fd:
            fd.read()

    Otherwise the .close() function will also close the handle to the file.

    :param path: The absolute pathname of the file to be opened.
    :param mode: Optional string that specifies the mode in which the file is opened. It defaults to 'r' which means
        for reading in text mode. Other common values are 'w' for writing (truncating the file if it already exists),
        'x' for exclusive creation and 'a' for appending. The available modes are:
            Open Mode
            'r': Open for reading (default).
            'w': Open for writing, truncating the file first.
            'x': Open for exclusive creation, failing if the file already exists.
            'a': Open for writing, appending to the end of the file if it exists.
            '+': Open for updating (reading and writing), can be used in conjunction with any of the above.
            Open Type - can be specified with the OpenMode
            't': Text mode (default).
            'b': Binary mode.
    :param buffering: An optional integer used to set the buffering policy. Pass 0 to switch buffering off (only
        allowed in binary mode), 1 to select line buffering (only usable in text mode), and an integer > 1 to indicate
        the size in bytes of a fixed-size chunk buffer. When no buffering argument is given, the default buffering
        is max size for a single SMB2 packet (65536). This can be higher but is dependent on the credits available from
        the server.
    :param encoding: The name of the encoding used to decode or encode the file. This should only be used in text mode.
        The default encoding is platform dependent (whatever locale.getpreferredencoding() returns), but any text
        encoding types supported by Python can be used.
    :param errors: Specifies how encoding encoding and decoding errors are to be handled. This cannot be used in binary
        mode. A variety of standard error handlers are available, though any error handling name that has been
        registered with codecs.register_error() is also valid. See the open() docs for a list of builtin error handlers
        for your Python version.
    :param newline: Controls how universal newlines mode works. This should only be used in text mode. It can be
        'None', '', '\n', '\r', and '\r\n'.
    :param share_access: String that specifies the type of access that is allowed when a handle to this file is opened
        by another process. The default is 'None' which exclusively locks the file until the file is closed. The
        available access values are:
            'r': Allow other handles to be opened with read access.
            'w': Allow other handles to be opened with write access.
            'd': Allow other handles to be opened with delete access.
        A combination of values can be set to allow multiple access types together.
    :param desired_access: Override the access mask used when opening the file.
    :param file_attributes: Set custom file attributes when opening the file.
    :param file_type: The type of file to access, supports 'file' (default), 'dir', and 'pipe'.
    :param kwargs: Common arguments used to build the SMB Session.
    :return: The file object returned by the open() function, the type depends on the mode that was used to open the
        file.
    """
    file_class = {
        "file": SMBFileIO,
        "dir": SMBDirectoryIO,
        "pipe": SMBPipeIO,
    }[file_type]

    raw_fd = file_class(
        path,
        mode=mode,
        share_access=share_access,
        desired_access=desired_access,
        file_attributes=file_attributes,
        **kwargs,
    )
    try:
        raw_fd.open()

        line_buffering = buffering == 1
        if buffering == 0:
            if "b" not in raw_fd.mode:
                raise ValueError("can't have unbuffered text I/O")

            return raw_fd

        if raw_fd.readable() and raw_fd.writable():
            buff_type = io.BufferedRandom
        elif raw_fd.readable():
            buff_type = io.BufferedReader
        else:
            buff_type = io.BufferedWriter

        if buffering == -1:
            buffering = MAX_PAYLOAD_SIZE

        fd_buffer = buff_type(raw_fd, buffer_size=buffering)

        if "b" in raw_fd.mode:
            return fd_buffer

        return io.TextIOWrapper(fd_buffer, encoding, errors, newline, line_buffering=line_buffering)
    except Exception:
        # If there was a failure in the setup, make sure the file is closed.
        raw_fd.close()
        raise


def readlink(path, **kwargs):
    """
    Return a string representing the path to which the symbolic link points. If the link is relative it will be
    converted to an absolute pathname relative to the link itself. The link target may point to a local path and not
    another UNC path.

    :param path: The path to the symbolic link to read.
    :param kwargs: Common SMB Session arguments for smbclient.
    :return: The link target path.
    """
    norm_path = ntpath.normpath(path)
    reparse_buffer = _get_reparse_point(norm_path, **kwargs)
    reparse_tag = reparse_buffer["reparse_tag"]
    if reparse_tag.get_value() != ReparseTags.IO_REPARSE_TAG_SYMLINK:
        raise ValueError(f"Cannot read link of reparse point with tag {reparse_tag} at '{norm_path}'")

    symlink_buffer = SymbolicLinkReparseDataBuffer()
    symlink_buffer.unpack(reparse_buffer["data_buffer"].get_value())
    return symlink_buffer.resolve_link(norm_path)


def remove(path, **kwargs):
    """
    Remove (delete) the file path. If path is a directory, an IsADirectoryError is raised. Use rmdir() to remove
    directories.

    Trying to remove a file that is in use causes an exception to be raised unless the existing handle was opened with
    the Delete share access. In that case the file will be removed once all handles are closed.

    :param path: The full UNC path to the file to remove.
    :param kwargs: Common SMB Session arguments for smbclient.
    """
    _delete(SMBFileIO, path, **kwargs)


def removedirs(name, **kwargs):
    """
    Remove directories recursively. Works like rmdir() except that, if the leaf directory is successfully removed,
    removedirs() tries to successively remove every parent directory mentioned in path until an error is raised (which
    is ignored, because it generally means that a parent directory is not empty).

    :param name: The directory to start removing recursively from.
    :param kwargs: Common SMB Session arguments for smbclient.
    """
    remove_dir = ntpath.normpath(name)
    while True:
        try:
            rmdir(remove_dir, **kwargs)
        except (SMBResponseException, OSError):
            return
        else:
            remove_dir = ntpath.dirname(remove_dir)


def rename(src, dst, **kwargs):
    """
    Rename the file or directory src to dst. If dst exists, the operation will fail with an OSError subclass in a
    number of cases.

    :param src: The path to the file or directory to rename.
    :param dst: The path to rename the file or directory to.
    :param kwargs: Common SMB Session arguments for smbclient.
    """
    _rename_information(src, dst, replace_if_exists=False, **kwargs)


def renames(old, new, **kwargs):
    """
    Recursive directory or file renaming function. Works like rename(), except creation of any intermediate directories
    needed to make the new pathname good is attempted first. After the rename, directories corresponding to rightmost
    path segments of the old name will be pruned away using removedirs().

    :param old: The path to the file or directory to rename.
    :param new: The path to rename the file or directory to.
    :param kwargs: Common SMB Session arguments for smbclient.
    """
    makedirs(ntpath.dirname(new), exist_ok=True, **kwargs)
    rename(old, new, **kwargs)
    removedirs(ntpath.dirname(old), **kwargs)


def replace(src, dst, **kwargs):
    """
    Rename the file or directory src to dst. If dst exists and is a directory, OSError will be raised. If dst exists
    and is a file, it will be replaced silently if the user has permission. The path at dst must be on the same share
    as the src file or folder.

    :param src: The path to the file or directory to rename.
    :param dst: The path to rename the file or directory to.
    :param kwargs: Common SMB Session arguments for smbclient.
    """
    _rename_information(src, dst, replace_if_exists=True, **kwargs)


def rmdir(path, **kwargs):
    """
    Remove (delete) the directory path. If the directory does not exist or is not empty, an FileNotFoundError or an
    OSError is raised respectively.

    :param path: The path to the directory to remove.
    :param kwargs: Common SMB Session arguments for smbclient.
    """
    _delete(SMBDirectoryIO, path, **kwargs)


def scandir(path, search_pattern="*", **kwargs):
    """
    Return an iterator of DirEntry objects corresponding to the entries in the directory given by path. The entries are
    yielded in arbitrary order, and the special entries '.' and '..' are not included.

    Using scandir() instead of listdir() can significantly increase the performance of code that also needs file type
    or file attribute information, because DirEntry objects expose this information if the SMB server provides it when
    scanning a directory. All DirEntry methods may perform a SMB request, but is_dir(), is_file(), is_symlink() usually
    only require a one system call unless the file or directory is a reparse point which requires 2 calls. See the
    Python documentation for how DirEntry is set up and the methods and attributes that are available.

    :param path: The path to a directory to scan.
    :param search_pattern: THe search string to match against the names of directories or files. This pattern can use
    '*' as a wildcard for multiple chars and '?' as a wildcard for a single char. Does not support regex patterns.
    :param kwargs: Common SMB Session arguments for smbclient.
    :return: An iterator of DirEntry objects in the directory.
    """
    connection_cache = kwargs.get("connection_cache", None)
    with SMBDirectoryIO(path, share_access="rwd", **kwargs) as fd:
        for dir_info in fd.query_directory(search_pattern, FileInformationClass.FILE_ID_FULL_DIRECTORY_INFORMATION):
            filename = dir_info["file_name"].get_value().decode("utf-16-le")
            if filename in [".", ".."]:
                continue

            dir_entry = SMBDirEntry(
                SMBRawIO(rf"{path}\{filename}", **kwargs), dir_info, connection_cache=connection_cache
            )
            yield dir_entry


def stat(path, follow_symlinks=True, **kwargs):
    """
    Get the status of a file. Perform the equivalent of a stat() system call on the given path.

    This function normally follows symlinks; to stat a symlink add the argument follow_symlinks=False.

    :param path: The path to the file or directory to stat.
    :param follow_symlinks: Whether to open the file's reparse point if present during the open. In most scenarios
        this means to stat() the symlink target if the path is a symlink or not.
    :param kwargs: Common SMB Session arguments for smbclient.
    :return: A tuple representing the stat result of the path. This contains the standard tuple entries as
        os.stat_result as well as:
            st_chgtime: The time, seconds since EPOCH, when the file's metadata was last changed.
            st_atime_ns: Same as st_atime but measured in nanoseconds
            st_mtime_ns: Same as st_mtime but measured in nanoseconds
            st_ctime_ns: Same as st_ctime but measured in nanoseconds
            st_chgtime_ns: Same as st_chgtime but measured in nanoseconds
            st_file_attributes: An int representing the Windows FILE_ATTRIBUTES_* constants.
            st_reparse_tag: An int representing the Windows IO_REPARSE_TAG_* constants. This is set to 0 unless
                follow_symlinks=False and the path is a reparse point. See smbprotocol.reparse_point.ReparseTags.
    """
    raw = SMBRawIO(
        path,
        mode="r",
        share_access="rwd",
        desired_access=FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES,
        create_options=0 if follow_symlinks else CreateOptions.FILE_OPEN_REPARSE_POINT,
        **kwargs,
    )
    with SMBFileTransaction(raw) as transaction:
        query_info(transaction, FileBasicInformation)
        # volume_label is variable and can return up to the first 32 chars (32 * 2 for UTF-16) + null padding
        query_info(transaction, FileFsVolumeInformation, output_buffer_length=88)
        query_info(transaction, FileInternalInformation)
        query_info(transaction, FileStandardInformation)
        query_info(transaction, FileAttributeTagInformation)

    basic_info, fs_volume, internal_info, standard_info, attribute_tag = transaction.results

    reparse_tag = attribute_tag["reparse_tag"].get_value()

    file_attributes = basic_info["file_attributes"]
    st_mode = 0  # Permission bits are mostly symbolic, holdover from python stat behaviour
    if file_attributes.has_flag(FileAttributes.FILE_ATTRIBUTE_DIRECTORY):
        st_mode |= py_stat.S_IFDIR | 0o111
    else:
        st_mode |= py_stat.S_IFREG

    if file_attributes.has_flag(FileAttributes.FILE_ATTRIBUTE_READONLY):
        st_mode |= 0o444
    else:
        st_mode |= 0o666

    if reparse_tag == ReparseTags.IO_REPARSE_TAG_SYMLINK:
        # Python behaviour is to remove the S_IFDIR and S_IFREG is the file is a symbolic link. It also only sets
        # S_IFLNK for symbolic links and not other reparse point tags like junction points.
        st_mode ^= py_stat.S_IFMT(st_mode)
        st_mode |= py_stat.S_IFLNK

    # The time fields are 100s of nanoseconds since 1601-01-01 UTC and we need to convert to nanoseconds since EPOCH.
    epoch_ft = DateTimeField.EPOCH_FILETIME
    atime_ns = (basic_info["last_access_time"].get_value() - epoch_ft) * 100
    mtime_ns = (basic_info["last_write_time"].get_value() - epoch_ft) * 100
    ctime_ns = (basic_info["creation_time"].get_value() - epoch_ft) * 100
    chgtime_ns = (basic_info["change_time"].get_value() - epoch_ft) * 100

    return SMBStatResult(
        st_mode=st_mode,
        st_ino=internal_info["index_number"].get_value(),
        st_dev=fs_volume["volume_serial_number"].get_value(),
        st_nlink=standard_info["number_of_links"].get_value(),
        st_uid=0,
        st_gid=0,
        st_size=standard_info["end_of_file"].get_value(),
        st_atime=atime_ns / 1000000000,
        st_mtime=mtime_ns / 1000000000,
        st_ctime=ctime_ns / 1000000000,
        st_chgtime=chgtime_ns / 1000000000,
        st_atime_ns=atime_ns,
        st_mtime_ns=mtime_ns,
        st_ctime_ns=ctime_ns,
        st_chgtime_ns=chgtime_ns,
        st_file_attributes=file_attributes.get_value(),
        st_reparse_tag=reparse_tag,
    )


def stat_volume(path, **kwargs):
    """
    Get stat of a volume. Currently the volume size information is returned.

    :param path: The path to the file or directory on a file system volume to stat.
    :param kwargs: Common SMB Session arguments for smbclient.
    :return: A tuple representing the full size result:
                total_size: Total size of the file system
                caller_available_size: Available size for the logged user of the file system
                actual_available_size: Available size of the file system
    """
    raw = SMBRawIO(
        path, mode="r", share_access="rwd", desired_access=FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES, **kwargs
    )
    with SMBFileTransaction(raw) as transaction:
        query_info(transaction, FileFsFullSizeInformation)
    full_size = transaction.results[0]
    unit_in_bytes = full_size["sectors_per_unit"].get_value() * full_size["bytes_per_sector"].get_value()
    return SMBStatVolumeResult(
        total_size=full_size["total_allocation_units"].get_value() * unit_in_bytes,
        caller_available_size=full_size["caller_available_units"].get_value() * unit_in_bytes,
        actual_available_size=full_size["actual_available_units"].get_value() * unit_in_bytes,
    )


def symlink(src, dst, target_is_directory=False, **kwargs):
    """
    Create a symbolic link pointing to src named dst. The src argument must be an absolute path in the same share as
    src.

    If the target src exists, then the symlink type is created based on the target type. If the target does not exist
    then the target_is_directory var can be used to control the type of symlink created.

    Note the server must support creating a reparse point using the FSCTL_SET_REPARSE_POINT code. This is typically
    only Windows servers.

    :param src: The target of the symlink.
    :param dst: The path where the symlink is to be created.
    :param target_is_directory: If src does not exist, controls whether a file or directory symlink is created.
    :param kwargs: Common SMB Session arguments for smbclient.
    """
    norm_dst = ntpath.normpath(dst)
    if not is_remote_path(norm_dst):
        raise ValueError("The link dst must be an absolute UNC path for where the link is to be created")

    norm_src = ntpath.normpath(src)
    print_name = norm_src

    if not is_remote_path(norm_src):
        flags = SymbolicLinkFlags.SYMLINK_FLAG_RELATIVE
        substitute_name = norm_src
        dst_dir = ntpath.dirname(norm_dst)
        norm_src = ntpath.abspath(ntpath.join(dst_dir, norm_src))
    else:
        flags = SymbolicLinkFlags.SYMLINK_FLAG_ABSOLUTE
        substitute_name = "\\??\\UNC\\" + norm_src[2:]

    src_drive = ntpath.splitdrive(norm_src)[0]
    dst_drive = ntpath.splitdrive(norm_dst)[0]
    if src_drive.lower() != dst_drive.lower():
        raise ValueError(f"Resolved link src root '{src_drive}' must be the same as the dst root '{dst_drive}'")

    try:
        src_stat = stat(norm_src, **kwargs)
    except OSError as err:
        if err.errno != errno.ENOENT:
            raise
    else:
        # If the src actually exists, override the target_is_directory with whatever type src actually is.
        target_is_directory = py_stat.S_ISDIR(src_stat.st_mode)

    symlink_buffer = SymbolicLinkReparseDataBuffer()
    symlink_buffer["flags"] = flags
    symlink_buffer.set_name(substitute_name, print_name)

    reparse_buffer = ReparseDataBuffer()
    reparse_buffer["reparse_tag"] = ReparseTags.IO_REPARSE_TAG_SYMLINK
    reparse_buffer["data_buffer"] = symlink_buffer

    co = CreateOptions.FILE_OPEN_REPARSE_POINT
    if target_is_directory:
        co |= CreateOptions.FILE_DIRECTORY_FILE
    else:
        co |= CreateOptions.FILE_NON_DIRECTORY_FILE
    raw = SMBRawIO(
        norm_dst, mode="x", desired_access=FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES, create_options=co, **kwargs
    )

    with SMBFileTransaction(raw) as transaction:
        ioctl_request(
            transaction,
            CtlCode.FSCTL_SET_REPARSE_POINT,
            flags=IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL,
            input_buffer=reparse_buffer,
        )


def truncate(path, length, **kwargs):
    """
    Truncate the file corresponding to path, so that it is at most length bytes in size.

    :param path: The path for the file to truncate.
    :param length: The length in bytes to truncate the file to.
    :param kwargs: Common SMB Session arguments for smbclient.
    """
    with open_file(path, mode="ab", **kwargs) as fd:
        fd.truncate(length)


def unlink(path, **kwargs):
    """
    Remove (delete) the file path. This function is semantically identical to remove(); the unlink name is its
    traditional Unix name. Please see the documentation for remove() for further information.

    :param path: The full UNC path to the file to remove.
    :param kwargs: Common SMB Session arguments for smbclient.
    """
    remove(path, **kwargs)


def utime(path, times=None, ns=None, follow_symlinks=True, **kwargs):
    """
    Set the access and modified times of the file specified by path.

    utime() takes two optional parameters, times and ns. These specify the times set on path and are used as follows:

        * If ns is specified, it must be a 2-tuple of the form (atime_ns, mtime_ns) where each member is an int
          expressing nanoseconds. Note SMB has a precision of 100's of nanoseconds.
        * If times is not None, it must be a 2-tuple of the form (atime, mtime) where each member is an int or float
          expressing seconds.
        * If times and ns is None, this is equivalent to specifying ns=(atime_ns, mtime_ns) where both times are the
          current time.

    It is an error to specify tuples for both times and ns.

    :param path: The full UNC path to the file or directory to update the time.
    :param times: A 2-tuple of the form (atime, mtime)
    :param ns: A 2-tuple of the form (atime_ns, mtime_ns)
    :param follow_symlinks: Whether to follow symlinks when opening path.
    :param kwargs: Common SMB Session arguments for smbclient.
    """
    if times and ns:
        raise ValueError("Both times and ns have been set for utime.")
    elif times or ns:
        if times:
            time_tuple = times

            # seconds in 100s of nanoseonds
            op = operator.mul
            op_amt = 10000000
        else:
            time_tuple = ns

            # nanoseconds in 100s of nanoseconds
            op = operator.floordiv
            op_amt = 100

        if len(time_tuple) != 2:
            raise ValueError("The time tuple should be a 2-tuple of the form (atime, mtime).")

        # EPOCH_FILETIME is EPOCH represented as MS FILETIME (100s of nanoseconds since 1601-01-01
        atime, mtime = tuple([op(t, op_amt) + DateTimeField.EPOCH_FILETIME for t in time_tuple])
    else:
        # time_ns() was only added in Python 3.7
        time_ns = getattr(time, "time_ns", None)
        if not time_ns:

            def time_ns():  # pragma: no cover
                return int(time.time()) * 1000000000

        atime = mtime = (time_ns() // 100) + DateTimeField.EPOCH_FILETIME

    _set_basic_information(
        path, last_access_time=atime, last_write_time=mtime, follow_symlinks=follow_symlinks, **kwargs
    )


def walk(top, topdown=True, onerror=None, follow_symlinks=False, **kwargs):
    """
    Generate the file names in a directory tree by walking the tree either top-down or bottom-up. For each directory
    in the tree rooted at directory top (including top itself), it yields a 3-tuple (dirpath, dirnames, filenames).

    dirpath is a string, the path to the directory, dirnames is a list of names of the subdirectories in dirpath
    (excluding '.' and '..''). filenames is a list of names of the non-directory files in dirpath. Note that the names
    in the lists contain no path components. To get a full path (which beings with top) to a file or directory in
    dirpath, do ntpath.join(dirpath, name).

    If optional argument topdown is True or not specified, the triple for a directory is generated before the triples
    for any of its subdirectories (directories are generated top-down). If topdown is False, the triple for a directory
    is generated after the triples for all of its subdirectories (directories are generated bottom-up). No matter the
    value of topdown, the list of subdirectories is retrieved before the tuples for the directory and its
    subdirectories are generated.

    When topdown is True, the caller can modify the dirnames list in-place (perhaps using del or slice assignment) and
    walk() will only recurse into the subdirectories whose names remain in dirnames; this can be used to prune the
    search, impose a specific order of visting, or even to inform walk() about directories the caller creates or
    renames before it resumes walk() again. Modifying dirnames when topdown is False has no effect on the behaviour of
    the walk, because in bottom-up mode the directories in dirnames are generated before dirpath itself is generated.

    By default, errors from scandir() call are ignored. If optional argument onerror is specified, it should be a
    function; It will be called with one argument, an OSError instance. It can report the error to continue with the
    walk, or raise the exception to abort the walk. Note that the filename is available as the filename attribute of
    the exception object.

    By default walk() will not walk down into symbolic links that resolve to directories, Set follow_symlinks to True
    to visit directories pointed to by symlinks. Be aware that setting follow_symlinks to True can lead to infinite
    recursion if a link points to a parent directory of itself. walk() does not keep track of the directories it
    visited already.

    :param top: The full UNC path to the directory to walk.
    :param topdown: Controls whether to run in top-down (True) or bottom-up mode (False)
    :param onerror: A function that takes in 1 argument of OSError that is called when an error is encountered.
    :param follow_symlinks: Whether to follow symlinks that point to directories that are encountered.
    :param kwargs: Common SMB Session arguments for smbclient.
    """
    try:
        scandir_gen = scandir(top, **kwargs)
    except OSError as err:
        if onerror is not None:
            onerror(err)
        return

    dirs = []
    files = []
    bottom_up_dirs = []
    while True:
        try:
            try:
                entry = next(scandir_gen)
            except StopIteration:
                break
        except OSError as err:
            if onerror is not None:
                onerror(err)
            return

        if not entry.is_dir():
            files.append(entry.name)
            continue

        dirs.append(entry.name)
        if not topdown and (follow_symlinks or not entry.is_symlink()):
            # Add the directory to the bottom up list which is recursively walked below, we exclude symlink dirs if
            # follow_symlinks is False.
            bottom_up_dirs.append(entry.path)

    walk_kwargs = {"topdown": topdown, "onerror": onerror, "follow_symlinks": follow_symlinks}
    walk_kwargs.update(kwargs)

    if topdown:
        yield top, dirs, files

        for dirname in dirs:
            dirpath = ntpath.join(top, dirname)

            # In case the dir was changed in the yield we need to re-check if the dir is now a symlink and skip it if
            # it is not and follow_symlinks=False.
            if not follow_symlinks and py_stat.S_ISLNK(lstat(dirpath, **kwargs).st_mode):
                continue

            yield from walk(dirpath, **walk_kwargs)
    else:
        # On a bottom up approach we yield the sub directories before the top path.
        for dirpath in bottom_up_dirs:
            yield from walk(dirpath, **walk_kwargs)

        yield top, dirs, files


def getxattr(path, attribute, follow_symlinks=True, **kwargs):
    """
    Return the value of the extended filesystem attribute attribute for path

    :param path: The full UNC path to the file to get the extended attribute for.
    :param attribute: The extended attribute to lookup.
    :param follow_symlinks: Whether to follow the symlink at path if encountered
    :param kwargs: Common SMB Session arguments for smbclient.
    :return: The value fo the attribute.
    """
    # I could use FileGetEaInformation() to select the attribute to return but that behaviour varies across different
    # SMB server, Samba returns all regardless of the ea_name set in the list and Windows returns a blank entry even
    # if the xattr is not set. Instead we just get them all and filter it from there.
    extended_attributes = _get_extended_attributes(path, follow_symlinks, **kwargs)

    # Convert the input attribute name to bytes and default to using utf-8. If a different encoding is desired then the
    # user should pass in a byte string themselves.
    b_attribute = to_bytes(attribute)
    b_xattr = next((b_val for b_name, b_val in extended_attributes if b_name == b_attribute), None)
    if b_xattr is None:
        raise SMBOSError(NtStatus.STATUS_END_OF_FILE, path)

    return b_xattr


def listxattr(path, follow_symlinks=True, **kwargs):
    """
    Return a list of attributes on path.

    :param path: The full UNC path to the file to get the list of extended attributes for.
    :param follow_symlinks: Whether to follow the symlink at path if encountered.
    :param kwargs: Common SMB Session arguments for smbclient.
    :return: List of attributes on the file with each attribute entry being a byte string.
    """
    return [b_name for b_name, _ in _get_extended_attributes(path, follow_symlinks, **kwargs)]


def removexattr(path, attribute, follow_symlinks=True, **kwargs):
    """
    Removes the extended filesystem attribute attribute from path.

    :param path: The full UNC path to the file to remove the extended attribute from.
    :param attribute: The attribute to remove, if not a byte string the text is encoded using utf-8.
    :param follow_symlinks: Whether to follow the symlink at path if encountered.
    :param kwargs: Common SMB Session arguments for smbclient.
    """
    # Setting a null byte value will remove the extended attribute, we also run with XATTR_REPLACE as that will raise
    # an exception if the attribute was not already set.
    setxattr(path, attribute, b"", flags=XATTR_REPLACE, follow_symlinks=follow_symlinks, **kwargs)


def setxattr(path, attribute, value, flags=0, follow_symlinks=True, **kwargs):
    """
    Set the extended filesystem attribute on path to value. flags may be XATTR_REPLACE or XATTR_CREATE. if
    XATTR_REPLACE is given and the attribute does not exists, EEXISTS will be raised. If XATTR_CREATE is given and the
    attribute already exists, the attribute will not be created and ENODATA will be raised.

    :param path: The full UNC path to the file to set the extended attribute on.
    :param attribute: The attribute to set, if not a byte string the text is encoded using utf-8.
    :param value: The value to set on the attribute, if not a byte string the text is encoded using utf-8.
    :param flags: Set to XATTR_REPLACE to replace an attribute or XATTR_CREATE to create an attribute or 0 for both.
    :param follow_symlinks: Whether to follow the symlink at path if encountered.
    :param kwargs: Common SMB Session arguments for smbclient.
    """
    # Make sure we are dealing with a byte string, defaults to using utf-8 to encode a text string, a user can use
    # another encoding by passing in a byte string directly.
    b_attribute = to_bytes(attribute)
    b_value = to_bytes(value)

    # If flags are set we need to verify whether the attribute already exists or not. SMB doesn't have a native
    # create/replace mechanism so we need to implement that ourselves.
    if flags:
        xattrs = _get_extended_attributes(path, follow_symlinks=follow_symlinks, **kwargs)
        present = next((True for b_name, _ in xattrs if b_name == b_attribute), False)

        if flags == XATTR_CREATE and present:
            raise SMBOSError(NtStatus.STATUS_OBJECT_NAME_COLLISION, path)
        elif flags == XATTR_REPLACE and not present:
            raise SMBOSError(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND, path)

    raw = SMBRawIO(
        path,
        mode="r",
        share_access="r",
        desired_access=FilePipePrinterAccessMask.FILE_WRITE_EA,
        create_options=0 if follow_symlinks else CreateOptions.FILE_OPEN_REPARSE_POINT,
        **kwargs,
    )
    with SMBFileTransaction(raw) as transaction:
        ea_info = FileFullEaInformation()
        ea_info["ea_name"] = b_attribute
        ea_info["ea_value"] = b_value
        set_info(transaction, ea_info)


def _delete(raw_type, path, **kwargs):
    # Ensures we delete the symlink (if present) and don't follow it down.
    co = CreateOptions.FILE_OPEN_REPARSE_POINT
    co |= {
        "dir": CreateOptions.FILE_DIRECTORY_FILE,
        "file": CreateOptions.FILE_NON_DIRECTORY_FILE,
    }.get(raw_type.FILE_TYPE, 0)

    # Setting a shared_access of rwd means we can still delete a file that has an existing handle open, the file will
    # be deleted when that handle is closed. This replicates the os.remove() behaviour when running on Windows locally.
    raw = raw_type(
        path,
        mode="r",
        share_access="rwd",
        desired_access=FilePipePrinterAccessMask.DELETE | FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES,
        create_options=co,
        **kwargs,
    )

    with SMBFileTransaction(raw) as transaction:
        # Make sure the file does not have the FILE_ATTRIBUTE_READONLY flag as Windows will fail to delete these files.
        basic_info = FileBasicInformation()
        basic_info["creation_time"] = 0
        basic_info["last_access_time"] = 0
        basic_info["last_write_time"] = 0
        basic_info["change_time"] = 0
        basic_info["file_attributes"] = (
            FileAttributes.FILE_ATTRIBUTE_NORMAL
            if raw_type.FILE_TYPE == "file"
            else FileAttributes.FILE_ATTRIBUTE_DIRECTORY
        )
        set_info(transaction, basic_info)

        info_buffer = FileDispositionInformation()
        info_buffer["delete_pending"] = True
        set_info(transaction, info_buffer)


def _get_extended_attributes(path, follow_symlinks=True, **kwargs):
    raw = SMBRawIO(
        path,
        mode="r",
        share_access="r",
        desired_access=FilePipePrinterAccessMask.FILE_READ_EA,
        create_options=0 if follow_symlinks else CreateOptions.FILE_OPEN_REPARSE_POINT,
        **kwargs,
    )

    try:
        with SMBFileTransaction(raw) as transaction:
            # We don't know the EA size and FileEaInformation is too unreliable so just set the max size to the SMB2
            # payload length. It seems to fail if it goes any higher than this.
            query_info(
                transaction,
                FileFullEaInformation,
                flags=QueryInfoFlags.SL_RESTART_SCAN,
                output_buffer_length=MAX_PAYLOAD_SIZE,
            )
    except SMBOSError as err:
        if err.ntstatus == NtStatus.STATUS_NO_EAS_ON_FILE:
            return []
        raise

    return [(e["ea_name"].get_value(), e["ea_value"].get_value()) for e in transaction.results[0]]


def _get_reparse_point(path, **kwargs):
    raw = SMBRawIO(
        path,
        mode="r",
        desired_access=FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES,
        create_options=CreateOptions.FILE_OPEN_REPARSE_POINT,
        **kwargs,
    )

    with SMBFileTransaction(raw) as transaction:
        ioctl_request(
            transaction, CtlCode.FSCTL_GET_REPARSE_POINT, output_size=16384, flags=IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL
        )

    reparse_buffer = ReparseDataBuffer()
    reparse_buffer.unpack(transaction.results[0])
    return reparse_buffer


def _rename_information(src, dst, replace_if_exists=False, **kwargs):
    verb = "replace" if replace_if_exists else "rename"
    if not is_remote_path(ntpath.normpath(dst)):
        raise ValueError(f"dst must be an absolute path to where the file or directory should be {verb}d.")

    raw_args = dict(kwargs)
    raw_args.update(
        {
            "mode": "r",
            "share_access": "rwd",
            "create_options": CreateOptions.FILE_OPEN_REPARSE_POINT,
        }
    )

    # We open/close the dest (ignoring if the file does not exist) so we can resolve the DFS path and determine the
    # filename src needs to be renamed to.
    dst_raw = SMBRawIO(dst, desired_access=FilePipePrinterAccessMask.FILE_EXECUTE, **raw_args)
    try:
        SMBFileTransaction(dst_raw).commit()
    except SMBOSError as err:
        if err.errno != errno.ENOENT:
            raise

    # We need to open source first so we can get the resolved tree to compare the volumes
    with SMBRawIO(src, desired_access=FilePipePrinterAccessMask.DELETE, **raw_args) as src_raw:
        # We compare the server part using the GUID in case a different alias was specified for the server. The GUID
        # should uniquely identify the server for our cases here.
        src_guid = src_raw.fd.connection.server_guid
        src_share = ntpath.normpath(src_raw.fd.tree_connect.share_name).split("\\")[-1]

        dst_guid = dst_raw.fd.connection.server_guid
        dst_share = ntpath.normpath(dst_raw.fd.tree_connect.share_name).split("\\")[-1]

        if src_guid != dst_guid or src_share.lower() != dst_share.lower():
            raise ValueError(f"Cannot {verb} a file to a different root than the src.")

        dst_tree = dst_raw.fd.tree_connect
        dst_path = dst_raw.fd.file_name
        if dst_tree.is_dfs_share and dst_path.startswith(dst_tree.share_name[2:]):
            # Special handling when dst is on a DFS share, the renamed file
            # should not include the DFS share itself that is present on the
            # Open.file_name. Strip out that prefix if present.
            dst_path = dst_path[len(dst_tree.share_name) - 1 :]

        with SMBFileTransaction(src_raw) as transaction:
            file_rename = FileRenameInformation()
            file_rename["replace_if_exists"] = replace_if_exists
            file_rename["file_name"] = to_text(dst_path)
            set_info(transaction, file_rename)


def _set_basic_information(
    path,
    creation_time=0,
    last_access_time=0,
    last_write_time=0,
    change_time=0,
    file_attributes=0,
    follow_symlinks=True,
    **kwargs,
):
    raw = SMBRawIO(
        path,
        mode="r",
        share_access="rwd",
        desired_access=FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES,
        create_options=0 if follow_symlinks else CreateOptions.FILE_OPEN_REPARSE_POINT,
        **kwargs,
    )

    with SMBFileTransaction(raw) as transaction:
        basic_info = FileBasicInformation()
        basic_info["creation_time"] = creation_time
        basic_info["last_access_time"] = last_access_time
        basic_info["last_write_time"] = last_write_time
        basic_info["change_time"] = change_time
        basic_info["file_attributes"] = file_attributes
        set_info(transaction, basic_info)


class SMBDirEntry:
    def __init__(self, raw, dir_info, connection_cache=None):
        self._smb_raw = raw
        self._dir_info = dir_info
        self._stat = None
        self._lstat = None
        self._connection_cache = connection_cache

    def __str__(self):
        return f"<{self.__class__.__name__}: {self.name!r}>"

    @property
    def name(self):
        """The entry's base filename, relative to the scandir() path argument."""
        return self._smb_raw.name.split("\\")[-1]

    @property
    def path(self):
        """The entry's full path name."""
        return self._smb_raw.name

    def inode(self):
        """
        Return the inode number of the entry.

        The result is cached on the 'smcblient.DirEntry' object. Use
        'smbclient.stat(entry.path, follow_symlinks=False).st_ino' to fetch up-to-date information.
        """
        return self._dir_info["file_id"].get_value()

    def is_dir(self, follow_symlinks=True):
        """
        Return 'True' if this entry is a directory or a symbolic link pointing to a directory; return 'False' if the
        entry is or points to any other kind of file, or if it doesn't exist anymore.

        If follow_symlinks is 'False', return 'True' only if this entry is a directory (without following symlinks);
        return 'False' if the entry is any other kind of file.

        The result is cached on the 'smcblient.DirEntry' object, with a separate cache for follow_symlinks 'True' and
        'False'. Call 'smbclient.path.isdir(entry.path)' to fetch up-to-date information.

        On the first, uncached call, no SMB call is required unless the path is a reparse point.

        :param follow_symlinks: Whether to check if the entry's target is a directory (True) or the entry itself
            (False) if the entry is a symlink.
        :return: bool that states whether the entry is a directory or not.
        """
        is_lnk = self.is_symlink()
        if follow_symlinks and is_lnk:
            return self._link_target_type_check(py_stat.S_ISDIR)
        else:
            # Python behaviour is to consider a symlink not a directory even if it has the DIRECTORY attribute.
            return not is_lnk and self._dir_info["file_attributes"].has_flag(FileAttributes.FILE_ATTRIBUTE_DIRECTORY)

    def is_file(self, follow_symlinks=True):
        """
        Return 'True' if this entry is a file or a symbolic link pointing to a file; return 'False' if the entry is or
        points to a directory or other non-file entry.

        If follow_symlinks is 'False', return 'True' only if this entry is a file (without following symlinks); return
        'False' if entry is a directory or other non-file entry.

        The result is cached on the 'smcblient.DirEntry' object, with a separate cache for follow_symlinks 'True' and
        'False'. Call 'smbclient.path.isfile(entry.path)' to fetch up-to-date information.

        On the first, uncached call, no SMB call is required unless the path is a reparse point.

        :param follow_symlinks: Whether to check if the entry's target is a file (True) or the entry itself (False) if
            the entry is a symlink.
        :return: bool that states whether the entry is a file or not.
        """
        is_lnk = self.is_symlink()
        if follow_symlinks and is_lnk:
            return self._link_target_type_check(py_stat.S_ISREG)
        else:
            # Python behaviour is to consider a symlink not a file even if it does not have the DIRECTORY attribute.
            return not is_lnk and not self._dir_info["file_attributes"].has_flag(
                FileAttributes.FILE_ATTRIBUTE_DIRECTORY
            )

    def is_symlink(self):
        """
        Return 'True' if this entry is a symbolic link (even if broken); return 'False' if the entry points to a
        directory or any kind of file.

        The result is cached on the 'smcblient.DirEntry' object. Call 'smcblient.path.islink()' to fetch up-to-date
        information.

        On the first, uncached call, only files or directories that are reparse points requires another SMB call. The
        result is cached for subsequent calls.

        :return: Whether the path is a symbolic link.
        """
        if self._dir_info["file_attributes"].has_flag(FileAttributes.FILE_ATTRIBUTE_REPARSE_POINT):
            # While a symlink is a reparse point, all reparse points aren't symlinks. We need to get the reparse tag
            # to use as our check. Unlike WIN32_FILE_DATA scanned locally, we don't get the reparse tag in the original
            # query result. We need to do a separate stat call to get this information.
            lstat = self.stat(follow_symlinks=False)
            return lstat.st_reparse_tag == ReparseTags.IO_REPARSE_TAG_SYMLINK
        else:
            return False

    def stat(self, follow_symlinks=True):
        """
        Return a SMBStatResult object for this entry. This method follows symbolic links by default; to stat a symbolic
        link without following add the 'follow_symlinks=False' argument.

        This method always requires an extra SMB call or 2 if the path is a reparse point. The result is cached on the
        'smcblient.DirEntry' object, with a separate cache for follow_symlinks 'True' and 'False'. Call
        'smbclient.stat(entry.path)' to fetch up-to-date information.

        :param follow_symlinks: Whether to stat() the symlink target (True) or the symlink itself (False) if path is a
            symlink or not.
        :return: SMBStatResult object, see smbclient.stat() for more information.
        """
        if follow_symlinks:
            if not self._stat:
                if self.is_symlink():
                    self._stat = stat(self.path, connection_cache=self._connection_cache)
                else:
                    # Because it's not a symlink lstat will be the same as stat so set both.
                    if self._lstat is None:
                        self._lstat = lstat(self._smb_raw.name, connection_cache=self._connection_cache)
                    self._stat = self._lstat
            return self._stat
        else:
            if not self._lstat:
                self._lstat = lstat(self.path, connection_cache=self._connection_cache)
            return self._lstat

    @classmethod
    def from_path(cls, path, follow_symlinks=True, **kwargs):
        file_stat = stat(path, follow_symlinks=follow_symlinks, **kwargs)

        # A DirEntry only needs these 2 properties to be set
        dir_info = FileIdFullDirectoryInformation()
        dir_info["file_attributes"] = file_stat.st_file_attributes
        dir_info["file_id"] = file_stat.st_ino

        dir_entry = cls(SMBRawIO(path, **kwargs), dir_info, connection_cache=kwargs.get("connection_cache", None))
        dir_entry._stat = file_stat
        return dir_entry

    def _link_target_type_check(self, check):
        try:
            return check(self.stat(follow_symlinks=True).st_mode)
        except OSError as err:
            if err.errno == errno.ENOENT:  # Missing target, broken symlink just return False
                return False
            raise
