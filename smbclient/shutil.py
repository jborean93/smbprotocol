from __future__ import unicode_literals
import errno

from ntpath import join, basename, normcase, abspath, normpath, splitdrive

import sys
import stat as py_stat
from os import error as os_error

from smbclient._io import ioctl_request, SMBFileTransaction, SMBRawIO
from smbclient._os import remove, rmdir, listdir, stat, utime, open_file, makedirs, readlink, symlink, scandir
from smbclient.path import islink, isdir
from smbprotocol.exceptions import SMBOSError
from smbprotocol.ioctl import SMB2SrvCopyChunk, IOCTLFlags, SMB2SrvCopyChunkResponse, CtlCode, SMB2SrvCopyChunkCopy, \
    SMB2SrvRequestResumeKey
from smbprotocol.open import FilePipePrinterAccessMask, CreateOptions

CHUNK_SIZE = 1 * 1024 * 1024  # maximum chunksize allowed by smb


class Error(EnvironmentError):
    pass


class SpecialFileError(EnvironmentError):
    """Raised when trying to do a kind of operation (e.g. copying) which is
    not supported on a special file (e.g. a named pipe)"""


def rmtree(path, ignore_errors=False, onerror=None, **kwargs):
    """Recursively delete a directory tree.

    If ignore_errors is set, errors are ignored; otherwise, if onerror
    is set, it is called to handle the error with arguments (func,
    path, exc_info) where func is smbclient.listdir, smbclient.remove,
    or smbclient.rmdir;
    path is the argument to that function that caused it to fail; and
    exc_info is a tuple returned by sys.exc_info().  If ignore_errors
    is false and onerror is None, an exception is raised.

    :param path: The path to remove.
    :param ignore_errors: The ignore errors flag.
    :param onerror: The callback executed on errors
    :param kwargs: Common arguments used to build the SMB Session.
    :return: True if path is a dir or points to a dir.
    """
    if ignore_errors:
        def onerror(*args):
            pass
    elif onerror is None:
        def onerror(*args):
            raise

    try:
        dir_entries = scandir(path, **kwargs)
        for dir_entry in dir_entries:
            if dir_entry.is_dir():
                if dir_entry.is_symlink():
                    rmdir(dir_entry.path, **kwargs)
                else:
                    rmtree(dir_entry.path, ignore_errors, onerror, **kwargs)
            else:
                try:
                    remove(dir_entry.path, **kwargs)
                except os_error:
                    onerror(remove, dir_entry.path, sys.exc_info())
    except os_error:
        onerror(scandir, path, sys.exc_info())

    try:
        rmdir(path, **kwargs)
    except os_error:
        onerror(rmdir, path, sys.exc_info())


def copy2(src, dst, server_side_copy=False, **kwargs):
    """Copy data and metadata. Return the file's destination.

    Metadata is copied with copystat(). Please see the copystat function
    for more information.

    The destination may be a directory.

    """
    if isdir(dst, **kwargs):
        dst = join(dst, basename(src))
    if server_side_copy:
        copyfile_server_side(src, dst, **kwargs)
    else:
        copyfile(src, dst, **kwargs)
    copystat(src, dst, **kwargs)


def copystat(src, dst, **kwargs):
    """Copy file metadata

    Copy the permission bits, last access time, last modification time, and
    flags from `src` to `dst`. The file contents, owner, and group are
    unaffected. `src` and `dst` are path names given as strings.
    """
    st = stat(src, **kwargs)
    utime(dst, ns=(st.st_atime_ns, st.st_mtime_ns), **kwargs)

    # TODO: in principle, we can copy the readonly flag via chmod
    # mode = py_stat.S_IMODE(st.st_mode)
    # if hasattr(os, 'chmod'):
    #     os.chmod(dst, mode)


def copyfile(src, dst, **kwargs):
    """Copy data from src to dst"""
    if _samefile(src, dst):
        raise ValueError("`%s` and `%s` are the same file" % (src, dst))

    for fn in [src, dst]:
        try:
            st = stat(fn, **kwargs)
        except OSError:
            # File most likely does not exist
            pass
        else:
            # XXX What about other special files? (sockets, devices...)
            if py_stat.S_ISFIFO(st.st_mode):
                raise SpecialFileError("`%s` is a named pipe" % fn)

    with open_file(src, 'rb', **kwargs) as fsrc:
        with open_file(dst, 'wb', **kwargs) as fdst:
            copyfileobj(fsrc, fdst)


def copytree(src, dst, symlinks=False, ignore=None, server_side_copy=False, **kwargs):
    """Recursively copy a directory tree using copy2().

    The destination directory must not already exist.
    If exception(s) occur, an Error is raised with a list of reasons.

    If the optional symlinks flag is true, symbolic links in the
    source tree result in symbolic links in the destination tree; if
    it is false, the contents of the files pointed to by symbolic
    links are copied.

    The optional ignore argument is a callable. If given, it
    is called with the `src` parameter, which is the directory
    being visited by copytree(), and `names` which is the list of
    `src` contents, as returned by os.listdir():

        callable(src, names) -> ignored_names

    Since copytree() is called recursively, the callable will be
    called once for each directory that is copied. It returns a
    list of names relative to the `src` directory that should
    not be copied.

    XXX Consider this example code rather than the ultimate tool.

    """
    names = listdir(src, **kwargs)
    if ignore is not None:
        ignored_names = ignore(src, names)
    else:
        ignored_names = set()

    makedirs(dst, **kwargs)
    errors = []
    for name in names:
        if name in ignored_names:
            continue
        srcname = join(src, name)
        dstname = join(dst, name)
        try:
            if symlinks and islink(srcname, **kwargs):
                linkto = readlink(srcname, **kwargs)
                symlink(linkto, dstname, **kwargs)
            elif isdir(srcname, **kwargs):
                copytree(srcname, dstname, symlinks, ignore, **kwargs)
            else:
                # Will raise a SpecialFileError for unsupported file types
                copy2(srcname, dstname, server_side_copy=server_side_copy, **kwargs)
        # catch the Error from the recursive copytree so that we can
        # continue with other files
        except Error as err:
            errors.extend(err.args[0])
        except EnvironmentError as why:
            errors.append((srcname, dstname, str(why)))
    try:
        copystat(src, dst)
    except OSError as why:
        if WindowsError is not None and isinstance(why, WindowsError):
            # Copying file access times may fail on Windows
            pass
        else:
            errors.append((src, dst, str(why)))
    if errors:
        raise Error(errors)


def copyfile_server_side(src, dst, **kwargs):
    """
    Server side copy of a file

    :param src: The source file.
    :param dst: The target file.
    :param kwargs: Common SMB Session arguments for smbclient.
    """

    norm_dst = normpath(dst)
    norm_src = normpath(src)

    src_drive = splitdrive(norm_src)[0]
    dst_drive = splitdrive(norm_dst)[0]
    if src_drive.lower() != dst_drive.lower():
        raise ValueError(
            "Server side copy can only occur on the same drive, '%s' must be the same as the dst root '%s'" % (
                src_drive, dst_drive))

    try:
        stat(norm_dst, **kwargs)
    except SMBOSError as err:
        if err.errno != errno.ENOENT:
            raise
    else:
        raise ValueError("Target %s already exists" % norm_dst)

    with SMBRawIO(norm_src, mode='r', desired_access=FilePipePrinterAccessMask.GENERIC_READ,
                  create_options=(CreateOptions.FILE_NON_DIRECTORY_FILE), share_access='r',
                  **kwargs) as raw_src:

        with SMBFileTransaction(raw_src) as transaction_src:
            ioctl_request(transaction_src, CtlCode.FSCTL_SRV_REQUEST_RESUME_KEY,
                          flags=IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL,
                          output_size=32)

        val_resp = SMB2SrvRequestResumeKey()
        val_resp.unpack(transaction_src.results[0])

        chunks = _get_srv_copy_chunks(transaction_src)

        with SMBRawIO(norm_dst, mode='x', desired_access=FilePipePrinterAccessMask.GENERIC_WRITE,
                      share_access='r',
                      create_options=(CreateOptions.FILE_NON_DIRECTORY_FILE), **kwargs) as raw_dst:

            with SMBFileTransaction(raw_dst) as transaction_dst:
                for batch in _batches(chunks, 16):
                    copychunkcopy_struct = SMB2SrvCopyChunkCopy()
                    copychunkcopy_struct['source_key'] = val_resp['resume_key'].get_value()
                    copychunkcopy_struct['chunks'] = batch

                    ioctl_request(transaction_dst, CtlCode.FSCTL_SRV_COPYCHUNK_WRITE,
                                  flags=IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL,
                                  output_size=32, buffer=copychunkcopy_struct)

            for result in transaction_dst.results:
                copychunk_response = SMB2SrvCopyChunkResponse()
                copychunk_response.unpack(result)
                if copychunk_response['chunks_written'].get_value() < 1:
                    raise SMBOSError('Could not copy chunks in server side copy', filename=norm_dst)


def _get_srv_copy_chunks(transaction):
    chunks = []
    offset = 0

    while offset < transaction.raw.fd.end_of_file:
        copychunk_struct = SMB2SrvCopyChunk()
        copychunk_struct['source_offset'] = offset
        copychunk_struct['target_offset'] = offset
        if offset + CHUNK_SIZE < transaction.raw.fd.end_of_file:
            copychunk_struct['length'] = CHUNK_SIZE
        else:
            copychunk_struct['length'] = transaction.raw.fd.end_of_file - offset

        chunks.append(copychunk_struct)
        offset += CHUNK_SIZE

    return chunks


def _batches(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def _samefile(src, dst):
    return normcase(abspath(src)) == normcase(abspath(dst))


def copyfileobj(fsrc, fdst, length=16 * 1024):
    """copy data from file-like object fsrc to file-like object fdst"""
    while 1:
        buf = fsrc.read(length)
        if not buf:
            break
        fdst.write(buf)
