# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com> and other contributors
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import absolute_import
from __future__ import division

import errno
import ntpath
import os
import os.path
import shutil
import stat
import sys

from smbclient._io import (
    query_info,
    set_info,
    SMBFileTransaction,
    SMBRawIO,
)

from smbclient._os import (
    copyfile as smbclient_copyfile,
    makedirs,
    open_file,
    readlink,
    remove,
    rmdir,
    scandir,
    stat as smbclient_stat,
    symlink,
    SMBDirEntry,
)

from smbclient.path import (
    isdir,
    islink,
    samefile,
)

from smbprotocol import (
    MAX_PAYLOAD_SIZE,
)

from smbprotocol._text import (
    to_native,
)

from smbprotocol.file_info import (
    FileAttributes,
    FileBasicInformation,
)

from smbprotocol.open import (
    CreateOptions,
    FilePipePrinterAccessMask,
)

from smbprotocol.structure import (
    DateTimeField,
)


def copy(src, dst, follow_symlinks=True, **kwargs):
    """
    Copies the file src to the file or directory dst. If dst specified a directory, the file will be copied into dst
    using the base filename from src. Returns the path to the newly created file.

    If follow_symlinks is 'False', and src is a symbolic link, dst will be created as a symbolic link. If
    follow_symlinks is 'True' and src is a symbolic link, dst will be a copy of the file src refers to.

    copy() copies the file data and file's permission mode which on Windows is only the read-only flag. All other
    bits are ignored on a copy. Other metadata like file's creation and modification times, are not preserved.

    :param src: The path to the source file to copy, if not an absolute path then this is relative to the current
        directory.
    :param dst: The path to the destination to copy the file t.
    :param follow_symlinks: Whether to copy the symlink target of source or the symlink itself.
    :param kwargs: Common arguments used to build the SMB Session for any UNC paths.
    :return The path to the destination filename.
    """
    return _copy(src, dst, follow_symlinks, copymode, **kwargs)


def copy2(src, dst, follow_symlinks=True, **kwargs):
    """
    Identical to copy() except that copy() also attempts to preserve the file metadata.

    copy2() uses copystat() to copy the file metadata. Please see copystat() for more information about how and what
    metadata it copies to the dst file.

    :param src: The path to the source file to copy, if not an absolute path then this is relative to the current
        directory.
    :param dst: The path to the destination to copy the file t.
    :param follow_symlinks: Whether to copy the symlink target of source or the symlink itself.
    :param kwargs: Common arguments used to build the SMB Session for any UNC paths.
    :return The path to the destination filename.
    """
    return _copy(src, dst, follow_symlinks, copystat, **kwargs)


def copyfile(src, dst, follow_symlinks=True, **kwargs):
    """
    Copy the contents (no metadata) of the file names src to a file named dst and return dst in the most efficient way
    possible. If the src and dst reside on the same UNC share then a more efficient remote side copy is used. If the
    src and dst reside on the same local path then the proper shutil.copyfile() method is called, otherwise the content
    is copied using copyfileobj() in chunks.

    dst must be the complete target file name; look at copy() for a copy that accepts a target directory path. If src
    dst specify the same file, ValueError is raised.

    The destination location must be writable; otherwise, an OSError exception will be raised. If dst already exists,
    it will be replaced. Special files such as character or block devices and pipes cannot be copied with this
    function.

    If follow_symlinks is 'False' and src is a symbolic link, a new symbolic link will be created instead of copying
    the file src points to. This will fail if the symbolic link at src is a different root as dst.

    :param src: The src filepath to copy.
    :param dst: The destinoation filepath to copy to.
    :param follow_symlinks: Whether to copy the symlink target of source or the symlink itself.
    :param kwargs: Common arguments used to build the SMB Session for any UNC paths.
    :return: The dst path.
    """
    def wrap_not_implemented(function_name):
        def raise_not_implemented(*args, **kwargs):
            raise NotImplementedError("%s is unavailable on this platform as a local operation" % function_name)

        return raise_not_implemented

    norm_src = ntpath.normpath(src)
    if norm_src.startswith('\\\\'):
        src_root = ntpath.splitdrive(norm_src)[0]
        islink_func = islink
        readlink_func = readlink
        symlink_func = symlink
        src_open = open_file
        src_kwargs = kwargs
    else:
        src_root = None
        islink_func = os.path.islink
        # readlink and symlink are not available on Windows on Python 2.
        readlink_func = getattr(os, 'readlink', wrap_not_implemented('readlink'))
        symlink_func = getattr(os, 'symlink', wrap_not_implemented('symlink'))
        src_open = open
        src_kwargs = {}

    norm_dst = ntpath.normpath(dst)
    if norm_dst.startswith('\\\\'):
        dst_root = ntpath.splitdrive(norm_dst)[0]
        dst_open = open_file
        dst_kwargs = kwargs
    else:
        dst_root = None
        dst_open = open
        dst_kwargs = {}

    if not follow_symlinks and islink_func(src, **src_kwargs):
        if src_root != dst_root:
            raise ValueError("Cannot copy a symlink on different roots.")

        symlink_func(readlink_func(src), dst, **src_kwargs)
        return dst

    if src_root is None and dst_root is None:
        # The files are local and follow_symlinks is True, rely on the builtin copyfile mechanism.
        shutil.copyfile(src, dst)
        return dst

    if src_root == dst_root:
        # The files are located on the same share and follow_symlinks is True, rely on smbclient.copyfile for an
        # efficient server side copy.
        try:
            is_same = samefile(src, dst, **kwargs)
        except OSError as err:
            if err.errno == errno.ENOENT:
                is_same = False
            else:
                raise

        if is_same:
            raise shutil.Error(to_native("'%s' and '%s' are the same file, cannot copy" % (src, dst)))

        smbclient_copyfile(src, dst, **kwargs)
        return dst

    # Finally we are copying across different roots so we just chunk the data using copyfileobj
    with src_open(src, mode='rb', **src_kwargs) as src_fd, dst_open(dst, mode='wb', **dst_kwargs) as dst_fd:
        copyfileobj(src_fd, dst_fd, MAX_PAYLOAD_SIZE)

    return dst


# Because smbclient's open_file returns a file object this should just work.
copyfileobj = shutil.copyfileobj


def copymode(src, dst, follow_symlinks=True, **kwargs):
    """
    Copy the permission bits from src to dst. The file contents, owner, and group are unaffected. Due to the
    limitations of Windows, this function only sets/unsets the dst's FILE_ATTRIBUTE_READ_ONLY flag based on what src's
    attribute is set to.

    If follow_symlinks is 'False', and both src and dst are symbolic links, copymode() will attempt to modify the mode
    of dst itself (rather than the file it points to).

    This function supports src and dst being either a local or UNC path. A relative path will be resolved based on the
    current working directory.

    :param src: The src file or directory to copy the read only flag from.
    :param dst: The dst file or directory to copy the read only flag to.
    :param follow_symlinks: Whether to copy the read only flag on the symlink or the target of the symlink.
    :param kwargs: Common arguments used to build the SMB Session for any UNC paths.
    """
    src_mode = stat.S_IMODE(_get_file_stat(src, follow_symlinks, **kwargs).st_mode)

    norm_dst = ntpath.normpath(dst)
    if norm_dst.startswith('\\\\'):
        read_only = not (src_mode & stat.S_IWRITE == stat.S_IWRITE and src_mode & stat.S_IREAD == stat.S_IREAD)
        _set_file_basic_info(dst, follow_symlinks, read_only=read_only, **kwargs)
    else:
        _local_chmod(dst, src_mode, follow_symlinks)


def copystat(src, dst, follow_symlinks=True, **kwargs):
    """
    Copy the read only attribute, last access time, and last modification time from src to dst. The file contents,
    owner, and group are unaffected.

    If follow_symlinks is 'False' and src and dst both refer to symbolic links, copystat() will operate on the
    symbolic links themselves rather than the files the symbolic links refer to.

    :param src: The src file or directory to copy the read only flag from.
    :param dst: The dst file or directory to copy the read only flag to.
    :param follow_symlinks: Whether to copy the read only flag on the symlink or the target of the symlink.
    :param kwargs: Common arguments used to build the SMB Session for any UNC paths.
    """
    src_stat = _get_file_stat(src, follow_symlinks, **kwargs)
    src_mode = stat.S_IMODE(src_stat.st_mode)

    # *_ns was only added in Python 3, fallback to a manual calculation from seconds since EPOCH.
    atime_ns = getattr(src_stat, 'st_atime_ns', src_stat.st_atime * 1000000000)
    mtime_ns = getattr(src_stat, 'st_mtime_ns', src_stat.st_mtime * 1000000000)

    norm_dst = ntpath.normpath(dst)
    if norm_dst.startswith('\\\\'):
        read_only = not (src_mode & stat.S_IWRITE == stat.S_IWRITE and src_mode & stat.S_IREAD == stat.S_IREAD)
        _set_file_basic_info(dst, follow_symlinks, read_only=read_only, atime_ns=atime_ns, mtime_ns=mtime_ns, **kwargs)
    else:
        if not follow_symlinks and sys.version_info[0] < 3:
            # Python 2 always follows symlinks and does not have a kwarg to override, we can only just fail here.
            raise NotImplementedError("utime: follow_symlinks unavailable on this platform")

        _local_chmod(dst, src_mode, follow_symlinks)

        if sys.version_info[0] < 3:
            os.utime(dst, (atime_ns / 1000000000, mtime_ns / 1000000000))
        else:
            os.utime(dst, ns=(atime_ns, mtime_ns), follow_symlinks=follow_symlinks)


def copytree(src, dst, symlinks=False, ignore=None, copy_function=copy2, ignore_dangling_symlinks=False,
             dirs_exist_ok=False, **kwargs):
    """
    Recursively copy an entire directory tree rooted at src to a directory named dst and return the destination
    directory. dirs_exist_ok dictates whether to raise an exception in case dst or any missing parent directory
    exists.

    Permissions and times of directories are copied with copystat(), individual files are copied using copy2().

    If symlinks is 'True', symbolic links in the source tree are represented as symbolic links in the new tree and the
    metadata of the original links will be copied as far as the platform allow; if 'False' or omitted, the contents and
    metadata of the linked files are copied to the new tree.

    When symlinks is 'False', if the file pointed by the symlink doesn't exist, an exception will be added in the list
    of errors raises in an 'Error' exception at the end of the copy process. You can set the optional
    ignore_dangling_symlinks flag to 'True' if you want to silence this exception.

    if ignore is given, it must be a callable that will receive as its arguments the directory being visited by
    copytree(), and a list of its contents, as returned by smbclient.listdir(). Since copytee() is called recursively,
    the ignore callable will be called once for each directory that is copied. The callable must return a sequence of
    directory and file names relative to the current directory (i.e. a subset of the items in its second argument);
    these names will then be ignored in the copy process.

    If exception(s) occur, an shutil.Error is raised with a list of reasons.

    If copy_function is given, it must be a callable that will be used to copy each file. It will be called with the
    source path and the destination path as arguments. By default copy() is used, but any function that supports the
    same signature (like copy()) can be used.

    In this current form, copytree() only supports remote to remote copies over SMB.

    :param src: The source directory to copy.
    :param dst: The destination directory to copy to.
    :param symlinks: Whether to attempt to copy a symlink from the source tree to the dest tree, if False the symlink
        target's contents are copied instead as a normal file/dir.
    :param ignore: A callable in the form 'callable(src, names) -> ignored_named' that returns a list of file names to
        ignore based on the list passed in.
    :param copy_function: The copy function to use for copying files.
    :param ignore_dangling_symlinks: Ignore any broken symlinks, otherwise an Error is raised.
    :param dirs_exist_ok: Whether to fail if the dst directory exists or not.
    :param kwargs: Common arguments used to build the SMB Session for any UNC paths.
    :return: The dst path.
    """
    dir_entries = list(scandir(src, **kwargs))
    makedirs(dst, exist_ok=dirs_exist_ok, **kwargs)

    ignored = []
    if ignore is not None:
        ignored = ignore(src, [e.name for e in dir_entries])

    errors = []
    for dir_entry in dir_entries:
        if dir_entry.name in ignored:
            continue

        src_path = ntpath.join(src, dir_entry.name)
        dst_path = ntpath.join(dst, dir_entry.name)

        try:
            if dir_entry.is_symlink():
                link_target = readlink(src_path, **kwargs)
                if symlinks:
                    symlink(link_target, dst_path, **kwargs)
                    copystat(src_path, dst_path, follow_symlinks=False)
                    continue
                else:
                    # Manually override the dir_entry with a new one that is the link target and copy that below.
                    try:
                        dir_entry = SMBDirEntry.from_path(link_target, **kwargs)
                    except OSError as err:
                        if err.errno == errno.ENOENT and ignore_dangling_symlinks:
                            continue
                        raise

            if dir_entry.is_dir():
                copytree(src_path, dst_path, symlinks, ignore, copy_function, ignore_dangling_symlinks, dirs_exist_ok,
                         **kwargs)
            else:
                copy_function(src_path, dst_path, **kwargs)
        except shutil.Error as err:
            # From a recursive call of copytree().
            errors.extend(err.args[0])
        except OSError as err:
            # Main smbclient operations should raise an OSError exception (or one that inherits OSError).
            errors.append((src_path, dst_path, str(err)))
        except ValueError as err:
            # If the path is not supported or we are trying to symlink outside of the share boundary.
            errors.append((src_path, dst_path, str(err)))

    try:
        copystat(src, dst)
    except OSError as err:
        errors.append((src, dst, str(err)))

    if errors:
        raise shutil.Error(errors)
    return dst


def rmtree(path, ignore_errors=False, onerror=None, **kwargs):
    """
    Recursively delete a directory tree; path must point to a directory (but not a symbolic link to a directory).

    If ignore_errors is 'True', errors resulting from failed removals will be ignored; otherwise such errors are
    handled by calling a handler specified by onerror or, if that is omitted, they raise an exception.

    if onerror is provided, it must be a callable that accepts three parameters: function, path, excinfo.

    The first parameter, function, is the function which raised the exception. The second parameter, path, will be the
    path name passed to function. The third parameter, excinfo, will be the exception information returned by
    sys.exc_info(). Exceptions raised by onerror will not be caught.

    :param path: The path to remove.
    :param ignore_errors: Whether to ignore errors on failed removed or delegate the handling to onerror.
    :param onerror: The callback executed when an error on removal is raised.
    :param kwargs: Common arguments used to build the SMB Session.
    """
    if ignore_errors:
        def onerror(*args):
            pass
    elif onerror is None:
        def onerror(*args):
            raise

    if islink(path, **kwargs):
        try:
            raise OSError("Cannot call rmtree on a symbolic link")
        except OSError:
            onerror(islink, path, sys.exc_info())
            return

    scandir_gen = scandir(path, **kwargs)
    while True:
        try:
            dir_entry = next(scandir_gen)
        except StopIteration:
            break
        except OSError:
            onerror(scandir, path, sys.exc_info())
            continue

        # In case the entry is a directory symbolic link we need to remove the dir itself and not recurse down into
        # it with rmtree. Doing that would result in a symbolic link target having it's contents removed even if it's
        # outside the rmtree scope.
        if dir_entry.is_symlink() and \
                dir_entry.stat(follow_symlinks=False).st_file_attributes & FileAttributes.FILE_ATTRIBUTE_DIRECTORY:
            try:
                rmdir(dir_entry.path)
            except OSError:
                onerror(rmdir, dir_entry.path, sys.exc_info())
        elif dir_entry.is_dir():
            rmtree(dir_entry.path, ignore_errors, onerror)
        else:
            try:
                remove(dir_entry.path)
            except OSError:
                onerror(remove, dir_entry.path, sys.exc_info())

    try:
        rmdir(path)
    except OSError:
        onerror(rmdir, path, sys.exc_info())


def _copy(src, dst, follow_symlinks, copy_meta_func, **kwargs):
    # Need to check if dst is a UNC path before checking if it's a dir in smbclient.path before checking to see if it's
    # a local directory. If either one is a dir, join the filename of src onto dst.
    if ntpath.normpath(dst).startswith('\\\\') and isdir(dst, **kwargs):
        dst = ntpath.join(dst, ntpath.basename(src))
    elif os.path.isdir(dst):
        dst = os.path.join(dst, os.path.basename(src))

    copyfile(src, dst, follow_symlinks=follow_symlinks)
    copy_meta_func(src, dst, follow_symlinks=follow_symlinks)
    return dst


def _get_file_stat(path, follow_symlinks=True, **kwargs):
    if path.startswith('//') or path.startswith('\\\\'):
        return smbclient_stat(path, follow_symlinks=follow_symlinks, **kwargs)
    else:
        # Source is a local path or accessible to the host, use the builtin os module to get the read only flag.
        if follow_symlinks:
            return os.stat(path)
        else:
            return os.lstat(path)


def _local_chmod(path, mode, follow_symlinks):
    if sys.version_info[0] < 3:
        if not follow_symlinks:
            if not hasattr(os, 'lchmod'):
                raise NotImplementedError("chmod: follow_symlinks unavailable on this platform")
            os.lchmod(path, mode)
        else:
            os.chmod(path, mode)
    else:
        os.chmod(path, mode, follow_symlinks=follow_symlinks)


def _set_file_basic_info(file_path, follow_symlinks, read_only=None, atime_ns=None, mtime_ns=None, **kwargs):
    co = 0 if follow_symlinks else CreateOptions.FILE_OPEN_REPARSE_POINT

    # Need to check if we need to change the attributes if the read_only flag is set. We can't just blindly set the
    # read only attribute as that will remove any other attribute set on the file.
    new_attributes = 0
    if read_only is not None:
        file_fd = SMBRawIO(file_path, mode='r', share_access='rw', create_options=co,
                           desired_access=FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES, **kwargs)
        with SMBFileTransaction(file_fd) as transaction:
            query_info(transaction, FileBasicInformation)

        existing_attributes = transaction.results[0]['file_attributes'].get_value()
        if read_only and existing_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY == 0:
            new_attributes = existing_attributes | FileAttributes.FILE_ATTRIBUTE_READONLY
        elif not read_only and existing_attributes & FileAttributes.FILE_ATTRIBUTE_READONLY != 0:
            new_attributes = existing_attributes & ~FileAttributes.FILE_ATTRIBUTE_READONLY

            # Make sure at least 1 attribute is set (normal)
            if new_attributes == 0:
                new_attributes |= FileAttributes.FILE_ATTRIBUTE_NORMAL

    # Only set the attributes if there is actually a change to be made.
    if new_attributes or atime_ns is not None or mtime_ns is not None:
        file_fd = SMBRawIO(file_path, mode='r', share_access='rw', create_options=co,
                           desired_access=FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES, **kwargs)

        with SMBFileTransaction(file_fd) as transaction:
            basic_info = FileBasicInformation()
            basic_info['file_attributes'] = new_attributes

            if atime_ns is not None:
                basic_info['last_access_time'] = int((atime_ns // 100) + DateTimeField.EPOCH_FILETIME)

            if mtime_ns is not None:
                basic_info['last_write_time'] = int((mtime_ns // 100) + DateTimeField.EPOCH_FILETIME)

            set_info(transaction, basic_info)
