from __future__ import unicode_literals

from ntpath import join, basename, splitdrive

import sys
import os.path
from os import error as os_error

from smbclient._os import remove, rmdir, listdir, stat, makedirs, readlink, symlink, scandir, copyfile_server_side
from smbclient.path import islink, isdir
from smbprotocol.exceptions import SMBOSError


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


def copy(src, dst, **kwargs):
    """Copy data.

    The destination may be a directory.
    """
    _check_src_dst(src, dst)

    if _samefile(src, dst, **kwargs):
        raise ValueError("`%s` and `%s` are the same file" % (src, dst))

    if isdir(dst, **kwargs):
        dst = join(dst, basename(src))

    copyfile_server_side(src, dst, **kwargs)


def copytree_copy(src, dst, symlinks=False, ignore=None, **kwargs):
    """Recursively copy a directory tree using copy().

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
    _check_src_dst(src, dst)

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
                copytree_copy(srcname, dstname, symlinks, ignore, **kwargs)
            else:
                # Will raise a SpecialFileError for unsupported file types
                copy(srcname, dstname, **kwargs)
        # catch the Error from the recursive copytree so that we can
        # continue with other files
        except Error as err:
            errors.extend(err.args[0])
        except EnvironmentError as why:
            errors.append((srcname, dstname, str(why)))
    if errors:
        raise Error(errors)


def _samefile(src, dst, **kwargs):
    unc_src, rest_src = splitdrive(src)
    unc_dst, rest_dst = splitdrive(dst)
    if unc_src != unc_dst:
        return False

    if unc_src:
        stat1 = stat(src, **kwargs)
        if src == dst:
            return True
        try:
            stat2 = stat(dst, **kwargs)
            return stat1.st_ino == stat2.st_ino and stat1.st_dev == stat2.st_dev
        except SMBOSError:
            return False

    else:
        try:
            return os.path.samefile(src, dst)
        except OSError:
            # target file does not exist
            return False


def _is_remote_file(src):
    unc, _ = splitdrive(src)
    return bool(unc)


def _check_src_dst(src, dst):
    if not _is_remote_file(src):
        raise ValueError("Local sources are not supported yet")
    if not _is_remote_file(dst):
        raise ValueError("Local destinations are not supported yet")
