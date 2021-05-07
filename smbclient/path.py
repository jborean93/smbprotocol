# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import errno
import stat as py_stat

from smbclient._os import (
    stat,
)

from smbprotocol.exceptions import (
    SMBLinkRedirectionError,
    SMBOSError,
)


def exists(path, **kwargs):
    """
    Return True if path refers to an existing path. Returns False for broken symbolic links or links pointing to
    unreachable locations.

    :param path: The path to check if it exists.
    :param kwargs: Common arguments used to build the SMB Session.
    :return: Bool as to whether the path exists or not.
    """
    return _exists(path, False, True, **kwargs)


def lexists(path, **kwargs):
    """
    Return True if path refers to an existing path. Returns True for broken symbolic links or links pointing to
    unreachable locations.

    :param path: The path to check if it exists.
    :param kwargs: Common arguments used to build the SMB Session.
    :return: Bool as to whether the path exists or not.
    """
    return _exists(path, True, False, **kwargs)


def getatime(path, **kwargs):
    """
    Return the time of last access of path. The return value is a floating point number giving the number of seconds
    since the epoch (see the time module). Raise OSError if the file does not exist or is inaccessible.

    :param path: The path to get the atime for.
    :param kwargs: Common arguments used to build the SMB Session.
    :return: float that represents the number of seconds since epoch for atime.
    """
    return stat(path, **kwargs).st_atime


def getmtime(path, **kwargs):
    """
    Return the time of last modification of path. The return value is a floating point number giving the number of
    seconds since the epoch (see the time module). Raise OSError if the file does not exist or is inaccessible.

    :param path: The path to get the mtime for.
    :param kwargs: Common arguments used to build the SMB Session.
    :return: float that represents the number of seconds since epoch for atime.
    """
    return stat(path, **kwargs).st_mtime


def getctime(path, **kwargs):
    """
    Return the system’s ctime which is the creation time for path. The return value is a number giving the number of
    seconds since the epoch (see the time module). Raise OSError if the file does not exist or is inaccessible.

    :param path: The path to get the ctime for.
    :param kwargs: Common arguments used to build the SMB Session.
    :return: float that represents the number of seconds since epoch for atime.
    """
    return stat(path, **kwargs).st_ctime


def getsize(path, **kwargs):
    """
    Return the size, in bytes, of path. Raise OSError if the file does not exist or is inaccessible.

    :param path: The path to get the size for.
    :param kwargs: Common arguments used to build the SMB Session.
    :return: The byte size of the path.
    """
    return stat(path, **kwargs).st_size


def isfile(path, **kwargs):
    """
    Return True if path is an existing regular file. This follows symbolic links, so both islink() and isfile() can be
    true for the same path.

    :param path: The path to check.
    :param kwargs: Common arguments used to build the SMB Session.
    :return: True if the path is a file or points to a file.
    """
    return _stat_ismode(path, py_stat.S_ISREG, True, **kwargs)


def isdir(path, **kwargs):
    """
    Return True if path is an existing directory. This follows symbolic links, so both islink() and isdir() can be true
    for the same path.

    :param path: The path to check.
    :param kwargs: Common arguments used to build the SMB Session.
    :return: True if path is a dir or points to a dir.
    """
    return _stat_ismode(path, py_stat.S_ISDIR, True, **kwargs)


def islink(path, **kwargs):
    """
    Return True if path is a symbolic link.

    :param path: The path to check
    :param kwargs: Common arguments used to build the SMB Session.
    :return: True if path is a symlink.
    """
    return _stat_ismode(path, py_stat.S_ISLNK, False, **kwargs)


def samefile(path1, path2, **kwargs):
    """
    Return True if both pathname arguments refer to the same file or directory. This is determined by the device number
    and i-node number and raises an exception if an os.stat() call on either pathname fails.

    :param path1: The first path to compare.
    :param path2: The second path to compare.
    :param kwargs: Common arguments used to build the SMB Session.
    :return: Bool that indicates whether the 2 files are the same.
    """
    stat1 = stat(path1, **kwargs)
    stat2 = stat(path2, **kwargs)
    return stat1.st_ino == stat2.st_ino and stat1.st_dev == stat2.st_dev


def _exists(path, symlink_default, follow_symlinks, **kwargs):
    try:
        stat(path, follow_symlinks=follow_symlinks, **kwargs)
        return True
    except OSError as err:
        if err.errno == errno.ENOENT:
            return False
        raise
    except SMBLinkRedirectionError:
        # Link points to another server or local drive, return false
        return symlink_default


def _stat_ismode(path, check, follow, **kwargs):
    try:
        return check(stat(path, follow_symlinks=follow, **kwargs).st_mode)
    except SMBOSError as err:
        if err.errno == errno.ENOENT:
            return False
        raise
