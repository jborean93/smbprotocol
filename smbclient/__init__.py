# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import logging

from smbclient._pool import (
    delete_session,
    register_session,
    reset_connection_cache,
)

from smbclient._io import (
    SEEK_CUR,
    SEEK_END,
    SEEK_SET,
)

from smbclient._os import (
    copyfile,
    link,
    listdir,
    lstat,
    mkdir,
    makedirs,
    open_file,
    readlink,
    remove,
    removedirs,
    rename,
    renames,
    replace,
    rmdir,
    scandir,
    stat,
    symlink,
    truncate,
    unlink,
    utime,
    walk,
    getxattr,
    listxattr,
    removexattr,
    setxattr,
    SMBStatResult,
    XATTR_CREATE,
    XATTR_REPLACE,
)

try:
    from logging import NullHandler
except ImportError:  # pragma: no cover
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

logger = logging.getLogger(__name__)
logger.addHandler(NullHandler())
