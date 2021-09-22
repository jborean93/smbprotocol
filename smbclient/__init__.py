# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import uuid
import logging

from smbprotocol.connection import (
    Connection
)

from smbprotocol.session import (
    Session
)

from smbprotocol.tree import (
    TreeConnect
)

from smbclient._pool import (
    ClientConfig,
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
    stat_volume,
    symlink,
    truncate,
    unlink,
    utime,
    walk,
    getxattr,
    listxattr,
    removexattr,
    setxattr,
    SMBDirEntry,
    SMBStatResult,
    SMBStatVolumeResult,
    XATTR_CREATE,
    XATTR_REPLACE,
)


class Client(object):
    """
    High-level concept of SMB client that incapsulates Connection, Session and TreeConnect into a single object.

    Used to make the code more compact, readable and avoid duplication of the same few lines
    of client establishment for regular-case scenario (where only single connection, session and tree_connect is used).

    Additionally, for scenarios where several sessions are needed (different users) or several tree_connects are needed
    (access to different shares within the same user session) a caller may re-use sub-components of this client;
    for example, Client.connection can be used for another Session creation.
    """
    def __init__(self, real_client_config, dialect=None, require_encryption=True, use_encrypted_share=False, **kwargs):
        self.connection = Connection(uuid.uuid4(), real_client_config.server, real_client_config.port)
        self.connection.connect(dialect)
        self.session = Session(self.connection, real_client_config.username,
                               real_client_config.password, require_encryption)
        share = real_client_config.encrypted_share if use_encrypted_share else real_client_config.share
        self.tree_connect = TreeConnect(self.session, share)

    def connect(self):
        self.session.connect()
        self.tree_connect.connect()

    def disconnect(self):
        self.connection.disconnect(True)
        self.session = None
        self.tree_connect = None


try:
    from logging import NullHandler
except ImportError:  # pragma: no cover
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

logger = logging.getLogger(__name__)
logger.addHandler(NullHandler())
