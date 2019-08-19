# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import atexit
import ntpath
import uuid
import warnings

from smbprotocol.connection import (
    Connection,
)

from smbprotocol.session import (
    Session,
)

from smbprotocol.tree import (
    TreeConnect,
)

_CLIENT_GUID = uuid.uuid4()
_SMB_CONNECTIONS = {}


def get_smb_tree(path, username=None, password=None, port=445, encrypt=None, connection_timeout=60):
    """
    Returns an active Tree connection and file path relative to that tree based on the UNC path passed in and other
    connection arguments. The opened connection is registered in a pool and re-used if a connection is made to the same
    server with the same credentials.

    :param path: The absolute UNC path we want to open a tree connect to.
    :param username: Optional username to connect with. Required if no session has been registered for the server and
        Kerberos auth is not being used.
    :param password: Optional password to connect with.
    :param port: The port to connect with.
    :param encrypt: Whether to force encryption or not, once this has been set to True the session cannot be changed
        back to False.
    :param connection_timeout: Override the timeout used for the initial connection.
    :return: SMBSession that provides the fundamental connection layer to the SMB Server.
    """
    path_split = [p for p in ntpath.normpath(path).split("\\") if p]
    if len(path_split) < 2:
        raise ValueError("The SMB path specified must contain the server and share to connect to")

    server = path_split[0]
    connection_key = "%s:%s" % (server, port)
    share_path = "\\\\%s\\%s" % (server, path_split[1])

    global _SMB_CONNECTIONS
    connection = _SMB_CONNECTIONS.get(connection_key, None)

    if not connection:
        connection = Connection(_CLIENT_GUID, server, port)
        connection.connect(timeout=connection_timeout)
        _SMB_CONNECTIONS[connection_key] = connection

    # Find the first session in the connection session list that match the username specified, if not username then
    # just use the first session found or fall back to creating a new one with implicit auth/kerberos.
    session = next((s for s in connection.session_table.values() if username is None or s.username == username), None)
    if not session:
        session = Session(connection, username=username, password=password, require_encryption=(encrypt is True))
        session.connect()
    elif encrypt is not None:
        # We cannot go from encryption to no encryption on an existing session but we can do the opposite.
        if session.encrypt_data and not encrypt:
            raise ValueError("Cannot disable encryption on an already negotiated session.")
        elif not session.encrypt_data and encrypt:
            session.encrypt = True

    tree = next((t for t in session.tree_connect_table.values() if t.share_name == share_path), None)
    if not tree:
        tree = TreeConnect(session, share_path)
        tree.connect()

    file_path = ""
    if len(path_split) > 2:
        file_path = "\\".join(path_split[2:])

    return tree, file_path


# Make sure we run the function to close all the sessions when we exit Python
def reset_connection_cache(fail_on_error=True):
    """
    Closes all the connections/sessions that have been pooled in the SMB Client. This allows a user to reset their
    client in case of an unknown problem or they just wish to reset all the connections. It is also run on exit of the
    Python interpreter to ensure the SMB connections are closed.
    """
    global _SMB_CONNECTIONS

    for name, connection in list(_SMB_CONNECTIONS.items()):
        try:
            connection.disconnect()
            del _SMB_CONNECTIONS[name]
        except Exception as e:
            if fail_on_error:
                raise
            else:
                warnings.warn("Failed to close connection %s: %s" % (name, str(e)))


atexit.register(reset_connection_cache, fail_on_error=False)
