import uuid

from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.open import CreateDisposition, CreateOptions, \
    DirectoryAccessMask, FileAttributes, ImpersonationLevel, Open, ShareAccess
from smbprotocol.tree import TreeConnect

server = "127.0.0.1"
port = 1445
username = "smbuser"
password = "smbpassword1"
share = r"\\%s\share" % server
dir_name = "directory"

connection = Connection(uuid.uuid4(), server, port)
connection.connect()

try:
    session = Session(connection, username, password)
    session.connect()
    tree = TreeConnect(session, share)
    tree.connect()

    # ensure directory is created
    dir_open = Open(tree, dir_name)
    dir_open.open(
        ImpersonationLevel.Impersonation,
        DirectoryAccessMask.GENERIC_READ | DirectoryAccessMask.GENERIC_WRITE,
        FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
        ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
        CreateDisposition.FILE_OPEN_IF,
        CreateOptions.FILE_DIRECTORY_FILE
    )
    dir_open.close(False)

    # delete a directory
    dir_open = Open(tree, dir_name)
    dir_open.open(
        ImpersonationLevel.Impersonation,
        DirectoryAccessMask.DELETE,
        FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
        0,
        CreateDisposition.FILE_OPEN,
        CreateOptions.FILE_DIRECTORY_FILE | CreateOptions.FILE_DELETE_ON_CLOSE
    )
    dir_open.close(False)
finally:
    connection.disconnect(True)
