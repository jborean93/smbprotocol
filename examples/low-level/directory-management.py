import logging
import uuid

from smbprotocol.connection import Connection
from smbprotocol.open import (
    CreateDisposition,
    CreateOptions,
    DirectoryAccessMask,
    FileAttributes,
    FileInformationClass,
    FilePipePrinterAccessMask,
    ImpersonationLevel,
    Open,
    ShareAccess,
)
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

server = "127.0.0.1"
port = 445
username = "smbuser"
password = "smbpassword"
share = rf"\\{server}\share"
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
    dir_open.create(
        ImpersonationLevel.Impersonation,
        DirectoryAccessMask.GENERIC_READ | DirectoryAccessMask.GENERIC_WRITE,
        FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
        ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
        CreateDisposition.FILE_OPEN_IF,
        CreateOptions.FILE_DIRECTORY_FILE,
    )

    # create some files in dir and query the contents as part of a compound
    # request
    directory_file = Open(tree, r"%s\file.txt" % dir_name)
    directory_file.create(
        ImpersonationLevel.Impersonation,
        FilePipePrinterAccessMask.GENERIC_WRITE | FilePipePrinterAccessMask.DELETE,
        FileAttributes.FILE_ATTRIBUTE_NORMAL,
        ShareAccess.FILE_SHARE_READ,
        CreateDisposition.FILE_OVERWRITE_IF,
        CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_DELETE_ON_CLOSE,
    )

    compound_messages = [
        directory_file.write(b"Hello World", 0, send=False),
        dir_open.query_directory("*", FileInformationClass.FILE_NAMES_INFORMATION, send=False),
        directory_file.close(False, send=False),
        dir_open.close(False, send=False),
    ]
    requests = connection.send_compound([x[0] for x in compound_messages], session.session_id, tree.tree_connect_id)
    responses = []
    for i, request in enumerate(requests):
        response = compound_messages[i][1](request)
        responses.append(response)

    dir_files = []
    for dir_file in responses[1]:
        dir_files.append(dir_file["file_name"].get_value().decode("utf-16-le"))

    log.info("Directory '%s\\%s' contains the files: %s", share, dir_name, ", ".join(repr(file) for file in dir_files))

    # delete a directory (note the dir needs to be empty to delete on close)
    dir_open = Open(tree, dir_name)
    delete_msgs = [
        dir_open.create(
            ImpersonationLevel.Impersonation,
            DirectoryAccessMask.DELETE,
            FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
            0,
            CreateDisposition.FILE_OPEN,
            CreateOptions.FILE_DIRECTORY_FILE | CreateOptions.FILE_DELETE_ON_CLOSE,
            send=False,
        ),
        dir_open.close(False, send=False),
    ]
    delete_reqs = connection.send_compound(
        [x[0] for x in delete_msgs], sid=session.session_id, tid=tree.tree_connect_id, related=True
    )
    for i, request in enumerate(delete_reqs):
        response = delete_msgs[i][1](request)
finally:
    connection.disconnect(True)
