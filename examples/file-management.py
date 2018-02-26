import uuid

from smbprotocol.connection import Connection
from smbprotocol.create_contexts import CreateContextName, \
    SMB2CreateContextRequest, SMB2CreateQueryMaximalAccessRequest
from smbprotocol.security_descriptor import AccessAllowedAce, AccessMask, \
    AclPacket, SDControl, SIDPacket, SMB2CreateSDBuffer
from smbprotocol.session import Session
from smbprotocol.structure import FlagField
from smbprotocol.open import CreateDisposition, CreateOptions, \
    FileAttributes, FilePipePrinterAccessMask, ImpersonationLevel, Open, \
    ShareAccess
from smbprotocol.tree import TreeConnect

server = "127.0.0.1"
port = 445
username = "smbuser"
password = "smbpassword"
share = r"\\%s\share" % server
file_name = "file-test.txt"

connection = Connection(uuid.uuid4(), server, port)
connection.connect()

try:
    session = Session(connection, username, password)
    session.connect()
    tree = TreeConnect(session, share)
    tree.connect()

    # ensure file is created, get maximal access, and set everybody read access
    max_req = SMB2CreateContextRequest()
    max_req['buffer_name'] = \
        CreateContextName.SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST
    max_req['buffer_data'] = SMB2CreateQueryMaximalAccessRequest()

    # create security buffer that sets the ACL for everyone to have read access
    everyone_sid = SIDPacket()
    everyone_sid.from_string("S-1-1-0")

    ace = AccessAllowedAce()
    ace['mask'] = AccessMask.GENERIC_ALL
    ace['sid'] = everyone_sid

    acl = AclPacket()
    acl['aces'] = [ace]

    sec_desc = SMB2CreateSDBuffer()
    sec_desc['control'].set_flag(SDControl.SELF_RELATIVE)
    sec_desc.set_dacl(acl)
    sd_buffer = SMB2CreateContextRequest()
    sd_buffer['buffer_name'] = CreateContextName.SMB2_CREATE_SD_BUFFER
    sd_buffer['buffer_data'] = sec_desc

    create_contexts = [
        max_req,
        sd_buffer
    ]

    file_open = Open(tree, file_name)
    open_info = file_open.open(
        ImpersonationLevel.Impersonation,
        FilePipePrinterAccessMask.GENERIC_READ |
        FilePipePrinterAccessMask.GENERIC_WRITE,
        FileAttributes.FILE_ATTRIBUTE_NORMAL,
        ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
        CreateDisposition.FILE_OVERWRITE_IF,
        CreateOptions.FILE_NON_DIRECTORY_FILE,
        create_contexts
    )

    # as the raw structure 'maximal_access' is an IntField, we create our own
    # flag field, set the value and get the human readble string
    max_access = FlagField(
        size=4,
        flag_type=FilePipePrinterAccessMask,
        flag_strict=False
    )
    max_access.set_value(open_info[0]['maximal_access'].get_value())
    print("Maximum access mask for file %s\\%s: %s"
          % (share, file_name, str(max_access)))

    # write to a file
    text = "Hello World, what a nice day to play with SMB"
    file_open.write(text.encode('utf-8'), 0)

    # read from a file
    file_text = file_open.read(0, 1024)
    print("Text of file %s\\%s: %s"
          % (share, file_name, file_text.decode('utf-8')))
    file_open.close(False)

    # read and delete a file in a single SMB packet instead of 3
    file_open = Open(tree, file_name)
    delete_msgs = [
        file_open.open(
            ImpersonationLevel.Impersonation,
            FilePipePrinterAccessMask.GENERIC_READ |
            FilePipePrinterAccessMask.DELETE,
            FileAttributes.FILE_ATTRIBUTE_NORMAL,
            0,
            CreateDisposition.FILE_OPEN,
            CreateOptions.FILE_NON_DIRECTORY_FILE |
            CreateOptions.FILE_DELETE_ON_CLOSE,
            send=False
        ),
        file_open.read(0, len(text), send=False),
        file_open.close(False, send=False)
    ]
    requests = connection.send_compound([x[0] for x in delete_msgs],
                                        session.session_id,
                                        tree.tree_connect_id, related=True)
    responses = []
    for i, request in enumerate(requests):
        response = delete_msgs[i][1](request)
        responses.append(response)
    print("Text of file when reading/deleting in 1 request: %s"
          % responses[1].decode('utf-8'))
finally:
    connection.disconnect(True)
