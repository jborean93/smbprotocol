import logging
import uuid

from smbprotocol.constants import Dialects
from smbprotocol.connection import Connection
from smbprotocol.tree import TreeConnect

log = logging.getLogger(__name__)


class Client(object):
    def __init__(self, dialect=None, require_secure_negotiate=True,
                 require_message_signing=True):
        """
        [MS-SMB2] v53.0 2017-09-15

        3.2.1.1 Global
        Used as the client interface with an SMB server, the attributes set
        here correspond to the objects listed in the Global section of MS-SMB2

        :param dialect: The dialect version the client supports, if not omitted
            will default to SMB 3.1.1, see contants.Dialects for the values
            that can be set here
        :param require_secure_negotiate: Indicates that the client requires
            validation of an SMB2 NEGOTIATE request
        :param require_message_signing: Indicate that the client requies
            validation of all SMB requests and responses
        """
        self.connection_table = []
        self.require_message_signing = require_message_signing

        self.dialect = dialect
        if dialect is None or dialect >= Dialects.SMB_2_1_0:
            # opened files, indexed by name and lease_key
            self.global_file_table = {}

            # a global identifier for this client
            self.client_guid = uuid.uuid4()

        if dialect is None or dialect >= Dialects.SMB_3_0_0:
            # The highest SMB2 dialect that the client implements
            self.max_dialect = \
                dialect if dialect is not None else Dialects.SMB_3_1_1

            # Indicates the client requires validation of an SMB2 NEGOTIATE
            # request
            self.require_secure_negotiate = require_secure_negotiate

            # a list of Server entries
            self.server_list = []

    def open_connection(self, share, username, password,
                        port=445):
        """
        [MS-SMB2] v53.0 2017-09-15

        3.2.4.2 Application Requests a Connection to a Share
        Will do the following
            * Connect to the target server
            * Negotiate the SMB protocol details
            * Authenticate the user
            * Connect to the share specified

        :param share: The share to access, should be the full network form
        :param username: The username to authenticate with
        :param password: The password to authenticate with
        :param port: The port to use for the transport
        :return: Session and TreeConnect handle
        """
        # determine the server from the UNC share that we are connecting to
        if not share.startswith("\\\\"):
            raise Exception("Share should be in the full UNC form "
                            "\\\\server\\share")
        server_name = share[2:].split("\\")[0]

        # Try and find an existing connections to the server
        connection = None
        for conn in self.connection_table:
            if conn.server.server_name == server_name and \
                    conn.dialect == self.dialect:
                connection = conn
                break

        # We don't have an existing Connection, create a new one
        if connection is None:
            connection = Connection(self.client_guid,
                                    self.require_message_signing, server_name,
                                    port)
            connection.connect()
            self.connection_table.append(connection)
            connection.negotiate(self.dialect)

        # get the Session from the Connection session_table
        session = None
        for id, sess in connection.session_table.items():
            if username == sess.username and password == sess.password:
                session = sess
                break

        # we don't have an existing Session, create a new one
        if session is None:
            session = connection.create_session(username, password)

        # Try and find an existing TreeConnect from the Session
        tree_connect = None
        for id, tree in session.tree_connect_table.items():
            if tree.share_name == share:
                tree_connect = tree

        # we don't have an existing TreeConnect, create a new one
        if tree_connect is None:
            tree_connect = TreeConnect(session)
            tree_connect.connect(share)

        return session, tree_connect

    def open_file(self, session, tree_connect, path):
        # TODO: verify session and tree_connect are valid

        file = None
        if self.dialect > Dialects.SMB_2_0_2:
            file = self.global_file_table.get(path, None)

        if not file:
            # create new file
            a = ""

        pass

    def open_directory(self):
        pass

    def open_named_pipe(self):
        pass


class Server(object):

    def __init__(self, server_guid, dialect_revision, capabilities,
                 security_mode, address_list, server_name):
        """
        [MS-SMB2] v53.0 2017-09-15

        3.2.1.9 Per Server
        List of attributes that are set per server

        :param server_guid: A GUID that is generated by the remote server
        :param dialect_revision: Preferred dialect between client and server
        :param capabilities: The capabilities received from the server in the
            SMB2 NEGOTIATE response
        :param security_mode: The security mode received from the server in the
            SMB2 NEGOTIATE response
        :param address_list: A list of IPv4 and IPv6 addresses hosted on the
            server
        :param server_name: A FQDN, NetBIOS or IP Address of the server
        """
        self.server_guid = server_guid
        self.dialect_revision = dialect_revision
        self.capabilities = capabilities
        self.security_mode = security_mode

        if isinstance(address_list, str):
            self.address_list = [address_list]
        elif isinstance(address_list, list):
            self.address_list = address_list
        else:
            raise Exception("address_list must be a str or list not %s" %
                            type(address_list).__name__)

        self.server_name = server_name
