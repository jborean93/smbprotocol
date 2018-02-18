import logging

from smbprotocol.connection import Commands, Dialects
from smbprotocol.exceptions import SMBException
from smbprotocol.ioctl import CtlCode, IOCTLFlags, SMB2IOCTLRequest, \
    SMB2IOCTLResponse, SMB2ValidateNegotiateInfoRequest, \
    SMB2ValidateNegotiateInfoResponse
from smbprotocol.structure import BytesField, EnumField, FlagField, IntField, \
    Structure

try:
    from collections import OrderedDict
except ImportError:  # pragma: no cover
    from ordereddict import OrderedDict

log = logging.getLogger(__name__)


class TreeFlags(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.9 SMB2 TREE_CONNECT Response Flags
    Flags used in SMB 3.1.1  to indicate how to process the operation.
    """
    SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT = 0x0004
    SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER = 0x0002
    SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT = 0x0001


class ShareType(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.10 SMB2 TREE_CONNECT Response Capabilities
    The type of share being accessed
    """
    SMB2_SHARE_TYPE_DISK = 0x01
    SMB2_SHARE_TYPE_PIPE = 0x02
    SMB2_SHARE_TYPE_PRINT = 0x03


class ShareFlags(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.10 SMB2 TREE_CONNECT Response Capabilities
    Properties for the share
    """
    SMB2_SHAREFLAG_MANUAL_CACHING = 0x00000000
    SMB2_SHAREFLAG_AUTO_CACHING = 0x00000010
    SMB2_SHAREFLAG_VDO_CACHING = 0x00000020
    SMB2_SHAREFLAG_NO_CACHING = 0x00000030
    SMB2_SHAREFLAG_DFS = 0x00000001
    SMB2_SHAREFLAG_DFS_ROOT = 0x00000002
    SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS = 0x00000100
    SMB2_SHAREFLAG_FORCE_SHARED_DELETE = 0x00000200
    SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING = 0x00000400
    SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM = 0x00000800
    SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK = 0x00001000
    SMB2_SHAREFLAG_ENABLE_HASH_V1 = 0x00002000
    SMB2_SHAREFLAG_ENABLE_HASH_V2 = 0x00004000
    SMB2_SHAREFLAG_ENCRYPT_DATA = 0x00008000
    SMB2_SHAREFLAG_IDENTITY_REMOTING = 0x00040000


class ShareCapabilities(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.10 SMB2 TREE_CONNECT Response Capabilities
    Indicates various capabilities for a share
    """
    SMB2_SHARE_CAP_DFS = 0x00000008
    SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY = 0x00000010
    SMB2_SHARE_CAP_SCALEOUT = 0x00000020
    SMB2_SHARE_CAP_CLUSTER = 0x00000040
    SMB2_SHARE_CAP_ASYMMETRIC = 0x00000080
    SMB2_SHARE_CAP_REDIRECT_TO_OWNER = 0x00000100


class SMB2TreeConnectRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.9 SMB2 TREE_CONNECT Request
    Sent by the client to request access to a particular share on the server
    """
    COMMAND = Commands.SMB2_TREE_CONNECT

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=9
            )),
            ('flags', FlagField(
                size=2,
                flag_type=TreeFlags,
            )),
            ('path_offset', IntField(
                size=2,
                default=64 + 8,
            )),
            ('path_length', IntField(
                size=2,
                default=lambda s: len(s['buffer']),
            )),
            ('buffer', BytesField(
                size=lambda s: s['path_length'].get_value()
            ))
        ])
        super(SMB2TreeConnectRequest, self).__init__()


class SMB2TreeConnectResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.10 SMB2 TREE_CONNECT Response
    Sent by the server when an SMB2 TREE_CONNECT request is processed
    successfully.
    """
    COMMAND = Commands.SMB2_TREE_CONNECT

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=16
            )),
            ('share_type', EnumField(
                size=1,
                enum_type=ShareType,
            )),
            ('reserved', IntField(size=1)),
            ('share_flags', FlagField(
                size=4,
                flag_type=ShareFlags,
            )),
            ('capabilities', FlagField(
                size=4,
                flag_type=ShareCapabilities,
            )),
            ('maximal_access', IntField(size=4))
        ])
        super(SMB2TreeConnectResponse, self).__init__()


class SMB2TreeDisconnect(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.11/12 SMB2 TREE_DISCONNECT Request and Response
    Sent by the client to request that the tree connect specific by tree_id in
    the header is disconnected.
    """
    COMMAND = Commands.SMB2_TREE_DISCONNECT

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=4,
            )),
            ('reserved', IntField(size=2))
        ])
        super(SMB2TreeDisconnect, self).__init__()


class TreeConnect(object):

    def __init__(self, session, share_name):
        """
        [MS-SMB2] v53.0 2017-09-15

        3.2.1.4 Per Tree Connect
        Attributes per Tree Connect (share connections)

        :param session: The Session to connect to the tree with
        :param share_name: The name of the share, including the server name,
            e.g. \\server\share
        """
        self._connected = False
        self.open_table = {}

        self.share_name = share_name
        self.tree_connect_id = None
        self.session = session
        self.is_dfs_share = None

        # SMB 3.x+
        self.is_ca_share = None
        self.encrypt_data = None
        self.is_scaleout_share = None

    def connect(self, require_secure_negotiate=True):
        """
        Connect to the share.

        :param require_secure_negotiate: For Dialects 3.0 and 3.0.2, will
            verify the negotiation parameters with the server to prevent
            SMB downgrade attacks
        """
        log.info("Session: %s - Creating connection to share %s"
                 % (self.session.username, self.share_name))
        utf_share_name = self.share_name.encode('utf-16-le')
        connect = SMB2TreeConnectRequest()
        connect['buffer'] = utf_share_name

        log.info("Session: %s - Sending Tree Connect message"
                 % self.session.username)
        log.debug(str(connect))
        request = self.session.connection.send(connect,
                                               sid=self.session.session_id)

        log.info("Session: %s - Receiving Tree Connect response"
                 % self.session.username)
        response = self.session.connection.receive(request)
        tree_response = SMB2TreeConnectResponse()
        tree_response.unpack(response['data'].get_value())
        log.debug(str(tree_response))

        # https://msdn.microsoft.com/en-us/library/cc246687.aspx
        self.tree_connect_id = response['tree_id'].get_value()
        log.info("Session: %s - Created tree connection with ID %d"
                 % (self.session.username, self.tree_connect_id))
        self._connected = True
        self.session.tree_connect_table[self.tree_connect_id] = self

        capabilities = tree_response['capabilities']
        self.is_dfs_share = capabilities.has_flag(
            ShareCapabilities.SMB2_SHARE_CAP_DFS)
        self.is_ca_share = capabilities.has_flag(
            ShareCapabilities.SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY)

        dialect = self.session.connection.dialect
        if dialect >= Dialects.SMB_3_0_0 and \
                self.session.connection.supports_encryption:
            self.encrypt_data = tree_response['share_flags'].has_flag(
                ShareFlags.SMB2_SHAREFLAG_ENCRYPT_DATA)

            self.is_scaleout_share = capabilities.has_flag(
                ShareCapabilities.SMB2_SHARE_CAP_SCALEOUT)

            # secure negotiate is only valid for SMB 3 dialects before 3.1.1
            if dialect < Dialects.SMB_3_1_1 and require_secure_negotiate:
                self._verify_dialect_negotiate()

    def disconnect(self):
        """
        Disconnects the tree connection.
        """
        if not self._connected:
            return

        log.info("Session: %s, Tree: %s - Disconnecting from Tree Connect"
                 % (self.session.username, self.share_name))

        req = SMB2TreeDisconnect()
        log.info("Session: %s, Tree: %s - Sending Tree Disconnect message"
                 % (self.session.username, self.share_name))
        log.debug(str(req))
        request = self.session.connection.send(req,
                                               sid=self.session.session_id,
                                               tid=self.tree_connect_id)

        log.info("Session: %s, Tree: %s - Receiving Tree Disconnect response"
                 % (self.session.username, self.share_name))
        res = self.session.connection.receive(request)
        res_disconnect = SMB2TreeDisconnect()
        res_disconnect.unpack(res['data'].get_value())
        log.debug(str(res_disconnect))
        self._connected = False
        del self.session.tree_connect_table[self.tree_connect_id]

    def _verify_dialect_negotiate(self):
        log_header = "Session: %s, Tree: %s" \
                     % (self.session.username, self.share_name)
        log.info("%s - Running secure negotiate process" % log_header)
        ioctl_request = SMB2IOCTLRequest()
        ioctl_request['ctl_code'] = \
            CtlCode.FSCTL_VALIDATE_NEGOTIATE_INFO
        ioctl_request['file_id'] = b"\xff" * 16

        val_neg = SMB2ValidateNegotiateInfoRequest()
        val_neg['capabilities'] = \
            self.session.connection.client_capabilities
        val_neg['guid'] = self.session.connection.client_guid
        val_neg['security_mode'] = \
            self.session.connection.client_security_mode
        val_neg['dialects'] = \
            self.session.connection.negotiated_dialects

        ioctl_request['buffer'] = val_neg
        ioctl_request['max_output_response'] = len(val_neg)
        ioctl_request['flags'] = IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL
        log.info("%s - Sending Secure Negotiate Validation message"
                 % log_header)
        log.debug(str(ioctl_request))
        request = self.session.connection.send(ioctl_request,
                                               sid=self.session.session_id,
                                               tid=self.tree_connect_id)

        log.info("%s - Receiving secure negotiation response" % log_header)
        response = self.session.connection.receive(request)
        ioctl_resp = SMB2IOCTLResponse()
        ioctl_resp.unpack(response['data'].get_value())
        log.debug(str(ioctl_resp))

        log.info("%s - Unpacking secure negotiate response info" % log_header)
        val_resp = SMB2ValidateNegotiateInfoResponse()
        val_resp.unpack(ioctl_resp['buffer'].get_value())
        log.debug(str(val_resp))

        self._verify("server capabilities",
                     val_resp['capabilities'].get_value(),
                     self.session.connection.server_capabilities.get_value())
        self._verify("server guid",
                     val_resp['guid'].get_value(),
                     self.session.connection.server_guid)
        self._verify("server security mode",
                     val_resp['security_mode'].get_value(),
                     self.session.connection.server_security_mode)
        self._verify("server dialect",
                     val_resp['dialect'].get_value(),
                     self.session.connection.dialect)
        log.info("Session: %d, Tree: %d - Secure negotiate complete"
                 % (self.session.session_id, self.tree_connect_id))

    def _verify(self, check, actual, expected):
        log_header = "Session: %d, Tree: %d"\
                     % (self.session.session_id, self.tree_connect_id)
        if actual != expected:
            raise SMBException("%s - Secure negotiate failed to verify %s, "
                               "Actual: %s, Expected: %s"
                               % (log_header, check, actual, expected))
