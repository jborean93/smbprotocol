# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import logging
from collections import OrderedDict

from smbprotocol import Dialects
from smbprotocol.exceptions import (
    FileClosed,
    InvalidDeviceRequest,
    NotSupported,
    SMBException,
)
from smbprotocol.header import Commands
from smbprotocol.ioctl import (
    CtlCode,
    IOCTLFlags,
    SMB2IOCTLRequest,
    SMB2IOCTLResponse,
    SMB2ValidateNegotiateInfoRequest,
    SMB2ValidateNegotiateInfoResponse,
)
from smbprotocol.structure import BytesField, EnumField, FlagField, IntField, Structure

log = logging.getLogger(__name__)


class TreeFlags:
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.9 SMB2 TREE_CONNECT Response Flags
    Flags used in SMB 3.1.1  to indicate how to process the operation.
    """

    SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT = 0x0004
    SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER = 0x0002
    SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT = 0x0001


class ShareType:
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.10 SMB2 TREE_CONNECT Response Capabilities
    The type of share being accessed
    """

    SMB2_SHARE_TYPE_DISK = 0x01
    SMB2_SHARE_TYPE_PIPE = 0x02
    SMB2_SHARE_TYPE_PRINT = 0x03


class ShareFlags:
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


class ShareCapabilities:
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
        self.fields = OrderedDict(
            [
                ("structure_size", IntField(size=2, default=9)),
                (
                    "flags",
                    FlagField(
                        size=2,
                        flag_type=TreeFlags,
                    ),
                ),
                (
                    "path_offset",
                    IntField(
                        size=2,
                        default=64 + 8,
                    ),
                ),
                (
                    "path_length",
                    IntField(
                        size=2,
                        default=lambda s: len(s["buffer"]),
                    ),
                ),
                ("buffer", BytesField(size=lambda s: s["path_length"].get_value())),
            ]
        )
        super().__init__()


class SMB2TreeConnectResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.10 SMB2 TREE_CONNECT Response
    Sent by the server when an SMB2 TREE_CONNECT request is processed
    successfully.
    """

    COMMAND = Commands.SMB2_TREE_CONNECT

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("structure_size", IntField(size=2, default=16)),
                (
                    "share_type",
                    EnumField(
                        size=1,
                        enum_type=ShareType,
                    ),
                ),
                ("reserved", IntField(size=1)),
                (
                    "share_flags",
                    FlagField(
                        size=4,
                        flag_type=ShareFlags,
                    ),
                ),
                (
                    "capabilities",
                    FlagField(
                        size=4,
                        flag_type=ShareCapabilities,
                    ),
                ),
                ("maximal_access", IntField(size=4)),
            ]
        )
        super().__init__()


class SMB2TreeDisconnect(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.11/12 SMB2 TREE_DISCONNECT Request and Response
    Sent by the client to request that the tree connect specific by tree_id in
    the header is disconnected.
    """

    COMMAND = Commands.SMB2_TREE_DISCONNECT

    def __init__(self):
        self.fields = OrderedDict(
            [
                (
                    "structure_size",
                    IntField(
                        size=2,
                        default=4,
                    ),
                ),
                ("reserved", IntField(size=2)),
            ]
        )
        super().__init__()


class TreeConnect:
    def __init__(self, session, share_name):
        """
        [MS-SMB2] v53.0 2017-09-15

        3.2.1.4 Per Tree Connect
        Attributes per Tree Connect (share connections)

        :param session: The Session to connect to the tree with.
        :param share_name: The name of the share, including the server name.
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
        log.info(f"Session: {self.session.username} - Creating connection to share {self.share_name}")
        utf_share_name = self.share_name.encode("utf-16-le")
        connect = SMB2TreeConnectRequest()
        connect["buffer"] = utf_share_name

        log.info("Session: %s - Sending Tree Connect message", self.session.username)
        log.debug(connect)
        request = self.session.connection.send(connect, sid=self.session.session_id)

        log.info("Session: %s - Receiving Tree Connect response", self.session.username)
        response = self.session.connection.receive(request)
        tree_response = SMB2TreeConnectResponse()
        tree_response.unpack(response["data"].get_value())
        log.debug(tree_response)

        # https://msdn.microsoft.com/en-us/library/cc246687.aspx
        self.tree_connect_id = response["tree_id"].get_value()
        log.info("Session: %s - Created tree connection with ID %d", self.session.username, self.tree_connect_id)
        self._connected = True
        self.session.tree_connect_table[self.tree_connect_id] = self

        capabilities = tree_response["capabilities"]
        self.is_dfs_share = capabilities.has_flag(ShareCapabilities.SMB2_SHARE_CAP_DFS)
        self.is_ca_share = capabilities.has_flag(ShareCapabilities.SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY)

        dialect = self.session.connection.dialect
        if dialect >= Dialects.SMB_3_0_0 and self.session.connection.supports_encryption:
            self.encrypt_data = tree_response["share_flags"].has_flag(ShareFlags.SMB2_SHAREFLAG_ENCRYPT_DATA)

            self.is_scaleout_share = capabilities.has_flag(ShareCapabilities.SMB2_SHARE_CAP_SCALEOUT)

        if require_secure_negotiate:
            self._verify_dialect_negotiate()

    def disconnect(self):
        """
        Disconnects the tree connection.
        """
        if not self._connected:
            return

        log.info(f"Session: {self.session.username}, Tree: {self.share_name} - Disconnecting from Tree Connect")

        req = SMB2TreeDisconnect()
        log.info(f"Session: {self.session.username}, Tree: {self.share_name} - Sending Tree Disconnect message")
        log.debug(req)
        request = self.session.connection.send(req, sid=self.session.session_id, tid=self.tree_connect_id)

        log.info(f"Session: {self.session.username}, Tree: {self.share_name} - Receiving Tree Disconnect response")
        res = self.session.connection.receive(request)
        res_disconnect = SMB2TreeDisconnect()
        res_disconnect.unpack(res["data"].get_value())
        log.debug(res_disconnect)
        self._connected = False
        del self.session.tree_connect_table[self.tree_connect_id]

    def _verify_dialect_negotiate(self):
        log_header = f"Session: {self.session.username}, Tree: {self.share_name}"
        log.info("%s - Running secure negotiate process", log_header)

        if not self.session.signing_key:
            # This will only happen if we authenticated with the guest or anonymous user.
            raise SMBException(
                "Cannot verify negotiate information without a session signing key. Authenticate with "
                "a non-guest or anonymous account or set require_secure_negotiate=False to disable the "
                "negotiation info verification checks."
            )

        dialect = self.session.connection.dialect
        if dialect >= Dialects.SMB_3_1_1:
            # SMB 3.1.1+ uses the negotiation info to generate the signing key so doesn't need this extra exchange.
            return

        ioctl_request = SMB2IOCTLRequest()
        ioctl_request["ctl_code"] = CtlCode.FSCTL_VALIDATE_NEGOTIATE_INFO
        ioctl_request["file_id"] = b"\xff" * 16

        val_neg = SMB2ValidateNegotiateInfoRequest()
        val_neg["capabilities"] = self.session.connection.client_capabilities
        val_neg["guid"] = self.session.connection.client_guid
        val_neg["security_mode"] = self.session.connection.client_security_mode
        val_neg["dialects"] = self.session.connection.negotiated_dialects

        ioctl_request["buffer"] = val_neg
        ioctl_request["max_output_response"] = len(val_neg)
        ioctl_request["flags"] = IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL
        log.info("%s - Sending Secure Negotiate Validation message", log_header)
        log.debug(ioctl_request)
        request = self.session.connection.send(
            ioctl_request, sid=self.session.session_id, tid=self.tree_connect_id, force_signature=True
        )

        log.info("%s - Receiving secure negotiation response", log_header)
        try:
            response = self.session.connection.receive(request)

        except (FileClosed, InvalidDeviceRequest, NotSupported) as e:
            # https://docs.microsoft.com/en-us/archive/blogs/openspecification/smb3-secure-dialect-negotiation
            # Older dialects may respond with these exceptions, this is expected and we only want to fail if
            # they are not signed. Check that header signature was signed, fail if it wasn't. The signature, if
            # present, would have been verified when the connection received the data.
            if e.header["signature"].get_value() == b"\x00" * 16:
                raise

            return

        # If we received an actual response we want to validate the info provided matches with what was negotiated.
        ioctl_resp = SMB2IOCTLResponse()
        ioctl_resp.unpack(response["data"].get_value())
        log.debug(ioctl_resp)

        log.info("%s - Unpacking secure negotiate response info", log_header)
        val_resp = SMB2ValidateNegotiateInfoResponse()
        val_resp.unpack(ioctl_resp["buffer"].get_value())
        log.debug(val_resp)

        self._verify(
            "server capabilities",
            val_resp["capabilities"].get_value(),
            self.session.connection.server_capabilities.get_value(),
        )
        self._verify("server guid", val_resp["guid"].get_value(), self.session.connection.server_guid)
        self._verify(
            "server security mode", val_resp["security_mode"].get_value(), self.session.connection.server_security_mode
        )
        self._verify("server dialect", val_resp["dialect"].get_value(), self.session.connection.dialect)
        log.info("Session: %d, Tree: %d - Secure negotiate complete", self.session.session_id, self.tree_connect_id)

    def _verify(self, check, actual, expected):
        if actual != expected:
            log_header = f"Session: {self.session.session_id}, Tree: {self.tree_connect_id}"
            raise SMBException(
                f"{log_header} - Secure negotiate failed to verify {check}, Actual: {actual}, Expected: {expected}",
            )
