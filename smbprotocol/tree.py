import logging

from smbprotocol.messages import SMB2TreeConnectRequest, \
    SMB2TreeConnectResponse, SMB2IOCTLRequest, SMB2IOCTLResponse, \
    SMB2ValidateNegotiateInfoRequest, SMB2ValidateNegotiateInfoResponse
from smbprotocol.constants import Commands, Dialects, ShareCapabilities,\
    ShareFlags, IOCTLFlags, CtlCode, NtStatus

log = logging.getLogger(__name__)


class TreeConnect(object):

    def __init__(self, session):
        """
        [MS-SMB2] v53.0 2017-09-15

        3.2.1.4 Per Tree Connect
        Attributes per Tree Connect (share connections)
        """
        self.share_name = None
        self.tree_connect_id = None
        self.session = session
        self.is_dfs_share = None

        # SMB 3.x+
        self.is_ca_share = None
        self.encrypt_data = None
        self.is_scaleout_share = None

    def connect(self, share_name, require_secure_negotiate=True):
        log.info("Session: %d - Creating connection to share %s"
                 % (self.session.session_id, share_name))
        utf_share_name = share_name.encode('utf-16-le')
        connect = SMB2TreeConnectRequest()
        connect['path_offset'] = 64 + 8
        connect['path_length'] = len(utf_share_name)
        connect['buffer'] = utf_share_name

        log.info("Session: %d - Sending Tree Connect message"
                 % self.session.session_id)
        log.debug(str(connect))
        self.session.connection.send(connect, Commands.SMB2_TREE_CONNECT,
                                     self.session)

        log.info("Session: %d - Receiving Tree Connect response"
                 % self.session.session_id)
        response = self.session.connection.receive()
        tree_response = SMB2TreeConnectResponse()
        tree_response.unpack(response['data'].get_value())
        log.debug(str(tree_response))

        # https://msdn.microsoft.com/en-us/library/cc246687.aspx
        self.tree_connect_id = response['tree_id'].get_value()
        log.info("Session: %d - Created tree connection with ID %d"
                 % (self.session.session_id, self.tree_connect_id))
        self.session.tree_connect_table[self.tree_connect_id] = self

        capabilities = tree_response['capabilities'].get_value()
        self.is_dfs_share = capabilities & \
            ShareCapabilities.SMB2_SHARE_CAP_DFS == \
            ShareCapabilities.SMB2_SHARE_CAP_DFS
        self.is_ca_share = capabilities & \
            ShareCapabilities.SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY == \
            ShareCapabilities.SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY
        self.share_name = utf_share_name

        dialect = self.session.connection.dialect
        if dialect >= Dialects.SMB_3_0_0 and \
                self.session.connection.supports_encryption:
            self.encrypt_data = tree_response['share_flags'].get_value() & \
                                ShareFlags.SMB2_SHAREFLAG_ENCRYPT_DATA == \
                                ShareFlags.SMB2_SHAREFLAG_ENCRYPT_DATA

            scaleout_bit = ShareCapabilities.SMB2_SHARE_CAP_SCALEOUT
            self.is_scaleout_share = capabilities & scaleout_bit == \
                scaleout_bit

            if dialect < Dialects.SMB_3_1_1 and require_secure_negotiate:
                self._verify_dialect_negotiate()

    def _verify_dialect_negotiate(self):
        log.info("Session: %d, Tree: %d - Running secure negotiate "
                 "process" % (self.session.session_id,
                              self.tree_connect_id))
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
        log.info("Session: %d, Tree: %d = Sending Secure Negotiate "
                 "Validation message" % (self.session.session_id,
                                         self.tree_connect_id))
        log.debug(str(ioctl_request))
        log.debug(str(val_neg))
        self.session.connection.send(ioctl_request,
                                     Commands.SMB2_IOCTL, self.session,
                                     self)
        response = self.session.connection.receive()
        log.info("Session: %s, Tree: %d - Receiving secure negotiation "
                 "response"
                 % (self.session.session_id, self.tree_connect_id))

        ioctl_resp = SMB2IOCTLResponse()
        ioctl_resp.unpack(response['data'].get_value())
        log.debug(str(ioctl_resp))
        val_resp = SMB2ValidateNegotiateInfoResponse()
        val_resp.unpack(ioctl_resp['buffer'].get_value())
        log.debug(str(val_resp))

        if val_resp['capabilities'].get_value() != \
                self.session.connection.server_capabilities:
            raise Exception("Invalid capabilities")
        if val_resp['guid'].get_value() != \
                self.session.connection.server_guid:
            raise Exception("Invalid server guid")
        if val_resp['security_mode'].get_value() != \
                self.session.connection.server_security_mode:
            raise Exception("Invalid server security mode")
        if val_resp['dialect'].get_value() != self.session.connection.dialect:
            raise Exception("Invalid server dialect")
        log.info("Session: %d, Tree: %d - Secure negotiate complete"
                 % (self.session.session_id, self.tree_connect_id))
