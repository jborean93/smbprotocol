import os
import struct
import uuid

from smbprotocol.messages import SMB2PacketHeader, SMB3PacketHeader, \
    SMB3NegotiateRequest,\
    SMB2PreauthIntegrityCapabilities, SMB2NegotiateContextRequest, \
    SMB1PacketHeader, SMB1NegotiateRequest, SMB2NegotiateResponse, \
    SMB2ErrorResponse
from smbprotocol.constants import Command, SecurityMode, Dialects,\
    HashAlgorithms, NegotiateContextType, Capabilities, Smb1Flags2, NtStatus
from smbprotocol.transport.direct_tcp import DirectTcp


class Client(object):
    def __init__(self):
        self.connection_table = {}

        # SMB 2.1
        self.global_file_table = {}
        self.client_guid = uuid.uuid4()

        # SMB 3
        self.max_dialect = Dialects.SMB_3_1_1
        self.require_secure_negotiate = False
        self.server_list = []


class Connection(object):

    def __init__(self, client_guid, server_name, dialect="Unknown"):
        self.client_guid = client_guid

        self.session_table = {}
        self.preauth_session_table = {}
        self.outstanding_requests = {}
        self.sequence_window = {
            'low': 0,
            'high': 0
        }
        self.gss_negotiate_token = None
        self.max_transact_size = None
        self.max_read_size = None
        self.max_write_size = None
        self.server_guid = None
        self.require_signing = False
        self.server_name = server_name

        # SMB 2.1
        self.dialect = dialect
        self.supports_file_leasing = None
        self.supports_multi_credit = None
        self.client_guid = client_guid

        # SMB 3.x
        self.supports_directory_leasing = None
        self.supports_multi_channel = None
        self.supports_persistent_handles = None
        self.supports_encryption = None
        self.client_capabilities = \
            Capabilities.SMB2_GLOBAL_CAP_DFS |\
            Capabilities.SMB2_GLOBAL_CAP_LEASING |\
            Capabilities.SMB2_GLOBAL_CAP_MTU |\
            Capabilities.SMB2_GLOBAL_CAP_DIRECTORY_LEASING |\
            Capabilities.SMB2_GLOBAL_CAP_ENCRYPTION
        self.server_capabilities = None
        if self.require_signing:
            self.client_security_mode = \
                SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED
        else:
            self.client_security_mode = \
                SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        self.server_security_mode = None
        self.server = None

        # SMB 3.1
        self.preauth_integrity_hash_id = None
        self.preauth_integrity_hash_value = None
        self.cipher_id = None

        # Not in documentation
        self.salt = None

        self.transport = DirectTcp(server_name)

    def negotiate(self):
        # While we don't support SMBv1, we need to send the first Negotiate
        # message over the SMB1 packet to see if SMB2 is supported
        header = SMB1PacketHeader()
        header['command'] = 0x72  # SMBv1 Negotiate Protocol
        header['flags2'] = Smb1Flags2.SMB_FLAGS2_LONG_NAME |\
            Smb1Flags2.SMB_FLAGS2_EXTENDED_SECURITY |\
            Smb1Flags2.SMB_FLAGS2_NT_STATUS |\
            Smb1Flags2.SMB_FLAGS2_UNICODE

        neg_req = SMB1NegotiateRequest()
        neg_req['dialects'] = b"\x02NT LM 0.12\x00" \
                              b"\x02SMB 2.002\x00" \
                              b"\x02SMB 2.???\x00"
        header['data'] = neg_req

        self.transport.send(header)
        response = self.transport.recv()

        smb_response = SMB2NegotiateResponse()
        smb_response.unpack(response['data'].get_value())

        if smb_response['dialect_revision'].value == Dialects.SMB_2_WILDCARD:
            self._increment_sequence_windows(1)
            smb_response = self._negotiate_smb2()

        self.max_transact_size = smb_response['max_transact_size'].value
        self.max_read_size = smb_response['max_read_size'].value
        self.max_write_size = smb_response['max_read_size'].value
        self.server_guid = smb_response['server_guid'].value
        self.gss_negotiate_token = smb_response['buffer'].value

        # SMB 2.1
        self.dialect = smb_response['dialect_revision'].value
        if smb_response['security_mode'].value & \
                SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED:
            self.require_signing = True
        else:
            self.require_signing = False
        capabilities = smb_response['capabilities'].value
        if capabilities & Capabilities.SMB2_GLOBAL_CAP_LEASING:
            self.supports_file_leasing = True
        else:
            self.supports_file_leasing = False
        if capabilities & Capabilities.SMB2_GLOBAL_CAP_MTU:
            self.supports_multi_credit = True
        else:
            self.supports_multi_credit = False

        # SMB 3.x
        if self.dialect >= Dialects.SMB_3_0_0:
            if capabilities & Capabilities.SMB2_GLOBAL_CAP_DIRECTORY_LEASING:
                self.supports_directory_leasing = True
            else:
                self.supports_directory_leasing = False
            if capabilities & Capabilities.SMB2_GLOBAL_CAP_MULTI_CHANNEL:
                self.supports_multi_channel = True
            else:
                self.supports_multi_channel = False
            # TODO: SMB2_GLOBAL_CAP_PERSISTENT_HANDLES
            if capabilities & Capabilities.SMB2_GLOBAL_CAP_ENCRYPTION and \
                    (self.dialect == Dialects.SMB_3_0_0 or
                        self.dialect == Dialects.SMB_3_0_2):
                self.supports_encryption = True
            else:
                self.supports_encryption = False
            self.server_capabilities = capabilities
            self.server_security_mode = smb_response['security_mode'].value

            # TODO: Check/add server to server_list in Client Page 203

        if self.dialect == Dialects.SMB_3_1_1:
            context_list = smb_response['negotiate_context_list'].value
            for context in context_list:
                a = ""

            self.preauth_integrity_hash_value = 0
            hash_algo = self.preauth_integrity_hash_id
            a = ""
        a = ""

    def _negotiate_smb2(self):
        self.salt = os.urandom(32)

        header = SMB3PacketHeader()
        header['command'] = Command.SMB2_NEGOTIATE
        header['message_id'] = self.sequence_window['low']

        neg_req = SMB3NegotiateRequest()

        if self.dialect == "Unknown":
            dialects = [
                Dialects.SMB_2_0_2,
                Dialects.SMB_2_1_0,
                Dialects.SMB_3_0_0,
                Dialects.SMB_3_0_2,
                Dialects.SMB_3_1_1
            ]
        else:
            dialects = [
                self.dialect
            ]
        neg_req['dialects'] = dialects

        neg_req['security_mode'] = self.client_security_mode
        neg_req['capabilities'] = self.client_capabilities
        neg_req['client_guid'] = self.client_guid

        if Dialects.SMB_3_1_1 in dialects:
            preauth_int = SMB2PreauthIntegrityCapabilities()
            preauth_int['hash_algorithms'] = [
                HashAlgorithms.SHA_512
            ]
            preauth_int['salt'] = self.salt

            neg_context = SMB2NegotiateContextRequest()
            neg_context['context_type'] = \
                NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES
            neg_context['data'] = preauth_int

            neg_req['negotiate_context_list'] = [
                neg_context
            ]

        header['data'] = neg_req
        self.transport.send(header)
        response = self.transport.recv()

        if response['status'].value != NtStatus.STATUS_SUCCESS:
            error_message = self._parse_error(response)
            raise Exception("Failed to negotiate SMB session: %s"
                            % error_message)

        smb_response = SMB2NegotiateResponse()
        smb_response.unpack(response['data'].value)

        return smb_response

    def _parse_error(self, data):
        error_code = data['status'].value
        error_message = "UNKNOWN"
        for msg, code in vars(NtStatus).items():
            if code == error_code:
                error_message = msg
                break
        error_message = "%s: %s" % (error_message, hex(error_code))

        error = SMB2ErrorResponse()
        error.unpack(data['data'].value)
        byte_count = error['byte_count'].value
        if byte_count != 0:
            # TODO: add code to handle this
            # error_data countains an array of these many entries
            a = ""
        return error_message

    def _increment_sequence_windows(self, credits):
        self.sequence_window['low'] = self.sequence_window['high'] + credits
        self.sequence_window['high'] += credits


class Session(object):

    def __init__(self):
        self.session_id = None
        self.tree_connect_table = {}
        self.session_key = None
        self.signing_required = None
        self.connection = None
        self.user_credentials = None
        self.open_table = {}
        self.channel_list = []
        self.channel_sequence = None
        self.encrypt_data = None
        self.encryption_key = None
        self.decryption_key = None
        self.signing_key = None
        self.application_key = None

        # SMB 3.1
        self.preauth_integrity_hash_value = None


class Server(object):

    def __init__(self, guid, dialect_revision, capabilities, security_mode,
                 address_list, server_name):
        self.guid = guid
        self.dialect_revision = dialect_revision
        self.capabilities = capabilities
        self.security_mode = security_mode
        self.address_list = address_list
        self.server_name = server_name


Connection(uuid.uuid4(), "192.168.56.155").negotiate()
