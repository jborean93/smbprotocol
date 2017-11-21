import base64
import hashlib
import os
import uuid

from ntlm_auth.ntlm import Ntlm

from pyasn1.codec.der import decoder

from smbprotocol.messages import SMB2PacketHeader, SMB3PacketHeader, \
    SMB3NegotiateRequest, SMB2SessionSetupRequest, \
    SMB2PreauthIntegrityCapabilities, SMB2NegotiateContextRequest, \
    SMB1PacketHeader, SMB1NegotiateRequest, SMB2NegotiateResponse, \
    SMB2ErrorResponse, SMB2EncryptionCapabilities, SMB2NegotiateRequest, \
    SMB2SessionSetupResponse
from smbprotocol.constants import Command, SecurityMode, Dialects,\
    HashAlgorithms, NegotiateContextType, Capabilities, Smb1Flags2, NtStatus, \
    Ciphers
from smbprotocol.spnego import InitialContextToken, MechTypes
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

    def __init__(self, client_guid, server_name, dialect="Unknown",
                 require_message_signing=True):
        # Input values
        self.require_message_signing = require_message_signing

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
        # TODO: Actually set what we can do
        self.client_capabilities = \
            Capabilities.SMB2_GLOBAL_CAP_LEASING |\
            Capabilities.SMB2_GLOBAL_CAP_MTU |\
            Capabilities.SMB2_GLOBAL_CAP_DIRECTORY_LEASING |\
            Capabilities.SMB2_GLOBAL_CAP_ENCRYPTION
        self.server_capabilities = None

        if self.require_message_signing:
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
        header['data'] = SMB1NegotiateRequest()
        header['data']['dialects'] = b"\x02SMB 2.002\x00" \
                                     b"\x02SMB 2.???\x00"

        self.transport.send(header)
        response = self.transport.recv()

        smb_response = SMB2NegotiateResponse()
        smb_response.unpack(response['data'].get_value())

        # Renegotiate with an SMB2NegotiateRequest if 2.??? was received back
        if smb_response['dialect_revision'].get_value() == \
                Dialects.SMB_2_WILDCARD:
            self._increment_sequence_windows(1)
            header = self._negotiate_smb2()
            self.transport.send(header)
            response = self.transport.recv()

            if response['status'].value != NtStatus.STATUS_SUCCESS:
                error_message = self._parse_error(response)
                raise Exception("Failed to negotiate SMB session: %s"
                                % error_message)

            smb_response = SMB2NegotiateResponse()
            smb_response.unpack(response['data'].get_value())

        # set connection values from negotiate response
        self.dialect = smb_response['dialect_revision'].get_value()
        self.max_transact_size = smb_response['max_transact_size'].get_value()
        self.max_read_size = smb_response['max_read_size'].get_value()
        self.max_write_size = smb_response['max_read_size'].get_value()
        self.server_guid = smb_response['server_guid'].get_value()
        self.gss_negotiate_token = smb_response['buffer'].get_value()

        self.require_signing = smb_response['security_mode'].get_value() & \
            SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED
        capabilities = smb_response['capabilities'].get_value()

        # SMB 2.1
        if self.dialect >= Dialects.SMB_2_1_0:
            self.supports_file_leasing = \
                capabilities & Capabilities.SMB2_GLOBAL_CAP_LEASING
            self.supports_multi_credit = \
                capabilities & Capabilities.SMB2_GLOBAL_CAP_MTU

        # SMB 3.x
        if self.dialect >= Dialects.SMB_3_0_0:
            self.supports_directory_leasing = capabilities & \
                Capabilities.SMB2_GLOBAL_CAP_DIRECTORY_LEASING
            self.supports_multi_channel = capabilities & \
                Capabilities.SMB2_GLOBAL_CAP_MULTI_CHANNEL

            # TODO: SMB2_GLOBAL_CAP_PERSISTENT_HANDLES
            self.supports_persistent_handles = False
            self.supports_encryption = capabilities & \
                Capabilities.SMB2_GLOBAL_CAP_ENCRYPTION and \
                self.dialect < Dialects.SMB_3_1_1
            self.server_capabilities = capabilities
            self.server_security_mode = \
                smb_response['security_mode'].get_value()

            # TODO: Check/add server to server_list in Client Page 203

        # SMB 3.1
        if self.dialect >= Dialects.SMB_3_1_1:
            for context in smb_response['negotiate_context_list']:
                # TODO: Better validation of values
                if context['context_type'].get_value() == \
                        NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES:
                    self.cipher_id = context['data']['ciphers'][0]
                    self.supports_encryption = self.cipher_id != 0
                else:
                    self.preauth_integrity_hash_id = \
                        context['data']['hash_algorithms'][0]

            # better validation around what hashing function to use
            hash = hashlib.sha512
            hash_value = b"\x00" * 64
            hash_value = hash_value + header.pack()
            hash_value = hash(hash_value).digest()

            hash_value = hash_value + response.pack()
            hash_value = hash(hash_value).digest()

            self.preauth_integrity_hash_value = hash_value

        token, rdata = decoder.decode(smb_response['buffer'].get_value(),
                                      asn1Spec=InitialContextToken())

        # TODO: Add support for Kerberos
        client_types = {
            MechTypes.NTLMSSP: self._ntlm_auth
        }
        server_types = token['innerContextToken']['negTokenInit']['mechTypes']
        auth_method = None
        for type, method in client_types.items():
            if type in server_types:
                auth_method = method
                break

        if auth_method is None:
            raise Exception("SPNEGO authentication failed, client does not "
                            "support any server auth options")

        self._increment_sequence_windows(1)
        auth_method()
        a = ""

    def _ntlm_auth(self):
        ntlm_client = Ntlm()
        neg_message = ntlm_client.create_negotiate_message("JORDAN")

        # This doesn't work currently just sending the sec buffer natively
        # neg_init = NegTokenInit()
        # neg_init['mechTypes'].append(MechTypes.NTLMSSP)
        # neg_init['mechToken'] = base64.b64decode(neg_message)

        session_setup = SMB2SessionSetupRequest()
        session_setup['security_mode'] = self.client_security_mode
        # session_setup['buffer'] = encoder.encode(neg_init)
        session_setup['buffer'] = base64.b64decode(neg_message)

        header = SMB3PacketHeader()
        header['command'] = Command.SMB2_SESSION_SETUP
        header['message_id'] = self.sequence_window['low']
        header['data'] = session_setup

        self.transport.send(header)
        response = self.transport.recv()

        if response['status'].get_value() != \
                NtStatus.STATUS_MORE_PROCESSING_REQUIRED:
            error_message = self._parse_error(response)
            raise Exception("Failed to negotiate SMB ntlm auth, expecting "
                            "more processing required response: %s" %
                            error_message)

        session_resp = SMB2SessionSetupResponse()
        session_resp.unpack(response['data'].get_value())
        ntlm_client.parse_challenge_message(
            base64.b64encode(session_resp['buffer'].get_value()))
        auth_message = ntlm_client.create_authenticate_message(
            "Administrator", "Password02", "JORDAN")

        session_auth = SMB2SessionSetupRequest()
        session_auth['security_mode'] = self.client_security_mode
        session_auth['buffer'] = base64.b64decode(auth_message)

        self._increment_sequence_windows(1)
        header = SMB3PacketHeader()
        header['command'] = Command.SMB2_SESSION_SETUP
        header['message_id'] = self.sequence_window['low']
        header['data'] = session_auth
        header['session_id'] = response['session_id'].get_value()

        self.transport.send(header)
        response = self.transport.recv()
        if response['status'].get_value() != NtStatus.STATUS_SUCCESS:
            error_message = self._parse_error(response)
            raise Exception("Failed to authenticate SMB auth: %s"
                            % error_message)

    def _negotiate_smb2(self):
        self.salt = os.urandom(32)

        if self.dialect == "Unknown":
            neg_req = SMB3NegotiateRequest()
            neg_req['dialects'] = [
                Dialects.SMB_2_0_2,
                Dialects.SMB_2_1_0,
                Dialects.SMB_3_0_0,
                Dialects.SMB_3_0_2,
                Dialects.SMB_3_1_1
            ]
            highest_dialect = Dialects.SMB_3_1_1
        else:
            if self.dialect >= Dialects.SMB_3_1_1:
                neg_req = SMB3NegotiateRequest()
            else:
                neg_req = SMB2NegotiateRequest()
            neg_req['dialects'] = [
                self.dialect
            ]
            highest_dialect = self.dialect

        neg_req['security_mode'] = self.client_security_mode

        if highest_dialect >= Dialects.SMB_2_1_0:
            neg_req['client_guid'] = self.client_guid

        if highest_dialect >= Dialects.SMB_3_0_0:
            neg_req['capabilities'] = self.client_capabilities

        if highest_dialect >= Dialects.SMB_3_1_1:
            int_cap = SMB2NegotiateContextRequest()
            int_cap['context_type'] = \
                NegotiateContextType.SMB2_PREAUTH_INTEGRITY_CAPABILITIES
            int_cap['data'] = SMB2PreauthIntegrityCapabilities()
            int_cap['data']['hash_algorithms'] = [
                HashAlgorithms.SHA_512
            ]
            int_cap['data']['salt'] = self.salt

            enc_cap = SMB2NegotiateContextRequest()
            enc_cap['context_type'] = \
                NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES
            enc_cap['data'] = SMB2EncryptionCapabilities()
            enc_cap['data']['ciphers'] = [
                Ciphers.AES_128_GCM,
                Ciphers.AES_128_CCM
            ]

            neg_req['negotiate_context_list'] = [
                int_cap,
                enc_cap
            ]

        header = SMB2PacketHeader()
        header['command'] = Command.SMB2_NEGOTIATE
        header['message_id'] = self.sequence_window['low']
        header['data'] = neg_req

        return header

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
