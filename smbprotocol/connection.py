import copy
import logging
import hashlib
import hmac
import os

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import aead, algorithms
from cryptography.hazmat.backends import default_backend
from datetime import datetime

from smbprotocol.constants import Capabilities, Ciphers, Commands, Dialects, \
    HashAlgorithms, NegotiateContextType, NtStatus, SecurityMode, Smb1Flags2, \
    Smb2Flags
from smbprotocol.messages import SMB2PacketHeader, SMB3PacketHeader, \
    SMB3NegotiateRequest, \
    SMB2PreauthIntegrityCapabilities, SMB2NegotiateContextRequest, \
    SMB1PacketHeader, SMB1NegotiateRequest, SMB2NegotiateResponse, \
    SMB2ErrorResponse, SMB2EncryptionCapabilities, SMB2NegotiateRequest, \
    SMB2TransformHeader
from smbprotocol.session import Session
from smbprotocol.transport.direct_tcp import DirectTcp

log = logging.getLogger(__name__)


class Connection(object):

    def __init__(self, guid, signing_required, server_name, port):
        """
        ﻿[MS-SMB2] v53.0 2017-09-15

        3.2.1.2 Per SMB2 Transport Connection
        Used as the transport interface for a server. Some values have been
        omitted as they can be retrieved by the Server object stored in
        self.server

        :param guid: The client guid generated in Client
        :param ﻿signing_required: Whether signing is required on SMB messages
        :param server_name: The server to start the connection
        :param port: The port to use for the transport
        """
        log.info("Initialising connection, guid: %s, signing_required: %s, "
                 "server_name: %s, port: %d"
                 % (guid, signing_required, server_name, port))
        self.server_name = server_name
        self.port = port
        self.transport = DirectTcp(server_name, port)

        # Table of Session entries
        self.session_table = {}

        # Table of sessions that have not completed authentication, indexed by
        # session_id
        self.preauth_session_table = {}

        # Table of Requests awaiting a response, indexed by Request.cancel_id
        # and message_id
        self.outstanding_requests = {}

        # Table of available sequence numbers
        self.sequence_window = {
            'low': 0,
            'high': 0
        }

        # Byte array containing the negotiate token and remembered for
        # authentication
        self.gss_negotiate_token = None

        self.server_guid = None
        self.max_transact_size = None
        self.max_read_size = None
        self.max_write_size = None
        self.require_signing = None

        # SMB 2.1+
        self.dialect = None
        self.supports_file_leasing = None
        self.supports_multi_credit = None
        self.client_guid = guid

        # SMB 3.x+
        self.supports_directory_leasing = None
        self.supports_multi_channel = None
        self.supports_persistent_handles = None
        self.supports_encryption = None

        # TODO: Add more capabilities
        self.client_capabilities = Capabilities.SMB2_GLOBAL_CAP_ENCRYPTION
        self.client_security_mode = \
            SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED if \
            signing_required else SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        self.server_security_mode = None
        self.server_capabilities = None

        # SMB 3.1.1+
        # The hashing algorithm object that was negotiated
        self.preauth_integrity_hash_id = None

        # Preauth integrity hash value computed for the SMB2 NEGOTIATE request
        # contains the messages used to compute the hash
        self.preauth_integrity_hash_value = []

        # The cipher object that was negotiated
        self.cipher_id = None

    def connect(self):
        """
        ﻿﻿[MS-SMB2] v53.0 2017-09-15

        3.2.4.2.1 Connecting to the Target Server
        Will connect to the target server using the connection specified.
        """
        log.info("Setting up transport connection")
        self.transport.connect()

    def negotiate(self, dialect=None):
        """
        ﻿[MS-SMB2] v53.0 2017-09-15

        3.2.4.2.2 Negotiating the Protocol
        Will negotiate the capabilities with the server, it does this by
        sending an SMB1 negotiate message then finally an SMB2 negotiate
        message.
        """
        log.info("Starting negotiation with SMB server")
        smb_response = self._send_smb1_negotiate(dialect)

        # Renegotiate with SMB2NegotiateRequest if 2.??? was received back
        if smb_response['dialect_revision'].get_value() == \
                Dialects.SMB_2_WILDCARD:
            smb_response = self._send_smb2_negotiate()

        log.info("Negotiated dialect: %s"
                 % [dialect for dialect, v in vars(Dialects).items()
                    if v == smb_response['dialect_revision'].get_value()][0])
        self.dialect = smb_response['dialect_revision'].get_value()
        self.max_transact_size = smb_response['max_transact_size'].get_value()
        self.max_read_size = smb_response['max_read_size'].get_value()
        self.max_write_size = smb_response['max_write_size'].get_value()
        self.server_guid = smb_response['server_guid'].get_value()
        self.gss_negotiate_token = smb_response['buffer'].get_value()

        self.require_signing = self._flag_is_set(
            smb_response['security_mode'].get_value(),
            SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED)
        log.info("Connection require signing: %s" % self.require_signing)
        capabilities = smb_response['capabilities'].get_value()

        # SMB 2.1
        if self.dialect >= Dialects.SMB_2_1_0:
            self.supports_file_leasing = self._flag_is_set(
                capabilities, Capabilities.SMB2_GLOBAL_CAP_LEASING
            )
            self.supports_multi_credit = self._flag_is_set(
                capabilities, Capabilities.SMB2_GLOBAL_CAP_MTU
            )

        # SMB 3.x
        if self.dialect >= Dialects.SMB_3_0_0:
            self.supports_directory_leasing = self._flag_is_set(
                capabilities, Capabilities.SMB2_GLOBAL_CAP_DIRECTORY_LEASING
            )
            self.supports_multi_channel = self._flag_is_set(
                capabilities, Capabilities.SMB2_GLOBAL_CAP_MULTI_CHANNEL
            )

            # TODO: SMB2_GLOBAL_CAP_PERSISTENT_HANDLES
            self.supports_persistent_handles = False
            self.supports_encryption = self._flag_is_set(
                capabilities, Capabilities.SMB2_GLOBAL_CAP_ENCRYPTION
            ) and self.dialect < Dialects.SMB_3_1_1
            self.server_capabilities = capabilities
            self.server_security_mode = \
                smb_response['security_mode'].get_value()

            # TODO: Check/add server to server_list in Client Page 203

        # SMB 3.1
        if self.dialect >= Dialects.SMB_3_1_1:
            for context in smb_response['negotiate_context_list']:
                if context['context_type'].get_value() == \
                        NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES:
                    cipher_id = context['data']['ciphers'][0]
                    self.cipher_id = Ciphers.get_cipher(cipher_id)
                    self.supports_encryption = self.cipher_id != 0
                else:
                    hash_id = context['data']['hash_algorithms'][0]
                    self.preauth_integrity_hash_id = \
                        HashAlgorithms.get_algorithm(hash_id)

    def create_session(self, username, password):
        session = Session(self, username, password)
        session.authenticate()

        return session

    def send(self, message, command, session=None, tree=None):
        """
        Sends a message
        :return:
        """
        if command == Commands.SMB2_NEGOTIATE:
            header = SMB2PacketHeader()
        elif self.dialect < Dialects.SMB_3_0_0:
            header = SMB2PacketHeader()
        else:
            header = SMB3PacketHeader()

        header['command'] = command
        header['data'] = message

        if session:
            header['session_id'] = session.session_id
        if tree:
            header['tree_id'] = tree.tree_connect_id

        # TODO: pass through the message id to cancel
        message_id = 0
        if command != Commands.SMB2_CANCEL:
            message_id = self.sequence_window['low']
            self._increment_sequence_windows(1)

        header['message_id'] = message_id

        if session and session.encrypt_data and session.encryption_key:
            header = self._encrypt(header, session)
        elif session and session.signing_required and session.signing_key:
            self._sign(header, message)

        request = PendingRequest(header)
        self.outstanding_requests[message_id] = request
        self.transport.send(request)
        return header

    def receive(self, expected_status=NtStatus.STATUS_SUCCESS):
        """
        # 3.2.5.1 - Receiving Any Message
        :return:
        """
        message = self.transport.recv()
        if self.dialect is None or self.dialect < Dialects.SMB_3_0_0 or \
                message[:4] != b"\xfdSMB":
            header = SMB2PacketHeader()
            header.unpack(message)
        else:
            header = self._decrypt(message)
        self._verify(header)

        if header['status'].get_value() != expected_status:
            error_message = self._parse_error(header)
            raise Exception("Unexpected status returned from the server: %s"
                            % error_message)

        del self.outstanding_requests[header['message_id'].get_value()]

        return header

    def _sign(self, message, session):
        message['flags'] = message['flags'].get_value() | \
            Smb2Flags.SMB2_FLAGS_SIGNED
        signature = self._generate_signature(message, session)
        message['signature'] = signature

    def _verify(self, message):
        if message['message_id'].get_value() == 0xFFFFFFFFFFFFFFFF:
            return
        elif message['flags'].get_value() & Smb2Flags.SMB2_FLAGS_SIGNED == 0:
            return
        elif message['command'].get_value() == Commands.SMB2_SESSION_SETUP:
            return

        session_id = message['session_id'].get_value()
        session = self.session_table.get(session_id, None)
        if session is None:
            raise Exception("Failed to find session %d for message "
                            "verification" % session_id)
        expected = self._generate_signature(message, session)
        actual = message['signature'].get_value()
        if actual != expected:
            raise Exception("Server message signature could not be verified: "
                            "%s != %s" % (actual, expected))

    def _generate_signature(self, message, session):
        msg = copy.deepcopy(message)
        msg['signature'] = b"\x00" * 16
        msg_data = msg.pack()

        if self.dialect >= Dialects.SMB_3_0_0:
            # TODO: work out when to get channel.signing_key
            signing_key = session.signing_key

            c = cmac.CMAC(algorithms.AES(signing_key),
                          backend=default_backend())
            c.update(msg_data)
            signature = c.finalize()
        else:
            signing_key = session.signing_key
            hmac_algo = hmac.new(signing_key, msg=msg_data,
                                 digestmod=hashlib.sha256)
            signature = hmac_algo.digest()[:16]

        return signature

    def _encrypt(self, message, session):
        """
        [MS-SMB2] v53.0 2017-09-15

        3.1.4.3 Encrypting the Message
        Encrypts the message usinig the encryption keys negotiated with.

        :param message: The message to encrypt
        :param session: The session associated with the message
        :return: The encrypted message in a SMB2 TRANSFORM_HEADER
        """

        header = SMB2TransformHeader()
        header['original_message_size'] = len(message)
        header['session_id'] = message['session_id'].get_value()

        encryption_key = session.encryption_key
        if self.dialect >= Dialects.SMB_3_1_1:
            cipher = self.cipher_id
        else:
            cipher = Ciphers.get_cipher(Ciphers.AES_128_CCM)
        if cipher == aead.AESGCM:
            nonce = os.urandom(12)
            header['nonce'] = nonce + (b"\x00" * 4)
        else:
            nonce = os.urandom(11)
            header['nonce'] = nonce + (b"\x00" * 5)

        cipher_text = cipher(encryption_key).encrypt(nonce, message.pack(),
                                                     header.pack()[20:])
        signature = cipher_text[-16:]
        enc_message = cipher_text[:-16]

        header['signature'] = signature
        header['data'] = enc_message

        return header

    def _decrypt(self, message):
        """
        [MS-SMB2] v53.0 2017-09-15

        3.2.5.1.1 Decrypting the Message
        This will decrypt the message and convert the raw bytes value returned
        by direct_tcp to a SMB Header structure

        :param message: The message to decrypt
        :return: The decrypted message including the header
        """
        header = SMB2TransformHeader()
        header.unpack(message)

        if header['flags'].get_value() != 0x0001:
            raise Exception("Expecting flag of 0x0001 in SMB Transform Header "
                            "Response")

        session_id = header['session_id'].get_value()
        session = self.session_table.get(session_id, None)
        if session is None:
            raise Exception("Failed to find session %s for message decryption"
                            % session_id)

        if self.dialect >= Dialects.SMB_3_1_1:
            cipher = self.cipher_id
        else:
            cipher = Ciphers.get_cipher(Ciphers.AES_128_CCM)

        if cipher == aead.AESGCM:
            nonce = header['nonce'].get_value()[:12]
        else:
            nonce = header['nonce'].get_value()[:11]

        signature = header['signature'].get_value()
        enc_message = header['data'].get_value() + signature

        c = cipher(session.decryption_key)
        decrypted_message = c.decrypt(nonce, enc_message, header.pack()[20:52])

        packet = SMB2PacketHeader()
        packet.unpack(decrypted_message)

        return packet

    def _send_smb1_negotiate(self, dialect):
        header = SMB1PacketHeader()
        header['command'] = 0x72  # SMBv1 Negotiate Protocol
        header['flags2'] = Smb1Flags2.SMB_FLAGS2_LONG_NAME | \
            Smb1Flags2.SMB_FLAGS2_EXTENDED_SECURITY | \
            Smb1Flags2.SMB_FLAGS2_NT_STATUS | \
            Smb1Flags2.SMB_FLAGS2_UNICODE
        header['data'] = SMB1NegotiateRequest()
        dialects = b"\x02SMB 2.002\x00"
        if dialect != Dialects.SMB_2_0_2:
            dialects += b"\x02SMB 2.???\x00"
        header['data']['dialects'] = dialects
        request = PendingRequest(header)

        log.info("Sending SMB1 Negotiate message with dialects: %s" % dialects)
        log.debug(str(header))
        self.transport.send(request)

        self._increment_sequence_windows(1)
        response = self.transport.recv()
        log.info("Receiving SMB1 Negotiate response")
        header = SMB2PacketHeader()
        header.unpack(response)
        log.debug(str(header))
        smb_response = SMB2NegotiateResponse()
        try:
            smb_response.unpack(header['data'].get_value())
        except Exception as exc:
            raise Exception("Expecting SMB2NegotiateResponse message type in "
                            "response but could not unpack data: %s"
                            % str(exc))

        return smb_response

    def _send_smb2_negotiate(self):
        self.salt = os.urandom(32)

        if self.dialect is None:
            neg_req = SMB3NegotiateRequest()
            self.negotiated_dialects = [
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
            self.negotiated_dialects = [
                self.dialect
            ]
            highest_dialect = self.dialect
        neg_req['dialects'] = self.negotiated_dialects
        log.info("Negotiating with SMB2 protocol with highest client dialect "
                 "of: %s" % [dialect for dialect, v in vars(Dialects).items()
                             if v == highest_dialect][0])

        neg_req['security_mode'] = self.client_security_mode

        if highest_dialect >= Dialects.SMB_2_1_0:
            log.debug("Adding client guid %s to negotiate request"
                      % self.client_guid)
            neg_req['client_guid'] = self.client_guid

        if highest_dialect >= Dialects.SMB_3_0_0:
            log.debug("Adding client capabilities %d to negotiate request"
                      % self.client_capabilities)
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
            log.debug("Adding preauth integrity capabilities of hash SHA512 "
                      "and salt %s to negotiate request" % self.salt)

            enc_cap = SMB2NegotiateContextRequest()
            enc_cap['context_type'] = \
                NegotiateContextType.SMB2_ENCRYPTION_CAPABILITIES
            enc_cap['data'] = SMB2EncryptionCapabilities()
            enc_cap['data']['ciphers'] = [
                Ciphers.AES_128_GCM,
                Ciphers.AES_128_CCM
            ]
            # remove extra padding for last list entry
            enc_cap['padding'].size = 0
            enc_cap['padding'] = b""
            log.debug("Adding encryption capabilities of AES128 GCM and "
                      "AES128 CCM to negotiate request")

            neg_req['negotiate_context_list'] = [
                int_cap,
                enc_cap
            ]

        log.info("Sending SMB2 Negotiate message")
        log.debug(str(neg_req))
        header = self.send(neg_req, Commands.SMB2_NEGOTIATE)
        self.preauth_integrity_hash_value.append(header)

        response = self.receive()
        log.info("Receiving SMB2 Negotiate response")
        log.debug(str(response))
        self.preauth_integrity_hash_value.append(response)

        smb_response = SMB2NegotiateResponse()
        smb_response.unpack(response['data'].get_value())

        return smb_response

    def _increment_sequence_windows(self, credits):
        self.sequence_window['low'] = self.sequence_window['high'] + credits
        self.sequence_window['high'] += credits

    def _flag_is_set(self, value, flag):
        return value & flag == flag

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


class PendingRequest(object):

    def __init__(self, message):
        """
        ﻿[MS-SMB2] v53.0 2017-09-15

        3.2.1.7 Per Pending Request
        For each request that was sent to the server and is await a response
        :param message: The message to be sent in the request
        """
        self.cancel_id = os.urandom(8)
        self.async_id = os.urandom(8)
        self.message = message
        self.timestamp = datetime.now()
