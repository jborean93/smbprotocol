import base64
import hashlib
import hmac
import os
import uuid

from cryptography.hazmat.primitives import hashes, cmac
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, \
    KBKDFHMAC, Mode
from cryptography.hazmat.primitives.ciphers import aead, algorithms
from cryptography.hazmat.backends import default_backend

from datetime import datetime
from ntlm_auth.ntlm import Ntlm

from pyasn1.codec.der import decoder

from smbprotocol.messages import SMB2PacketHeader, SMB3PacketHeader, \
    SMB3NegotiateRequest, SMB2SessionSetupRequest, \
    SMB2PreauthIntegrityCapabilities, SMB2NegotiateContextRequest, \
    SMB1PacketHeader, SMB1NegotiateRequest, SMB2NegotiateResponse, \
    SMB2ErrorResponse, SMB2EncryptionCapabilities, SMB2NegotiateRequest, \
    SMB2SessionSetupResponse, SMB2TransformHeader, SMB2TreeConnectRequest,\
    SMB2TreeConnectResponse
from smbprotocol.constants import Command, SecurityMode, Dialects,\
    HashAlgorithms, NegotiateContextType, Capabilities, Smb1Flags2, NtStatus, \
    Ciphers, Smb2Flags, SessionFlags, TreeFlags, ShareCapabilities, \
    ShareFlags, ShareType
from smbprotocol.spnego import InitialContextToken, MechTypes
from smbprotocol.transport.direct_tcp import DirectTcp


class Client(object):
    def __init__(self, dialect=None, require_secure_negotiate=True,
                 require_message_signging=True):
        """
        ﻿[MS-SMB2] v53.0 2017-09-15

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
        self.require_message_signing = require_message_signging

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
        ﻿[MS-SMB2] v53.0 2017-09-15

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

    def open_file(self):
        pass

    def open_directory(self):
        pass

    def open_named_pipe(self):
        pass


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

        # Not in docs but contains some attributes used below like guid
        self.server = None

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
        self.transport.connect()

    def negotiate(self, dialect=None):
        """
        ﻿[MS-SMB2] v53.0 2017-09-15

        3.2.4.2.2 Negotiating the Protocol
        Will negotiate the capabilities with the server, it does this by
        sending an SMB1 negotiate message then finally an SMB2 negotiate
        message.
        """
        smb_response = self._send_smb1_negotiate()

        # Renegotiate with SMB2NegotiateRequest if 2.??? was received back
        if smb_response['dialect_revision'].get_value() == \
                Dialects.SMB_2_WILDCARD:
            smb_response = self._send_smb2_negotiate()

        self.dialect = smb_response['dialect_revision'].get_value()
        self.max_transact_size = smb_response['max_transact_size'].get_value()
        self.max_read_size = smb_response['max_read_size'].get_value()
        self.max_write_size = smb_response['max_write_size'].get_value()
        self.server_guid = smb_response['server_guid'].get_value()
        self.gss_negotiate_token = smb_response['buffer'].get_value()

        self.require_signing = self._flag_is_set(
            smb_response['security_mode'].get_value(),
            SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED)
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

    def send_message(self, message, command, session=None):
        # if we haven't negotiated the dialect use SMB2
        if command == Command.SMB2_NEGOTIATE:
            header = SMB2PacketHeader()
        elif self.dialect < Dialects.SMB_3_0_0:
            header = SMB2PacketHeader()
        else:
            header = SMB3PacketHeader()

        header['command'] = command
        header['data'] = message

        if session:
            header['session_id'] = session.session_id
        else:
            header['session_id'] = 0

        # TODO: pass through the message id to cancel
        message_id = 0
        if command != Command.SMB2_CANCEL:
            message_id = self.sequence_window['low']
            self._increment_sequence_windows(1)

        header['message_id'] = message_id

        if session and session.encrypt_data:
            header = self.encrypt_message(header, session)
        elif session and session.signing_required:
            self.sign_message(header, session)

        # ﻿https://msdn.microsoft.com/en-us/library/cc246611.aspx
        # ﻿Encrypt the message
        # https://msdn.microsoft.com/en-us/library/hh880620.aspx

        request = PendingRequest(header)
        self.outstanding_requests[message_id] = request
        self.transport.send(request)
        return header

    def receive_message(self, expected_status=NtStatus.STATUS_SUCCESS):
        # 3.2.5.1 - Receiving Any Message
        response = self.transport.recv()
        message = self.decrypt_message(response)

        self.verify_message_signature(message)

        # TODO: handle session reauth on STATUS_NETWORK_SESSION_EXPIRED

        if message['status'].get_value() != expected_status:
            error_message = self._parse_error(message)
            raise Exception("Unexpected status returned from the server: %s"
                            % error_message)

        del self.outstanding_requests[message['message_id'].get_value()]

        return message

    def encrypt_message(self, message, session):
        """
        [MS-SMB2] v53.0 2017-09-15

        3.1.4.3 Encrypting the Message

        :param message: The message to encrypt
        :return: The encrypted message in a SMB2 TRANSFORM_HEADER
        """
        # https://msdn.microsoft.com/en-us/library/jj906475.aspx

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

    def decrypt_message(self, message):
        """
        [MS-SMB2] v53.0 2017-09-15

        3.2.5.1.1 Decrypting the Message
        This will decrypt the message and convert the raw bytes value returned
        by direct_tcp to a SMB Header structure

        :param message: The message to decrypt
        :return: The decrypted message
        """
        if self.dialect is None or self.dialect < Dialects.SMB_3_0_0:
            header = SMB2PacketHeader()
            header.unpack(message)
            return header

        protocol_id = message[:4]
        if protocol_id != b"\xfdSMB":
            header = SMB2PacketHeader()
            header.unpack(message)
            return header

        header = SMB2TransformHeader()
        header.unpack(message)
        if header['flags'].get_value() != 0x0001:
            raise Exception("Expecting flag of 0x0001 in SMB response header")

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
        header['data'] = b""

        c = cipher(session.decryption_key)
        decrypted_message = c.decrypt(nonce, enc_message, header.pack()[20:])

        packet = SMB2PacketHeader()
        packet.unpack(decrypted_message)

        return packet

    def verify_message_signature(self, message):
        """
        [MS-SMB2] v53.0 2017-09-15

        3.2.5.1.3 Verifying the Signature
        Will verify the signature of the message if required, called when the
        message is not encrypted as that covers integrity checks.

        :param message: The message to verify the signature with
        """
        if message['message_id'].get_value() == 0xFFFFFFFFFFFFFFFF:
            return
        elif message['flags'].get_value() & Smb2Flags.SMB2_FLAGS_SIGNED == 0:
            return
        elif message['command'].get_value() == Command.SMB2_SESSION_SETUP:
            return

        session_id = message['session_id'].get_value()
        session = self.session_table.get(session_id, None)
        if session is None:
            raise Exception("Failed to find session %d for message "
                            "verification" % session_id)
        self.verify_signature(message, session)

    def sign_message(self, message, session):
        signing_key = session.signing_key
        message['flags'] = message['flags'].get_value() | \
            Smb2Flags.SMB2_FLAGS_SIGNED
        if self.dialect >= Dialects.SMB_3_0_0:
            c = cmac.CMAC(algorithms.AES(signing_key),
                          backend=default_backend())
            c.update(message.pack())
            signature = c.finalize()
        else:
            hmac_algo = hmac.new(signing_key, msg=message.pack(),
                                 digestmod=hashlib.sha256)
            signature = hmac_algo.digest()[:16]
        message['signature'] = signature

    def verify_signature(self, message, session):
        actual = message['signature'].get_value()
        message['signature'] = b"\x00" * 16

        if self.dialect >= Dialects.SMB_3_0_0:
            # TODO: work out when to get channel.signing_key
            signing_key = session.signing_key

            c = cmac.CMAC(algorithms.AES(signing_key),
                          backend=default_backend())
            c.update(message.pack())
            expected = c.finalize()
        else:
            signing_key = session.signing_key
            hmac_algo = hmac.new(signing_key, msg=message.pack(),
                                 digestmod=hashlib.sha256)
            expected = hmac_algo.digest()[:16]
        message['signature'] = actual

        if actual != expected:
            raise Exception("Server message signature could not be verified: "
                            "%s != %s" % (actual, expected))

    def _send_smb1_negotiate(self):
        header = SMB1PacketHeader()
        header['command'] = 0x72  # SMBv1 Negotiate Protocol
        header['flags2'] = Smb1Flags2.SMB_FLAGS2_LONG_NAME | \
            Smb1Flags2.SMB_FLAGS2_EXTENDED_SECURITY | \
            Smb1Flags2.SMB_FLAGS2_NT_STATUS | \
            Smb1Flags2.SMB_FLAGS2_UNICODE
        header['data'] = SMB1NegotiateRequest()
        dialects = b"\x02SMB 2.002\x00"
        if self.dialect != Dialects.SMB_2_0_2:
            dialects += b"\x02SMB 2.???\x00"
        header['data']['dialects'] = dialects
        request = PendingRequest(header)

        self.transport.send(request)

        self._increment_sequence_windows(1)
        response = self.transport.recv()
        header = SMB2PacketHeader()
        header.unpack(response)
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
            # remove extra padding for last list entry
            enc_cap['padding'].size = 0
            enc_cap['padding'] = b""

            neg_req['negotiate_context_list'] = [
                int_cap,
                enc_cap
            ]

        header = self.send_message(neg_req, Command.SMB2_NEGOTIATE)
        self.preauth_integrity_hash_value.append(header)

        response = self.receive_message()
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


class Session(object):

    def __init__(self, connection, username, password):
        """
        ﻿[MS-SMB2] v53.0 2017-09-15

        3.2.1.3 Per Session
        List of attributes that are set per session
        """
        self.session_id = None

        # Table of tree connection, lookup by TreeConnect.tree_connect_id and
        # by share_name
        self.tree_connect_table = {}

        # First 16 bytes of the cryptographic key for this authenticated
        # context, right-padded with 0 bytes
        self.session_key = None

        self.signing_required = connection.require_signing
        self.connection = connection
        self.username = username
        self.password = password

        # Table of OpenFile, lookup by OpenFile.file_id
        self.open_table = {}

        # SMB 3.x+
        # List of Channel
        self.channel_list = []

        # 16-bit identifier incremented on a network disconnect that indicates
        # to the server the client's Channel change
        self.channel_sequence = None

        self.encrypt_data = None
        self.encryption_key = None
        self.decryption_key = None
        self.signing_key = None
        self.application_key = None

        # SMB 3.1.1+
        # Preauth integrity value computed for the exhange of SMB2
        # SESSION_SETUP request and response for this session
        self.preauth_integrity_hash_value = \
            connection.preauth_integrity_hash_value

    def authenticate(self):
        token, rdata = decoder.decode(self.connection.gss_negotiate_token,
                                      asn1Spec=InitialContextToken())

        # TODO: Add support for Kerberos
        client_types = {
            MechTypes.NTLMSSP: self._authenticate_ntlm
        }
        server_types = token['innerContextToken']['negTokenInit']['mechTypes']
        auth_method = None
        for type in server_types:
            if type in client_types:
                auth_method = client_types[type]
                break

        if auth_method is None:
            raise Exception("SPNEGO authentication failed, client does not "
                            "support any server auth options")

        response, session_key = auth_method()
        setup_response = SMB2SessionSetupResponse()
        setup_response.unpack(response['data'].get_value())
        if self.connection.dialect >= Dialects.SMB_3_1_1:
            if response['flags'].get_value() & Smb2Flags.SMB2_FLAGS_SIGNED != \
                    Smb2Flags.SMB2_FLAGS_SIGNED:
                raise Exception("SMB2_FLAGS_SIGNED must be set in SMB2 "
                                "SESSION_SETUP Response when on Dialect 3.1.1")

        # TODO: remove from preauth session table and move to session_table
        self.connection.session_table[self.session_id] = self

        # session_key is the first 16 bytes, left padded 0 if less than 16
        if len(session_key) < 16:
            session_key += b"\x00" * (16 - len(session_key))
        self.session_key = session_key[:16]

        if self.connection.dialect >= Dialects.SMB_3_1_1:
            preauth_hash = b"\x00" * 64
            hash_al = self.connection.preauth_integrity_hash_id
            for message in self.preauth_integrity_hash_value:
                preauth_hash = hash_al(preauth_hash + message.pack()).digest()

            self.signing_key = self._smb3kdf(self.session_key,
                                             b"SMBSigningKey\x00",
                                             preauth_hash)
            self.application_key = self._smb3kdf(self.session_key,
                                                 b"SMBAppKey\x00",
                                                 preauth_hash)
            self.encryption_key = self._smb3kdf(self.session_key,
                                                b"SMBC2SCipherKey\x00",
                                                preauth_hash)
            self.decryption_key = self._smb3kdf(self.session_key,
                                                b"SMBS2CCipherKey\x00",
                                                preauth_hash)
        elif self.connection.dialect >= Dialects.SMB_3_0_0:
            self.signing_key = self._smb3kdf(self.session_key,
                                             b"SMB2AESCMAC\x00",
                                             b"SmbSign\x00")
            self.application_key = self._smb3kdf(self.session_key,
                                                 b"SMB2APP\x00", b"SmbRpc\x00")
            self.encryption_key = self._smb3kdf(self.session_key,
                                                b"SMB2AESCCM\x00",
                                                b"ServerIn \x00")
            self.decryption_key = self._smb3kdf(self.session_key,
                                                b"SMB2AESCCM\x00",
                                                b"ServerOut\x00")
        else:
            self.signing_key = self.session_key
            self.application_key = self.session_key

        flags = setup_response['session_flags'].get_value()
        if flags & SessionFlags.SMB2_SESSION_FLAG_IS_GUEST == 0 and \
                self.signing_required:
            raise Exception("SMB Signing is required but could only auth as "
                            "guest")
        if flags & SessionFlags.SMB2_SESSION_FLAG_ENCRYPT_DATA == \
                SessionFlags.SMB2_SESSION_FLAG_ENCRYPT_DATA:
            self.encrypt_data = True
            self.signing_required = False  # encryption covers signing
        else:
            self.encrypt_data = False
            self.signing_required = True

        self.connection.verify_signature(response, self)

    def send_message(self, message, command):
        session = self if self.session_id is not None else None
        return self.connection.send_message(message, command, session)

    def receive_message(self, expected_status=NtStatus.STATUS_SUCCESS):
        return self.connection.receive_message(expected_status)

    def _authenticate_ntlm(self):
        auth = Ntlm()
        try:
            domain, username = self.username.split("\\", 1)
        except ValueError:
            username = self.username
            domain = ''

        neg_message = auth.create_negotiate_message(domain)

        session_setup = SMB2SessionSetupRequest()
        session_setup['security_mode'] = self.connection.client_security_mode
        session_setup['buffer'] = base64.b64decode(neg_message)

        header = self.send_message(session_setup, Command.SMB2_SESSION_SETUP)
        self.preauth_integrity_hash_value.append(header)

        response = self.receive_message(
            NtStatus.STATUS_MORE_PROCESSING_REQUIRED)
        self.preauth_integrity_hash_value.append(response)

        self.session_id = response['session_id'].get_value()

        session_resp = SMB2SessionSetupResponse()
        session_resp.unpack(response['data'].get_value())

        auth.parse_challenge_message(base64.b64encode(
            session_resp['buffer'].get_value()
        ))
        auth_message = auth.create_authenticate_message(username,
                                                        self.password, domain)
        session_auth = SMB2SessionSetupRequest()
        session_auth['security_mode'] = self.connection.client_security_mode
        session_auth['buffer'] = base64.b64decode(auth_message)

        header = self.send_message(session_auth, Command.SMB2_SESSION_SETUP)
        self.preauth_integrity_hash_value.append(header)
        response = self.receive_message()

        session_key = auth.authenticate_message.exported_session_key

        return response, session_key

    def _smb3kdf(self, ki, label, context):
        """
        See SMB 3.x key derivation function
        https://blogs.msdn.microsoft.com/openspecification/2017/05/26/smb-2-and-smb-3-security-in-windows-10-the-anatomy-of-signing-and-cryptographic-keys/

        :param ki: The session key is the KDK used as an input to the KDF
        :param label: The purpose of this derived key as bytes string
        :param context: The context information of this derived key as bytes
        string
        :return: Key derived by the KDF as specified by [SP800-108] 5.1
        """
        kdf = KBKDFHMAC(
            algorithm=hashes.SHA256(),
            mode=Mode.CounterMode,
            length=16,
            rlen=4,
            llen=4,
            location=CounterLocation.BeforeFixed,
            label=label,
            context=context,
            fixed=None,
            backend=default_backend()
        )
        return kdf.derive(ki)


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

    def connect(self, share_name):
        utf_share_name = share_name.encode('utf-16-le')
        connect = SMB2TreeConnectRequest()
        connect['path_offset'] = 64 + 8
        connect['path_length'] = len(utf_share_name)
        connect['buffer'] = utf_share_name

        self.session.send_message(connect, Command.SMB2_TREE_CONNECT)
        response = self.session.receive_message()
        tree_response = SMB2TreeConnectResponse()
        tree_response.unpack(response['data'].get_value())

        # https://msdn.microsoft.com/en-us/library/cc246687.aspx

        self.tree_connect_id = response['tree_id'].get_value()

        capabilites = tree_response['capabilities'].get_value()
        self.is_dfs_share = capabilites & \
            ShareCapabilities.SMB2_SHARE_CAP_DFS == \
            ShareCapabilities.SMB2_SHARE_CAP_DFS
        self.is_ca_share = capabilites & \
            ShareCapabilities.SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY == \
            ShareCapabilities.SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY
        self.share_name = utf_share_name

        if self.session.connection.dialect >= Dialects.SMB_3_1_1 and \
                self.session.connection.supports_encryption:
            self.encrypt_data = tree_response['share_flags'].get_value() & \
                ShareFlags.SMB2_SHAREFLAG_ENCRYPT_DATA == \
                ShareFlags.SMB2_SHAREFLAG_ENCRYPT_DATA

        # TODO: Run Secure Negotiate

        a = ""


class OpenFile(object):

    def __init__(self):
        """
        [MS-SMB2] v53.0 2017-09-15

        3.2.1.5 Per Open File
        For SMB 2.1+, for each opened file (distinguished by name), attributes
        for that open object
        """
        # Table of Opens to this file
        self.open_table = {}

        self.lease_key = None
        self.lease_state = None

        # SMB 3.x+
        # A squence number stored by the client to track lease state changes
        self.lease_epoch = None


class ApplicationOpenFile(object):

    def __init__(self):
        """
        ﻿[MS-SMB2] v53.0 2017-09-15

        3.2.1.6 Per Application Open of a File
        Attributes per each open of a file of an application
        """
        self.file_id = None
        self.tree_connect = None
        self.connection = None
        self.oplocal_level = None
        self.durable = None
        self.file_name = None
        self.resilient_handle = None
        self.last_disconnect_time = None
        self.resilient_timeout = None
        self.operation_buckets = None

        # SMB 3.x+
        self.durable_timeout = None

        # Table of outstanding requests, lookup by Request.cancel_id,
        # message_id
        self.outstanding_requests = {}

        self.create_guid = None
        self.is_persistent = None
        self.desired_access = None
        self.share_mode = None
        self.create_options = None
        self.file_attributes = None
        self.create_disposition = None


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


class Channel(object):

    def __init__(self):
        """
        ﻿[MS-SMB2] v53.0 2017-09-15

        3.2.1.8 Per Channel
        If SMB 3.x+ is used, attributes per channel
        """
        self.signing_key = None
        self.connection = None


class Server(object):

    def __init__(self, server_guid, dialect_revision, capabilities,
                 security_mode, address_list, server_name):
        """
        ﻿[MS-SMB2] v53.0 2017-09-15

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


client = Client()
client.open_connection('\\\\127.0.0.1\\c$', 'vagrant', 'vagrant', port=8445)
