import base64
import binascii
import logging

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, \
    KBKDFHMAC, Mode
from cryptography.hazmat.backends import default_backend
from ntlm_auth.ntlm import Ntlm
from pyasn1.codec.der import decoder

from smbprotocol.messages import SMB2SessionSetupRequest, \
    SMB2SessionSetupResponse
from smbprotocol.constants import Commands, Dialects, NtStatus, SessionFlags, \
    Smb2Flags
from smbprotocol.spnego import InitialContextToken, MechTypes

log = logging.getLogger(__name__)


class Session(object):

    def __init__(self, connection, username, password):
        """
        ﻿[MS-SMB2] v53.0 2017-09-15

        3.2.1.3 Per Session
        List of attributes that are set per session
        """
        log.info("Initialising session with username: %s" % username)
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
        log.info("Authenticating session")
        token, rdata = decoder.decode(self.connection.gss_negotiate_token,
                                      asn1Spec=InitialContextToken())

        # TODO: Add support for Kerberos
        client_types = {
            MechTypes.NTLMSSP: self._authenticate_ntlm
        }
        server_types = token['innerContextToken']['negTokenInit']['mechTypes']
        auth_method = None
        for type in server_types:
            log.debug("Checking if server mechType %s is supported by the "
                      "client" % type)
            if type in client_types:
                log.info("Server mechType %s will be used for authentication"
                         % type)
                auth_method = client_types[type]
                break

        if auth_method is None:
            raise Exception("SPNEGO authentication failed, client does not "
                            "support any server auth options")

        response, session_key = auth_method()
        setup_response = SMB2SessionSetupResponse()
        setup_response.unpack(response['data'].get_value())
        if self.connection.dialect >= Dialects.SMB_3_1_1:
            if not response['flags'].has_flag(Smb2Flags.SMB2_FLAGS_SIGNED):
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

        flags = setup_response['session_flags']
        if flags.has_flag(SessionFlags.SMB2_SESSION_FLAG_IS_GUEST) \
                and self.signing_required:
            raise Exception("SMB Signing is required but could only auth as "
                            "guest")
        if flags.has_flag(SessionFlags.SMB2_SESSION_FLAG_ENCRYPT_DATA):
            self.encrypt_data = True
            self.signing_required = False  # encryption covers signing
        else:
            self.encrypt_data = False
            self.signing_required = True
        log.info("Verifying the SMB Setup Session signature as auth is "
                 "successful")
        self.connection._verify(response)

    def _authenticate_ntlm(self):
        auth = Ntlm()
        try:
            domain, username = self.username.split("\\", 1)
        except ValueError:
            username = self.username
            domain = ''

        log.info("NTLM: creating negotiate message")
        neg_message = base64.b64decode(auth.create_negotiate_message(domain))
        log.debug("NTLM NEGOTIATE: %s" % binascii.hexlify(neg_message))

        session_setup = SMB2SessionSetupRequest()
        session_setup['security_mode'] = self.connection.client_security_mode
        session_setup['buffer'] = neg_message

        log.info("NTLM: sending negoitate message")
        log.debug(str(session_setup))
        header = self.connection.send(session_setup,
                                      Commands.SMB2_SESSION_SETUP)
        self.preauth_integrity_hash_value.append(header)

        response = self.connection.receive(
            NtStatus.STATUS_MORE_PROCESSING_REQUIRED)
        log.info("NTLM: receiving challenge message")
        self.preauth_integrity_hash_value.append(response)

        self.session_id = response['session_id'].get_value()
        log.info("Setting session id to %s" % self.session_id)

        session_resp = SMB2SessionSetupResponse()
        session_resp.unpack(response['data'].get_value())
        log.debug(str(session_resp))

        challenge_msg = session_resp['buffer'].get_value()
        log.info("NTLM parsing challenge message")
        log.debug("NTLM CHALLENGE: %s" % binascii.hexlify(challenge_msg))
        auth.parse_challenge_message(base64.b64encode(challenge_msg))

        log.info("NTLM creating authentication message")
        auth_message = base64.b64decode(
            auth.create_authenticate_message(username, self.password, domain)
        )

        session_auth = SMB2SessionSetupRequest()
        session_auth['security_mode'] = self.connection.client_security_mode
        session_auth['buffer'] = auth_message

        log.info("NTLM: sending authentication message")
        header = self.connection.send(session_auth,
                                      Commands.SMB2_SESSION_SETUP, self)
        self.preauth_integrity_hash_value.append(header)
        response = self.connection.receive()
        log.info("NTLM: receiving authentication response")

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


class Channel(object):

    def __init__(self):
        """
        ﻿[MS-SMB2] v53.0 2017-09-15

        3.2.1.8 Per Channel
        If SMB 3.x+ is used, attributes per channel
        """
        self.signing_key = None
        self.connection = None
