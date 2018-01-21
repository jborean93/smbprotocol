import base64
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
from smbprotocol.spnego import InitialContextToken, MechTypes, ObjectIdentifier
from smbprotocol.structure import _bytes_to_hex

HAVE_SSPI = False  # TODO: add support for Windows and SSPI
HAVE_GSSAPI = False
try:
    import gssapi
    # Needed to get the session key for signing and encryption
    from gssapi.raw import inquire_sec_context_by_oid
    HAVE_GSSAPI = True
except ImportError:
    pass

log = logging.getLogger(__name__)


class Session(object):

    def __init__(self, connection, username, password):
        """
        [MS-SMB2] v53.0 2017-09-15

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
        log.debug("Decoding SPNEGO token containing supported auth mechanisms")
        token, rdata = decoder.decode(self.connection.gss_negotiate_token,
                                      asn1Spec=InitialContextToken())
        server_mechs = list(
            token['innerContextToken']['negTokenInit']['mechTypes']
        )
        if MechTypes.MS_KRB5 in server_mechs and MechTypes.KRB5:
            log.debug("Both MS_KRB5 and KRB5 received in the initial SPNGEO "
                      "token, removing MS_KRB5 to avoid duplication of work")
            server_mechs.remove(MechTypes.MS_KRB5)

        # loop through the Mechs until we get a successful auth
        response = session_key = None
        errors = {}
        for mech in server_mechs:
            mech_key = "Unknown (%s)" % str(mech)
            for name, value in vars(MechTypes).items():
                if isinstance(value, ObjectIdentifier) and value == mech:
                    mech_key = "%s (%s)" % (name, str(value))
                    break

            log.info("Attempting auth with mech %s" % mech_key)
            try:
                response, session_key = self._setup_session(mech)
                break
            except Exception as exc:
                log.warning("Failed auth for mech %s: %s"
                            % (mech_key, str(exc)))
                errors[str(mech_key)] = str(exc)
                pass

        if response is None:
            raise Exception("Failed to authenticated with server: %s"
                            % str(errors))

        log.info("Setting session id to %s" % self.session_id)
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
        self.connection._verify(response, True)

    def _setup_session(self, mech):
        if mech in [MechTypes.KRB5, MechTypes.MS_KRB5] and HAVE_GSSAPI:
            context = GSSAPIContext(username=self.username,
                                    password=self.password,
                                    server=self.connection.server_name)
        elif mech in [MechTypes.KRB5, MechTypes.MS_KRB5, MechTypes.NTLMSSP] \
                and HAVE_SSPI:
            raise NotImplementedError("SSPI on Windows for authentication is "
                                      "not yet implemented")
        elif mech == MechTypes.NTLMSSP:
            context = NtlmContext(username=self.username,
                                  password=self.password)
        else:
            raise NotImplementedError("Mech Type %s is not yet supported"
                                      % mech)

        for out_token in context.step():
            session_setup = SMB2SessionSetupRequest()
            session_setup['security_mode'] = \
                self.connection.client_security_mode
            session_setup['buffer'] = out_token

            log.info("Sending SMB2_SESSION_SETUP request message")
            header = self.connection.send(session_setup,
                                          Commands.SMB2_SESSION_SETUP, self)
            self.preauth_integrity_hash_value.append(header)

            log.info("Receiving SMB2_SESSION_SETUP response message")
            response = self.connection.receive(expected_status=[
                NtStatus.STATUS_SUCCESS,
                NtStatus.STATUS_MORE_PROCESSING_REQUIRED
            ])

            self.session_id = response['session_id'].get_value()
            session_resp = SMB2SessionSetupResponse()
            session_resp.unpack(response['data'].get_value())

            context.in_token = session_resp['buffer'].get_value()
            status = response['status'].get_value()
            if status == NtStatus.STATUS_MORE_PROCESSING_REQUIRED:
                log.info("More processing is required for SMB2_SESSION_SETUP")
                self.preauth_integrity_hash_value.append(response)

        # Once the context is established, we need the session key which is
        # used to derive the signing and sealing keys for SMB
        session_key = context.get_session_key()

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


class NtlmContext(object):

    def __init__(self, username, password):
        # try and get the domain part from the username
        log.info("Setting up NTLM Security Context for user %s" % username)
        try:
            self.domain, self.username = username.split("\\", 1)
        except ValueError:
            self.username = username
            self.domain = ''
        self.password = password
        self.context = Ntlm()
        self.in_token = None

    def step(self):
        log.info("NTLM: Generating Negotiate message")
        msg1 = self.context.create_negotiate_message(self.domain)
        msg1 = base64.b64decode(msg1)
        log.debug("NTLM: Negotiate message: %s" % _bytes_to_hex(msg1))
        yield msg1

        log.info("NTLM: Parsing Challenge message")
        msg2 = base64.b64encode(self.in_token)
        log.debug("NTLM: Challenge message: %s" % _bytes_to_hex(self.in_token))
        self.context.parse_challenge_message(msg2)

        log.info("NTLM: Generating Authenticate message")
        msg3 = self.context.create_authenticate_message(
            user_name=self.username,
            password=self.password,
            domain_name=self.domain
        )
        yield base64.b64decode(msg3)

    def get_session_key(self):
        return self.context.authenticate_message.exported_session_key


class GSSAPIContext(object):

    def __init__(self, username, password, server):
        log.info("Setting up GSSAPI Security Context for Kerberos auth")
        self.creds = self._acquire_creds(username, password)

        server_spn = "cifs@%s" % server
        log.debug("GSSAPI Server SPN Target: %s" % server_spn)
        server_name = gssapi.Name(base=server_spn,
                                  name_type=gssapi.NameType.hostbased_service)
        self.context = gssapi.SecurityContext(name=server_name,
                                              creds=self.creds,
                                              usage='initiate')
        self.in_token = None

    def step(self):
        while not self.context.complete:
            log.info("GSSAPI: gss_init_sec_context called")
            out_token = self.context.step(self.in_token)
            if out_token:
                yield out_token
            else:
                log.info("GSSAPI: gss_init_sec_context complete")

    def get_session_key(self):
        # GSS_C_INQ_SSPI_SESSION_KEY
        session_key_oid = gssapi.OID.from_int_seq("1.2.840.113554.1.2.2.5.5")
        context_data = gssapi.raw.inquire_sec_context_by_oid(self.context,
                                                             session_key_oid)

        return context_data[0]

    def _acquire_creds(self, username, password):
        # 3 use cases with Kerberos AUth
        #   1. Both the user and pass is supplied so we want to create a new
        #      ticket with the pass
        #   2. Only the user is supplied so we will attempt to get the cred
        #      from the existing store
        #   3. The user is not supplied so we will attempt to get the default
        #      cred from the existing store
        log.info("GSSAPI: Acquiring credentials handle")
        if username and password:
            log.debug("GSSAPI: Acquiring credentials handle for user %s with "
                      "password" % username)
            user = gssapi.Name(base=username,
                               name_type=gssapi.NameType.user)
            bpass = password.encode('utf-8')
            try:
                creds = gssapi.raw.acquire_cred_with_password(user, bpass,
                                                              usage='initiate')
            except AttributeError:
                raise Exception("Cannot get GSSAPI credential with password as"
                                " the necessary GSSAPI extensions are not "
                                "available")
            except gssapi.exceptions.GSSError as er:
                raise Exception("Failed to acquire GSSAPI credential with "
                                "password: %s" % str(er))
            # acquire_cred_with_password returns a wrapper, we want the creds
            # object inside this wrapper
            creds = creds.creds
        elif username:
            log.debug("GSSAPI: Acquiring credentials handle for user %s from "
                      "existing cache" % username)
            user = gssapi.Name(base=username,
                               name_type=gssapi.NameType.user)

            try:
                creds = gssapi.Credentials(name=user, usage='initiate')
            except gssapi.exceptions.MissingCredentialsError as er:
                raise Exception("Failed to acquire GSSAPI credential for user "
                                "%s from the exisiting cache: %s"
                                % (str(user), str(er)))
        else:
            log.debug("GSSAPI: Acquiring credentials handle for default user "
                      "in cache")
            try:
                creds = gssapi.Credentials(name=None, usage='initiate')
            except gssapi.exceptions.GSSError as er:
                raise Exception("Failed to acquire default GSSAPI credential "
                                "from the existing cache: %s" % str(er))
            user = creds.name

        log.info("GSSAPI: Acquired credentials for user %s" % str(user))
        return creds


class Channel(object):

    def __init__(self):
        """
        [MS-SMB2] v53.0 2017-09-15

        3.2.1.8 Per Channel
        If SMB 3.x+ is used, attributes per channel
        """
        self.signing_key = None
        self.connection = None
