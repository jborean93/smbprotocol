# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import atexit
import logging
import ntpath
import uuid

from smbprotocol._text import to_text
from smbprotocol.connection import Capabilities, Connection
from smbprotocol.dfs import (
    DFSReferralEntryFlags,
    DFSReferralRequest,
    DFSReferralResponse,
    DomainEntry,
    ReferralEntry,
)
from smbprotocol.exceptions import (
    BadNetworkName,
    FSDriverRequired,
    InvalidParameter,
    ObjectPathNotFound,
)
from smbprotocol.ioctl import CtlCode, IOCTLFlags, SMB2IOCTLRequest, SMB2IOCTLResponse
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect

log = logging.getLogger(__name__)

_SMB_CONNECTIONS = {}


class _ConfigSingleton(type):
    __instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls.__instances:
            config = super().__call__(*args, **kwargs)
            cls.__instances[cls] = config

            # Needs to be done after the config instance is in the singleton dict due to setting this value will kick
            # off an IPC connection which then gets and instance of this config to see what the default creds are.
            # The property will not run the DFS request if the passed in value matches what is already there. Set
            # to None initially to ensure it detects a changed value.
            # https://github.com/jborean93/smbprotocol/issues/109
            dc_value = config.domain_controller
            config.domain_controller = None
            config.domain_controller = dc_value

        else:
            # Allow users to initialise and set multiple config options like ConfigType(key=value) even when the object
            # has been initialized already.
            config = cls.__instances[cls]
            config.set(**kwargs)

        return config


class ClientConfig(metaclass=_ConfigSingleton):
    """SMB Client global settings

    This class defines global settings for the client that affects all connections that the client makes. When setting
    the `domain_controller` config option, a DFS domain referral request is send to that hostname. It will use the
    credentials provided in the config if set.

    Attributes:
        client_guid (uuid.UUID): The client GUID used when creating a connection to the server.
        username (Optional[str]): Optional default username used when creating a new SMB session.
        password (Optional[str]): Optional default password used when creating a new SMB session.
        domain_controller (Optional[str]): The domain controller hostname. When set the config will send a DFS referral
            request to this hostname to populate the domain cache used for DFS connections or when connecting to
            `SYSVOL` or `NETLOGON`
        skip_dfs (bool): Whether to skip using any DFS referral checks and treat any path as a normal path. This is
            only useful if there are problems with the DFS resolver or you wish to avoid the extra round trip(s) the
            resolver requires.
        auth_protocol (str): The protocol to use for authentication. Possible values are 'negotiate', 'ntlm' or
            'kerberos'. Defaults to 'negotiate'.
        require_secure_negotiate (bool): Whether to verify the negotiated dialects and capabilities on the connection
            to a share to protect against MitM downgrade attacks..
    """

    def __init__(
        self,
        client_guid=None,
        username=None,
        password=None,
        domain_controller=None,
        skip_dfs=False,
        auth_protocol="negotiate",
        require_secure_negotiate=True,
        **kwargs,
    ):
        self.client_guid = client_guid or uuid.uuid4()
        self.username = username
        self.password = password
        self.skip_dfs = skip_dfs
        self.auth_protocol = auth_protocol
        self.require_secure_negotiate = require_secure_negotiate
        self._domain_controller: str | None = domain_controller
        self._domain_cache: list[DomainEntry] = []
        self._referral_cache: list[ReferralEntry] = []

    @property
    def domain_controller(self):
        return self._domain_controller

    @domain_controller.setter
    def domain_controller(self, value):
        """Setting the domain controller will try to get any DFS domain referrals for future lookups."""
        if self._domain_controller == value:
            return

        self._domain_controller = value
        self._domain_cache = []

        if not value or self.skip_dfs:
            return

        ipc_tree = get_smb_tree(rf"\\{value}\IPC$")[0]
        try:
            domain_referral_response = dfs_request(ipc_tree, "")
        except InvalidParameter:
            log.warning(
                "Specified domain controller %s return STATUS_INVALID_PARAMETER, cannot use as DFS domain "
                "cache source",
                value,
            )
            return

        for domain_referral in domain_referral_response["referral_entries"].get_value():
            if not domain_referral["referral_entry_flags"].has_flag(DFSReferralEntryFlags.NAME_LIST_REFERRAL):
                continue

            self._domain_cache.append(DomainEntry(domain_referral))

    def cache_referral(self, referral):
        if referral["number_of_referrals"].get_value() > 0:
            self._referral_cache.append(ReferralEntry(referral))

    def lookup_domain(self, domain_name: str) -> DomainEntry | None:
        # TODO: Check domain referral expiry and resend request if expired
        for domain in self._domain_cache:
            if domain.domain_name.lower() == ("\\" + domain_name.lower()):
                return domain

    def lookup_referral(self, path_components: list[str]) -> ReferralEntry | None:
        """Checks if the path exists in the DFS referral cache."""
        # A lookup in ReferralCache involves searching for an entry with DFSPathPrefix that is a complete prefix of the
        # path being looked up.
        self._clear_expired_cache()
        hits = []
        for referral in self._referral_cache:
            referral_path_components = [p for p in referral.dfs_path.split("\\") if p]
            for idx, referral_component in enumerate(referral_path_components):
                if idx >= len(path_components) or referral_component != path_components[idx]:
                    break

            else:
                hits.append(referral)

        if hits:
            # In the event of multiple matches, the longest match is used.
            hits.sort(key=lambda h: len(h.dfs_path), reverse=True)
            return hits[0]

    def set(self, **config):
        domain_controller = False
        for key, value in config.items():
            if key.startswith("_"):
                raise ValueError(f"Cannot set private attribute {key}")

            elif key == "domain_controller":
                # This must be set last in case we are setting any username/password used for a domain referral lookup.
                domain_controller = True

            else:
                setattr(self, key, value)

        # Make sure we set this last in case different credentials were specified in the config
        if domain_controller:
            self.domain_controller = config["domain_controller"]

    def _clear_expired_cache(self) -> None:
        self._referral_cache = [refferal for refferal in self._referral_cache if not refferal.is_expired]


def dfs_request(tree: TreeConnect, path: str) -> DFSReferralResponse:
    """Send a DFS Referral request to the IPC tree and return the referrals."""
    dfs_referral = DFSReferralRequest()
    dfs_referral["request_file_name"] = to_text(path)

    ioctl_req = SMB2IOCTLRequest()
    ioctl_req["ctl_code"] = CtlCode.FSCTL_DFS_GET_REFERRALS
    ioctl_req["file_id"] = b"\xFF" * 16
    ioctl_req["max_output_response"] = 56 * 1024
    ioctl_req["flags"] = IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL
    ioctl_req["buffer"] = dfs_referral

    request = tree.session.connection.send(ioctl_req, sid=tree.session.session_id, tid=tree.tree_connect_id)
    response = tree.session.connection.receive(request)

    ioctl_resp = SMB2IOCTLResponse()
    ioctl_resp.unpack(response["data"].get_value())

    dfs_response = DFSReferralResponse()
    dfs_response.unpack(ioctl_resp["buffer"].get_value())

    return dfs_response


def delete_session(server, port=445, connection_cache=None):
    """
    Deletes the connection in the connection pool for the server specified. This will also close all sessions
    associated with the connection.

    :param server: The server name to close/delete.
    :param port: The port used for the server.
    :param connection_cache: Connection cache to be used with
    """
    connection_key = f"{server.lower()}:{port}"

    if connection_cache is None:
        connection_cache = _SMB_CONNECTIONS
    connection = connection_cache.get(connection_key, None)
    if connection:
        del connection_cache[connection_key]
        connection.disconnect(close=True)


def get_smb_tree(
    path, username=None, password=None, port=445, encrypt=None, connection_timeout=60, connection_cache=None
):
    """
    Returns an active Tree connection and file path including the tree based on the UNC path passed in and other
    connection arguments. The opened connection is registered in a pool and re-used if a connection is made to the same
    server with the same credentials.

    :param path: The absolute UNC path we want to open a tree connect to.
    :param username: Optional username to connect with. Required if no session has been registered for the server and
        Kerberos auth is not being used.
    :param password: Optional password to connect with.
    :param port: The port to connect with.
    :param encrypt: Whether to force encryption or not, once this has been set to True the session cannot be changed
        back to False.
    :param connection_timeout: Override the timeout used for the initial connection.
    :param connection_cache: Connection cache to be used with
    :return: The TreeConnect and file path including the tree based on the UNC path passed in.
    """
    # Ensure our defaults use the value from the client set config.
    client_config = ClientConfig()
    username = username or client_config.username
    password = password or client_config.password
    auth_protocol = client_config.auth_protocol

    # In case we need to nest a call to get_smb_tree, preserve the kwargs here so it's easier to update them in case
    # new kwargs are added.
    get_kwargs = {
        "username": username,
        "password": password,
        "port": port,
        "encrypt": encrypt,
        "connection_timeout": connection_timeout,
        "connection_cache": connection_cache,
    }

    # Normalise and check that the path contains at least 2 components, \\server\share
    path = ntpath.normpath(path)
    path_split = [p for p in path.split("\\") if p]
    if len(path_split) < 2:
        raise ValueError("The SMB path specified must contain the server and share to connect to")

    # Check if we've already got a referral match for the path specified and use that path instead.
    referral = client_config.lookup_referral(path_split)
    if referral and not referral.is_expired:
        path = path.replace(referral.dfs_path, referral.target_hint.target_path, 1)
        path_split = [p for p in path.split("\\") if p]

    else:
        # If there was no referral match, check if the hostname portion matches any known domain names
        domain_referral = client_config.lookup_domain(path_split[0])

        if domain_referral and not domain_referral.is_valid:
            # If the path is a valid domain name but our domain referral is not currently valid, issue a DC referral
            # to our known domain controller.
            ipc_tree = get_smb_tree(rf"\\{client_config.domain_controller}\IPC$", **get_kwargs)[0]
            referral_response = dfs_request(ipc_tree, domain_referral.domain_name)
            domain_referral.process_dc_referral(referral_response)

        if domain_referral:
            # Use the dc hint as the source for the root referral request
            ipc_tree = get_smb_tree(rf"\{domain_referral.dc_hint}\IPC$", **get_kwargs)[0]
            referral_response = dfs_request(ipc_tree, rf"\{path_split[0]}\{path_split[1]}")
            client_config.cache_referral(referral_response)
            referral = client_config.lookup_referral(path_split)
            if not referral:
                raise ObjectPathNotFound()

            path = path.replace(referral.dfs_path, referral.target_hint.target_path, 1)
            path_split = [p for p in path.split("\\") if p]

    server = path_split[0]
    session = register_session(
        server,
        username=username,
        password=password,
        port=port,
        encrypt=encrypt,
        connection_timeout=connection_timeout,
        connection_cache=connection_cache,
        auth_protocol=auth_protocol,
    )

    share_path = rf"\\{server}\{path_split[1]}"
    tree = next((t for t in session.tree_connect_table.values() if t.share_name == share_path), None)
    if not tree:
        tree = TreeConnect(session, share_path)
        try:
            tree.connect(require_secure_negotiate=client_config.require_secure_negotiate)
        except BadNetworkName as err:
            # If the server doesn't mention it supports DFS then don't try to
            # resolve the DFS path.
            if not session.connection.server_capabilities.has_flag(Capabilities.SMB2_GLOBAL_CAP_DFS):
                raise

            ipc_path = rf"\\{server}\IPC$"
            if path == ipc_path:  # In case we already tried connecting to IPC$ but that failed.
                raise

            # The share could be a DFS root, issue a root referral request to the hostname and cache the result.
            ipc_tree = get_smb_tree(ipc_path, **get_kwargs)[0]
            try:
                referral = dfs_request(ipc_tree, rf"\{path_split[0]}\{path_split[1]}")
            except FSDriverRequired:
                # If the DFS Request fails with STATUS_FS_DRIVER_REQUIRED then
                # the server doesn't support DFS requests and the original
                # BadNetworkName error should be raised instead of this one.
                # This provides better context as to why a failure occured, i.e.
                # a bad share path was provided.
                # https://github.com/jborean93/smbprotocol/issues/196
                raise err

            client_config.cache_referral(referral)

            # Sometimes a DFS referral may return 0 referrals, this needs to be checked here to avoid repeats.
            if not client_config.lookup_referral(path_split):
                raise ObjectPathNotFound()

            return get_smb_tree(path, **get_kwargs)

    # When opening a file on a DFS tree the raw path used in the CREATE
    # request is the the original DFS path as the server should normalise
    # it and return STATUS_PATH_NOT_COVERED if it's served by a DFS target
    # server.
    # https://github.com/jborean93/smbprotocol/issues/170
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/448cb979-7321-4598-89df-e5c97135b566
    file_path = ""
    if tree.is_dfs_share:
        file_path = "\\".join(path_split)

    elif len(path_split) > 2:
        file_path = "\\".join(path_split[2:])

    return tree, file_path


def register_session(
    server,
    username=None,
    password=None,
    port=445,
    encrypt=None,
    connection_timeout=60,
    connection_cache=None,
    auth_protocol="negotiate",
    require_signing=True,
):
    """
    Creates an active connection and session to the server specified. This can be manually called to register the
    credentials of a specific server instead of defining it on the first function connecting to the server. The opened
    connection is registered in a pool and re-used if a connection is made to the same server with the same
    credentials.

    :param server: The server name to register.
    :param username: Optional username to connect with. Required if no session has been registered for the server and
        Kerberos auth is not being used.
    :param password: Optional password to connect with.
    :param port: The port to connect with. Defaults to 445.
    :param encrypt: Whether to force encryption or not, once this has been set to True the session cannot be changed
        back to False.
    :param connection_timeout: Override the timeout used for the initial connection.
    :param connection_cache: Connection cache to be used with
    :param auth_protocol: The protocol to use for authentication. Possible values are 'negotiate', 'ntlm' or
        'kerberos'. Defaults to 'negotiate'.
    :param require_signing: Whether signing is required on SMB messages sent over this session. Defaults to True.
    :return: The Session that was registered or already existed in the pool.
    """
    connection_key = f"{server.lower()}:{port}"

    if connection_cache is None:
        connection_cache = _SMB_CONNECTIONS
    connection = connection_cache.get(connection_key, None)

    # Make sure we ignore any connections that may have had a closed connection
    if not connection or not connection.transport.connected:
        connection = Connection(ClientConfig().client_guid, server, port, require_signing=require_signing)
        connection.connect(timeout=connection_timeout)
        connection_cache[connection_key] = connection

    # Find the first session in the connection session list that match the username specified, if not username then
    # just use the first session found or fall back to creating a new one with implicit auth/kerberos.
    session = next((s for s in connection.session_table.values() if username is None or s.username == username), None)
    if not session:
        session = Session(
            connection,
            username=username,
            password=password,
            require_encryption=(encrypt is True),
            auth_protocol=auth_protocol,
        )
        session.connect()
    elif encrypt is not None:
        # We cannot go from encryption to no encryption on an existing session but we can do the opposite.
        if session.encrypt_data and not encrypt:
            raise ValueError("Cannot disable encryption on an already negotiated session.")
        elif not session.encrypt_data and encrypt:
            session.encrypt = True

    return session


# Make sure we run the function to close all the sessions when we exit Python
def reset_connection_cache(fail_on_error=True, connection_cache=None):
    """
    Closes all the connections/sessions that have been pooled in the SMB Client. This allows a user to reset their
    client in case of an unknown problem or they just wish to reset all the connections. It is also run on exit of the
    Python interpreter to ensure the SMB connections are closed.
    """
    if connection_cache is None:
        connection_cache = _SMB_CONNECTIONS

    for name, connection in list(connection_cache.items()):
        try:
            connection.disconnect()
            del connection_cache[name]
        except Exception as e:
            if fail_on_error:
                raise
            else:
                log.warning("Failed to close connection %s", name, exc_info=e)


atexit.register(reset_connection_cache, fail_on_error=False)
