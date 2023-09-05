# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import io
import logging

from smbclient._pool import ClientConfig, dfs_request, get_smb_tree
from smbprotocol import MAX_PAYLOAD_SIZE
from smbprotocol.exceptions import (
    NoMoreFiles,
    ObjectNameNotFound,
    ObjectPathNotFound,
    PathNotCovered,
    PipeBroken,
    SMBOSError,
    SMBResponseException,
)
from smbprotocol.file_info import FileAttributes, FileEndOfFileInformation
from smbprotocol.ioctl import IOCTLFlags, SMB2IOCTLRequest, SMB2IOCTLResponse
from smbprotocol.open import (
    CreateDisposition,
    CreateOptions,
    FilePipePrinterAccessMask,
    ImpersonationLevel,
    Open,
    QueryDirectoryFlags,
    ShareAccess,
    SMB2CreateRequest,
    SMB2QueryInfoRequest,
    SMB2QueryInfoResponse,
    SMB2SetInfoRequest,
    SMB2SetInfoResponse,
)

log = logging.getLogger(__name__)


SEEK_SET = io.SEEK_SET
SEEK_CUR = io.SEEK_CUR
SEEK_END = io.SEEK_END


def _parse_share_access(raw, mode):
    share_access = 0
    if raw:
        share_access_map = {
            "r": ShareAccess.FILE_SHARE_READ,
            "w": ShareAccess.FILE_SHARE_WRITE,
            "d": ShareAccess.FILE_SHARE_DELETE,
        }
        for c in raw:
            access_val = share_access_map.get(c)
            if access_val is None:
                chars = ", ".join(sorted(share_access_map.keys()))
                raise ValueError(f"Invalid share_access char {c}, can only be {chars}")
            share_access |= access_val

        if "r" in mode:
            share_access |= ShareAccess.FILE_SHARE_READ

    return share_access


def _parse_mode(raw, invalid=""):
    create_disposition = 0
    disposition_map = {
        "r": CreateDisposition.FILE_OPEN,
        "w": CreateDisposition.FILE_OVERWRITE_IF,
        "x": CreateDisposition.FILE_CREATE,
        "a": CreateDisposition.FILE_OPEN_IF,
        # These have no bearing on the CreateDisposition but are here so ValueError isn't raised
        "+": 0,
        "b": 0,
        "t": 0,
    }
    if invalid:
        for invalid_char in invalid:
            del disposition_map[invalid_char]

    for c in raw:
        dispo_val = disposition_map.get(c)
        if dispo_val is None:
            chars = ", ".join(sorted(disposition_map.keys()))
            raise ValueError(
                f"Invalid mode char {c}, can only be {chars}",
            )

        create_disposition |= dispo_val

    if create_disposition == 0:
        raise ValueError(f"Invalid mode value {raw}, must contain at least r, w, x, or a")

    return create_disposition


def _chunk_size(connection, length, operation):
    """
    Get the maximum size of data we can read/write. Also gets the number of credits to request to optimize subsequent
    read/write operations for the remaining length.

    :param connection: The SMB connection.
    :param length: The length of the data we are working with.
    :param operation: The operation the chunk is for: 'read', 'write', 'transact'
    :return: The size of the chunk we can use and the number of credits to request for the next operation.
    """
    max_size = getattr(connection, f"max_{operation}_size")

    # Determine the maximum data length we can send for the operation. We do this by checking the available credits and
    # calculating whatever is the smallest; length, negotiated operation size, available credit size).
    available_credits = connection.sequence_window["high"] - connection.sequence_window["low"]
    chunk_size = min(length, max_size, available_credits * MAX_PAYLOAD_SIZE)

    # Determine how many credits we need to fully optimize subsequent calls for the remaining amount of data. Basically
    # how many credits we need to send either the remaining data or the max operation size.
    remaining_length = min(max(0, length - chunk_size), max_size)
    consumed_credits = (max(0, chunk_size - 1) // MAX_PAYLOAD_SIZE) + 1
    remaining_credits = (max(0, remaining_length - 1) // MAX_PAYLOAD_SIZE) + 1
    desired_credits = max(0, remaining_credits - available_credits - consumed_credits)

    credit_request = consumed_credits + desired_credits

    return chunk_size, int(credit_request)


def _resolve_dfs(raw_io):
    """
    Resolves a DFS path for a failed Open request.

    :param raw_io: The SMBRawIO to resolve the DFS path for.
    :return: A new Open for each DFS target that was resolved.
    """
    if not raw_io.fd.tree_connect.is_dfs_share:
        return

    # Path is on a DFS root that is linked to another server.
    client_config = ClientConfig()
    raw_path = raw_io.name

    referral = dfs_request(raw_io.fd.tree_connect, raw_path[1:])
    client_config.cache_referral(referral)
    info = client_config.lookup_referral([p for p in raw_path.split("\\") if p])
    if not info:
        raise ObjectPathNotFound()

    connection_kwargs = getattr(raw_io, f"_{SMBRawIO.__name__}__kwargs", {})

    for target in info:
        new_path = raw_path.replace(info.dfs_path, target.target_path, 1)

        try:
            tree, fd_path = get_smb_tree(new_path, **connection_kwargs)

        except SMBResponseException as link_exc:
            log.warning("Failed to connect to DFS link target %s", target, exc_info=link_exc)
            continue

        # Record the target that worked for future reference.
        info.target_hint = target
        yield Open(tree, fd_path)


def ioctl_request(transaction, ctl_code, output_size=0, flags=IOCTLFlags.SMB2_0_IOCTL_IS_IOCTL, input_buffer=b""):
    """
    Sends an IOCTL request to the server.

    :param transaction: The SMBFileTransaction the request is to run under.
    :param ctl_code: The IOCTL Code of the request.
    :param output_size: Specify the max output response allowed from the server.
    :param flags: Specify custom flags to be set on the IOCTL request.
    :param input_buffer: Specify an optional input buffer for the request.
    """
    ioctl_req = SMB2IOCTLRequest()
    ioctl_req["ctl_code"] = ctl_code
    ioctl_req["file_id"] = transaction.raw.fd.file_id
    ioctl_req["max_output_response"] = output_size
    ioctl_req["flags"] = flags
    ioctl_req["buffer"] = input_buffer

    def _receive_resp(request):
        response = transaction.raw.fd.connection.receive(request)
        query_resp = SMB2IOCTLResponse()
        query_resp.unpack(response["data"].get_value())
        return query_resp["buffer"].get_value()

    transaction += (ioctl_req, _receive_resp)


def query_info(transaction, info_class, flags=0, output_buffer_length=None):
    """
    Sends a QUERY INFO request to the server for the information class passed in.

    :param transaction: The SMBFileTransaction the request is to run under.
    :param info_class: The required information class type defined in file_info.py that is being requested.
    :param flags: Optional flags to set on the query request.
    :param output_buffer_length: Override the max output buffer length, defaults to the size of the information class.
    """
    info_obj = info_class()
    query_req = SMB2QueryInfoRequest()
    query_req["info_type"] = info_obj.INFO_TYPE
    query_req["file_info_class"] = info_obj.INFO_CLASS
    query_req["file_id"] = transaction.raw.fd.file_id
    query_req["output_buffer_length"] = len(info_obj) if output_buffer_length is None else output_buffer_length
    query_req["flags"] = flags

    def _receive_resp(request):
        response = transaction.raw.fd.connection.receive(request)
        query_resp = SMB2QueryInfoResponse()
        query_resp.unpack(response["data"].get_value())
        return query_resp.parse_buffer(info_class)

    transaction += (query_req, _receive_resp)


def set_info(transaction, info_buffer):
    """
    Sends a SET INFO request to the server with the information class input.

    :param transaction: The SMBFileTransaction the request is to run under.
    :param info_buffer: The input information class to set.
    """
    set_req = SMB2SetInfoRequest()
    set_req["info_type"] = info_buffer.INFO_TYPE
    set_req["file_info_class"] = info_buffer.INFO_CLASS
    set_req["file_id"] = transaction.raw.fd.file_id
    set_req["buffer"] = info_buffer

    def _receive_resp(request):
        response = transaction.raw.fd.connection.receive(request)
        set_resp = SMB2SetInfoResponse()
        set_resp.unpack(response["data"].get_value())
        return set_resp

    transaction += (set_req, _receive_resp)


class SMBFileTransaction:
    def __init__(self, raw):
        """
        Stores compound requests in 1 class that can be committed when required. Either uses the opened raw object or
        if that is not opened, opens and closes it in the 1 request.

        :param raw: The SMBRawIO object to run the compound request with.
        """
        self.raw = raw
        self.results = None
        self._actions = []
        self._attempted_dfs_paths = set()

    def __add__(self, other):
        send_msg = other[0]
        unpack_func = other[1]

        self._actions.append((send_msg, unpack_func))
        return self

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.commit()

    def commit(self):
        """
        Sends a compound request to the server. Optionally opens and closes a handle in the same request if the handle
        is not already opened.
        """
        remove_index = []
        if self.raw.closed and (not self._actions or not isinstance(self._actions[0][0], SMB2CreateRequest)):
            self.raw.open(transaction=self)
            self._actions.insert(0, self._actions.pop(-1))  # Need to move the create to the start
            remove_index.insert(0, 0)

            self.raw.close(transaction=self)
            remove_index.insert(0, len(self._actions) - 1)

        send_msgs = []
        unpack_functions = []
        for action in self._actions:
            send_msgs.append(action[0])
            unpack_functions.append(action[1])

        sid = self.raw.fd.tree_connect.session.session_id
        tid = self.raw.fd.tree_connect.tree_connect_id
        requests = self.raw.fd.connection.send_compound(send_msgs, sid, tid, related=True)

        # Due to a wonderful threading issue we need to ensure we call .receive() for each message we sent so cannot
        # just enumerate the list in 1 line in case it throws an exception.
        failures = []
        responses = []
        try_again = False
        for idx, func in enumerate(unpack_functions):
            res = None

            try:
                try:
                    res = func(requests[idx])

                except (PathNotCovered, ObjectNameNotFound, ObjectPathNotFound):
                    # The MS-DFSC docs state that STATUS_PATH_NOT_COVERED is used when encountering a link to a
                    # different server but Samba seems to return the generic name or path not found.

                    # If the first action is not a CreateRequest then we can't resolve the DFS path in the transaction.
                    if not (idx == 0 and isinstance(send_msgs[0], SMB2CreateRequest)):
                        raise

                    for smb_open in _resolve_dfs(self.raw):
                        if smb_open.tree_connect.share_name == self.raw.fd.tree_connect.share_name:
                            continue

                        # Ensure we don't continuously try the same DFS referral targets if it's already been attempted.
                        # https://github.com/jborean93/smbprotocol/issues/228
                        tested_path = f"{smb_open.tree_connect.share_name}{smb_open.file_name}".lower()
                        if tested_path in self._attempted_dfs_paths:
                            continue

                        self._attempted_dfs_paths.add(tested_path)

                        self.raw.fd = smb_open

                        # In case this is a transaction with an explicit open we want to reopen it with the new params
                        # before trying it again.
                        self.raw.open(transaction=self)
                        self._actions[0] = self._actions.pop(-1)

                        try_again = True
                        break

                    else:
                        # Either there wasn't any DFS referrals or none of them worked, just reraise the error.
                        raise

            except SMBResponseException as exc:
                failures.append(SMBOSError(exc.status, self.raw.name))

            finally:
                responses.append(res)

        # Remove the existing open/close actions this transaction added internally.
        for idx in remove_index:
            del self._actions[idx]
            del responses[idx]

        if try_again:
            # If we updated the SMB Tree due to a DFS referral hit then try again.
            self.commit()

        elif failures:
            # If there was a failure, just raise the first exception found.
            raise failures[0]

        else:
            self.results = tuple(responses)


class SMBRawIO(io.RawIOBase):
    FILE_TYPE = None  # 'file', 'dir', or None (for unknown)
    _INVALID_MODE = ""

    def __init__(
        self, path, mode="r", share_access=None, desired_access=None, file_attributes=None, create_options=0, **kwargs
    ):
        tree, fd_path = get_smb_tree(path, **kwargs)

        self.share_access = share_access
        self.fd = Open(tree, fd_path)
        self._mode = mode
        self._name = path
        self._offset = 0
        self._flush = False
        self.__kwargs = kwargs  # Used in open for DFS referrals

        if desired_access is None:
            desired_access = 0

            # While we can open a directory, the values for FilePipePrinterAccessMask also apply to Dirs so just use
            # the same enum to simplify code.
            if "r" in self.mode or "+" in self.mode:
                desired_access |= (
                    FilePipePrinterAccessMask.FILE_READ_DATA
                    | FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES
                    | FilePipePrinterAccessMask.FILE_READ_EA
                )
            if "w" in self.mode or "x" in self.mode or "a" in self.mode or "+" in self.mode:
                desired_access |= (
                    FilePipePrinterAccessMask.FILE_WRITE_DATA
                    | FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES
                    | FilePipePrinterAccessMask.FILE_WRITE_EA
                )
        self._desired_access = desired_access

        if file_attributes is None:
            file_attributes = (
                FileAttributes.FILE_ATTRIBUTE_DIRECTORY
                if self.FILE_TYPE == "dir"
                else FileAttributes.FILE_ATTRIBUTE_NORMAL
            )
        self._file_attributes = file_attributes

        self._create_options = create_options
        self._create_options |= {
            "dir": CreateOptions.FILE_DIRECTORY_FILE,
            "file": CreateOptions.FILE_NON_DIRECTORY_FILE,
        }.get(self.FILE_TYPE, 0)

        super().__init__()

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @property
    def closed(self):
        return not self.fd.connected

    @property
    def mode(self):
        return self._mode

    @property
    def name(self):
        return self._name

    def close(self, transaction=None):
        if transaction:
            transaction += self.fd.close(send=False)
        else:
            self.fd.close()

    def flush(self):
        if self._flush and self.FILE_TYPE != "pipe":
            self.fd.flush()

    def open(self, transaction=None):
        if not self.closed:
            return

        open_at_end = False
        if not transaction:
            # The SMBFileTransaction has special logic that deals with DFS paths, use that to do the actual open.
            open_at_end = True
            transaction = SMBFileTransaction(self)

        share_access = _parse_share_access(self.share_access, self.mode)
        create_disposition = _parse_mode(self.mode, invalid=self._INVALID_MODE)

        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wpo/feeb3122-cfe0-4b34-821d-e31c036d763c
        # Impersonation on SMB has little meaning when opening files but is important if using RPC so set to a sane
        # default of Impersonation.
        transaction += self.fd.create(
            ImpersonationLevel.Impersonation,
            self._desired_access,
            self._file_attributes,
            share_access,
            create_disposition,
            self._create_options,
            send=False,
        )

        if open_at_end:
            transaction.commit()
            if "a" in self.mode and self.FILE_TYPE != "pipe":
                self._offset = self.fd.end_of_file

    def readable(self):
        """True if file was opened in a read mode."""
        return "r" in self.mode or "+" in self.mode

    def seek(self, offset, whence=SEEK_SET):
        """
        Move to new file position and return the file position.

        Argument offset is a byte count.  Optional argument whence defaults to
        SEEK_SET or 0 (offset from start of file, offset should be >= 0); other values
        are SEEK_CUR or 1 (move relative to current position, positive or negative),
        and SEEK_END or 2 (move relative to end of file, usually negative, although
        many platforms allow seeking beyond the end of a file).

        Note that not all file objects are seekable.
        """
        seek_offset = {
            SEEK_SET: 0,
            SEEK_CUR: self._offset,
            SEEK_END: self.fd.end_of_file,
        }[whence]
        self._offset = seek_offset + offset
        return self._offset

    def seekable(self):
        """True if file supports random-access."""
        return True

    def tell(self):
        """
        Current file position.

        Can raise OSError for non seekable files.
        """
        return self._offset

    def truncate(self, size):
        """
        Truncate the file to at most size bytes and return the truncated size.

        Size defaults to the current file position, as returned by tell().
        The current file position is changed to the value of size.
        """
        with SMBFileTransaction(self) as transaction:
            eof_info = FileEndOfFileInformation()
            eof_info["end_of_file"] = size
            set_info(transaction, eof_info)

        self.fd.end_of_file = size
        self._flush = True
        return size

    def writable(self):
        """True if file was opened in a write mode."""
        return "w" in self.mode or "x" in self.mode or "a" in self.mode or "+" in self.mode

    def readall(self):
        """
        Read and return all the bytes from the stream until EOF, using
        multiple calls to the stream if necessary.

        :return: The byte string read from the SMB file.
        """
        data = bytearray()
        while True:
            read_length = min(
                # We always want to be reading a minimum of 64KiB.
                max(self.fd.end_of_file - self._offset, MAX_PAYLOAD_SIZE),
                self.fd.connection.max_read_size,  # We can never read more than this.
            )

            buffer = bytearray(b"\x00" * read_length)
            bytes_read = self.readinto(buffer)
            if not bytes_read:
                break

            data += buffer[:bytes_read]

        return bytes(data)

    def readinto(self, b):
        """
        Read bytes into a pre-allocated, writable bytes-like object b, and
        return the number of bytes read. This may read less bytes than
        requested as it depends on the negotiated read size and SMB credits
        available.

        :param b: bytes-like object to read the data into.
        :return: The number of bytes read.
        """
        if self._offset >= self.fd.end_of_file and self.FILE_TYPE != "pipe":
            return 0

        chunk_size, credit_request = _chunk_size(self.fd.connection, len(b), "read")

        log.debug("Read %d -%d.", self._offset, chunk_size)
        read_msg, recv_func = self.fd.read(self._offset, chunk_size, send=False)
        request = self.fd.connection.send(
            read_msg,
            sid=self.fd.tree_connect.session.session_id,
            tid=self.fd.tree_connect.tree_connect_id,
            credit_request=credit_request,
        )

        try:
            file_bytes = recv_func(request)
        except PipeBroken:
            # A pipe will block until it returns the data available or was closed/broken.
            file_bytes = b""

        b[: len(file_bytes)] = file_bytes

        if self.FILE_TYPE != "pipe":
            self._offset += len(file_bytes)

        return len(file_bytes)

    def write(self, b):
        """
        Write buffer b to file, return number of bytes written.

        Only makes one system call, so not all of the data may be written.
        The number of bytes actually written is returned. This can be less than
        the length of b as it depends on the underlying connection.
        """
        chunk_size, credit_request = _chunk_size(self.fd.connection, len(b), "write")
        data = bytes(b[:chunk_size])

        write_msg, recv_func = self.fd.write(data, offset=self._offset, send=False)
        request = self.fd.connection.send(
            write_msg,
            sid=self.fd.tree_connect.session.session_id,
            tid=self.fd.tree_connect.tree_connect_id,
            credit_request=credit_request,
        )
        bytes_written = recv_func(request)

        if self.FILE_TYPE != "pipe":
            self._offset += bytes_written
            self.fd.end_of_file = max(self.fd.end_of_file, self._offset)
            self._flush = True

        return bytes_written


class SMBDirectoryIO(SMBRawIO):
    FILE_TYPE = "dir"
    _INVALID_MODE = "w+"

    def query_directory(self, pattern, info_class):
        query_flags = QueryDirectoryFlags.SMB2_RESTART_SCANS
        while True:
            try:
                entries = self.fd.query_directory(pattern, info_class, flags=query_flags)
            except NoMoreFiles:
                break

            query_flags = 0  # Only the first request should have set SMB2_RESTART_SCANS
            yield from entries

    def readable(self):
        return False

    def seekable(self):
        return False

    def writable(self):
        return False


class SMBFileIO(SMBRawIO):
    FILE_TYPE = "file"


class SMBPipeIO(SMBRawIO):
    FILE_TYPE = "pipe"

    def seekable(self):
        return False
