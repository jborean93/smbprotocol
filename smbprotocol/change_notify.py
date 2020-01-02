# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import logging
import threading

from collections import (
    OrderedDict,
)

from smbprotocol.connection import (
    Commands,
    NtStatus,
)

from smbprotocol.exceptions import (
    SMBResponseException,
)

from smbprotocol.structure import (
    BytesField,
    EnumField,
    FlagField,
    IntField,
    Structure,
    TextField,
)

log = logging.getLogger(__name__)


class ChangeNotifyFlags(object):
    """
    [MS-SMB2] 2.2.35 SMB2 CHANGE_NOTIFY Request - Flags
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/598f395a-e7a2-4cc8-afb3-ccb30dd2df7c
    """
    NONE = 0
    SMB2_WATCH_TREE = 0x0001


class CompletionFilter(object):
    """
    [MS-SMB2] 2.2.35 SMB2 CHANGE_NOTIFY Request - CompletionFilter
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/598f395a-e7a2-4cc8-afb3-ccb30dd2df7c
    """
    FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
    FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
    FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004
    FILE_NOTIFY_CHANGE_SIZE = 0x00000008
    FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
    FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020
    FILE_NOTIFY_CHANGE_CREATION = 0x00000040
    FILE_NOTIFY_CHANGE_EA = 0x00000080
    FILE_NOTIFY_CHANGE_SECURITY = 0x00000100
    FILE_NOTIFY_CHANGE_STREAM_NAME = 0x00000200
    FILE_NOTIFY_CHANGE_STREAM_SIZE = 0x00000400
    FILE_NOTIFY_CHANGE_STREAM_WRITE = 0x00000800


class FileAction(object):
    """
    [MS-FSCC] 2.7.1 FILE_NOTIFY_INFORMATION - Action
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/634043d7-7b39-47e9-9e26-bda64685e4c9
    """
    FILE_ACTION_ADDED = 0x00000001
    FILE_ACTION_REMOVED = 0x00000002
    FILE_ACTION_MODIFIED = 0x00000003
    FILE_ACTION_RENAMED_OLD_NAME = 0x00000004
    FILE_ACTION_RENAMED_NEW_NAME = 0x00000005
    FILE_ACTION_ADDED_STREAM = 0x00000006
    FILE_ACTION_REMOVED_STREAM = 0x00000007
    FILE_ACTION_MODIFIED_STREAM = 0x00000008
    FILE_ACTION_REMOVED_BY_DELETE = 0x00000009
    FILE_ACTION_ID_NOT_TUNNELLED = 0x0000000A
    FILE_ACTION_TUNNELLED_ID_COLLISION = 0x0000000B


class FileNotifyInformation(Structure):
    """
    [Ms-FSCC] 2.7.1 FILE_NOTIFY_INFORMATION
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/634043d7-7b39-47e9-9e26-bda64685e4c9
    """
    def __init__(self):
        self.fields = OrderedDict([
            ('next_entry_offset', IntField(size=4)),
            ('action', EnumField(
                size=4,
                enum_type=FileAction,
            )),
            ('file_name_length', IntField(
                size=4,
                default=lambda s: len(s['file_name']),
            )),
            ('file_name', TextField(
                encoding='utf-16-le',
                size=lambda s: s['file_name_length'].get_value(),
            )),
        ])
        super(FileNotifyInformation, self).__init__()


class SMB2ChangeNotifyRequest(Structure):
    """
    [MS-SMB2] 2.2.35 SMB2 CHANGE_NOTIFY Request
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/598f395a-e7a2-4cc8-afb3-ccb30dd2df7c

    Sent by the client to request change notifications on a directory.
    """
    COMMAND = Commands.SMB2_CHANGE_NOTIFY

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=32,
            )),
            ('flags', FlagField(
                size=2,
                flag_type=ChangeNotifyFlags,
            )),
            ('output_buffer_length', IntField(size=4)),
            ('file_id', BytesField(size=16)),
            ('completion_filter', FlagField(
                size=4,
                flag_type=CompletionFilter,
            )),
            ('reserved', IntField(size=4)),
        ])
        super(SMB2ChangeNotifyRequest, self).__init__()


class SMB2ChangeNotifyResponse(Structure):
    """
    [MS-SMB2] 2.2.36 SMB2 CHANGE_NOTIFY Response
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/14f9d050-27b2-49df-b009-54e08e8bf7b5

    Sent by the server to transmit the results of a client's change notify request.
    """
    COMMAND = Commands.SMB2_CHANGE_NOTIFY

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=9,
            )),
            ('output_buffer_offset', IntField(
                size=2,
                default=72,
            )),
            ('output_buffer_length', IntField(
                size=4,
                default=lambda s: len(s['buffer']),
            )),
            ('buffer', BytesField(
                size=lambda s: s['output_buffer_length'].get_value(),
            )),
        ])
        super(SMB2ChangeNotifyResponse, self).__init__()


class FileSystemWatcher(object):

    def __init__(self, open):
        """
        A class that encapsulates a FileSystemWatcher over SMB. It is designed to make it easy to run the watcher in
        the background and provide an event that is fired when the server notifies that a change has occurred. It is
        up to the caller to action on that event through their own sync or asynchronous implementation.

        :param open: The Open() class of a directory to watch for change notifications.
        """
        self.open = open
        self.response_event = threading.Event()

        self._t_on_response = threading.Thread(target=self._on_response)
        self._t_on_response.daemon = True
        self._t_exc = None
        self._request = None
        self._file_actions = None
        self._result_lock = threading.Lock()  # Used to ensure the result is only processed once

    @property
    def result(self):
        """
        The result of the FileSystemWatcher request after it has been completed. Returns None if it still running
        or has been cancelled, raises the underlying exception if one was returned by the server or a list of
        FileNotifyInformation() structures that contain all the changed details. The list is empty if the watcher's
        output buffer length was set to 0 which indicates a change has occured but no details were returned by the
        server.
        """
        if self.cancelled:
            return None
        if self._request is None or self._request.response is None:
            return None
        elif self._request.response['status'].get_value() == NtStatus.STATUS_PENDING:
            return None
        elif self._t_exc:
            raise self._t_exc

        with self._result_lock:
            if self._file_actions is not None:
                return self._file_actions

            response = self._request.response['data'].get_value()
            change_response = SMB2ChangeNotifyResponse()
            change_response.unpack(response)
            response_buffer = change_response['buffer'].get_value()

            self._file_actions = []
            current_offset = 0
            is_next = True
            while is_next:
                notify_info = FileNotifyInformation()
                notify_info.unpack(response_buffer[current_offset:])

                self._file_actions.append(notify_info)

                current_offset += notify_info['next_entry_offset'].get_value()
                is_next = notify_info['next_entry_offset'].get_value() != 0

        return self._file_actions

    @property
    def cancelled(self):
        """ States whether the change notify request was cancelled or not. """""
        return self._request is not None and self._request.cancelled is True

    def start(self, completion_filter, flags=0, output_buffer_length=65536, send=True):
        """
        Starts a change notify request against the server with the options specified.

        Note: cannot send as a compound request as the resulting async reply session cannot be determined. See the
        following URL for more details.
        https://social.msdn.microsoft.com/Forums/en-US/a580f7bc-6746-4876-83db-6ac209b202c4/mssmb2-change-notify-response-sessionid?forum=os_fileservices

        :param completion_filter: Specify one or more filters to request a notification on.
        :param flags: Specify custom flags, only ChangeNotifyFlags.SMB2_WATCH_TREE is defined which watches for change
            events in the sub directories of the Open() dir specified.
        :param output_buffer_length: The output buffer length to defined the max size of data the server can return.
            Set to 0 to only receive a notification of changes without the details of the change.
        :param send: Whether to send the request in the same call or return the message to the caller and the
            unpack function. Note the compound request must not close the dir the watcher is started on.
        """
        change_notify = SMB2ChangeNotifyRequest()
        change_notify['flags'] = flags
        change_notify['output_buffer_length'] = output_buffer_length
        change_notify['file_id'] = self.open.file_id
        change_notify['completion_filter'] = completion_filter

        log.info("Session: %s, Tree Connect: %s , Open: %s - sending SMB2 Change Notify request"
                 % (self.open.tree_connect.session.username, self.open.tree_connect.share_name, self.open.file_name))
        log.debug(change_notify)
        if send:
            request = self.open.connection.send(change_notify, self.open.tree_connect.session.session_id,
                                                self.open.tree_connect.tree_connect_id)
            self._start_response(request)
            return
        else:
            return change_notify, self._start_response

    def _start_response(self, request):
        self._request = request
        self._t_on_response.start()

    def cancel(self):
        """
        Cancels the change notify request on the server.
        """
        self._request.cancel()

    def wait(self):
        """
        Waits until a change response has been returned from the server.

        :return: The file action result
        """
        self._t_on_response.join()
        return self.result

    def _on_response(self):
        try:
            self.open.connection.receive(self._request)
        except SMBResponseException as exc:
            if exc.status == NtStatus.STATUS_CANCELLED:
                self.is_cancelled = True
            elif exc.status == NtStatus.STATUS_NOTIFY_ENUM_DIR:
                # output_buffer_length was 0 so we only need to notify the caller that a change occurred, set an empty
                # action list.
                self._file_actions = []
            else:
                self._t_exc = exc
        except Exception as exc:
            self._t_exc = exc
        finally:
            log.debug("Firing response event for %s change notify" % self.open.file_name)
            self.response_event.set()
