# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import re
import threading
import uuid

import pytest

from smbprotocol._text import (
    to_native,
)

from smbprotocol.connection import (
    Connection,
)

from smbprotocol.exceptions import (
    SMBResponseException,
)

from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect

from smbprotocol.change_notify import (
    CompletionFilter,
    FileAction,
    FileNotifyInformation,
    FileSystemWatcher,
    SMB2ChangeNotifyRequest,
    SMB2ChangeNotifyResponse,
)

from smbprotocol.open import (
    CreateDisposition,
    CreateOptions,
    DirectoryAccessMask,
    FileAttributes,
    FilePipePrinterAccessMask,
    ImpersonationLevel,
    ShareAccess,
    Open
)

from .utils import smb_real


class TestFileNotifyInformation(object):

    DATA = b"\x00\x00\x00\x00" \
           b"\x01\x00\x00\x00" \
           b"\x08\x00\x00\x00" \
           b"\x63\x00\x61\x00\x66\x00\xe9\x00"

    def test_create_message(self):
        message = FileNotifyInformation()
        message['action'] = 1
        message['file_name'] = u"café"
        actual = message.pack()
        assert len(message) == 20
        assert actual == self.DATA
        assert str(message['file_name']) == to_native(u"café")

    def test_parse_message(self):
        actual = FileNotifyInformation()
        assert actual.unpack(self.DATA) == b""
        assert len(actual) == 20
        assert actual['next_entry_offset'].get_value() == 0
        assert actual['action'].get_value() == 1
        assert actual['file_name_length'].get_value() == 8
        assert actual['file_name'].get_value() == u"café"


class TestSMB2ChangeNotifyRequest(object):

    DATA = b"\x20\x00" \
           b"\x00\x00" \
           b"\x08\x00\x00\x00" \
           b"\xff\xff\xff\xff\xff\xff\xff\xff" \
           b"\xff\xff\xff\xff\xff\xff\xff\xff" \
           b"\x01\x00\x00\x00" \
           b"\x00\x00\x00\x00"

    def test_create_message(self):
        message = SMB2ChangeNotifyRequest()
        message['output_buffer_length'] = 8
        message['file_id'] = b"\xff" * 16
        message['completion_filter'] = 1
        actual = message.pack()
        assert len(message) == 32
        assert actual == self.DATA

    def test_parse_message(self):
        actual = SMB2ChangeNotifyRequest()
        assert actual.unpack(self.DATA) == b""
        assert len(actual) == 32
        assert actual['structure_size'].get_value() == 32
        assert actual['flags'].get_value() == 0
        assert actual['output_buffer_length'].get_value() == 8
        assert actual['file_id'].get_value() == b"\xff" * 16
        assert actual['completion_filter'].get_value() == 1
        assert actual['reserved'].get_value() == 0


class TestSMB2ChangeNotifyResponse(object):

    DATA = b"\x09\x00" \
           b"\x48\x00" \
           b"\x04\x00\x00\x00" \
           b"\x01\x02\x03\x04"

    def test_create_message(self):
        message = SMB2ChangeNotifyResponse()
        message['buffer'] = b"\x01\x02\x03\x04"
        actual = message.pack()
        assert len(message) == 12
        assert actual == self.DATA

    def test_parse_message(self):
        actual = SMB2ChangeNotifyResponse()
        assert actual.unpack(self.DATA) == b""
        assert len(actual) == 12
        assert actual['structure_size'].get_value() == 9
        assert actual['output_buffer_offset'].get_value() == 72
        assert actual['output_buffer_length'].get_value() == 4
        assert actual['buffer'].get_value() == b"\x01\x02\x03\x04"


class TestChangeNotify(object):

    def _remove_file(self, tree, name):
        file_open = Open(tree, name)
        file_open.create(
            ImpersonationLevel.Impersonation,
            FilePipePrinterAccessMask.DELETE,
            FileAttributes.FILE_ATTRIBUTE_NORMAL,
            ShareAccess.FILE_SHARE_READ |
            ShareAccess.FILE_SHARE_WRITE |
            ShareAccess.FILE_SHARE_DELETE,
            CreateDisposition.FILE_OPEN_IF,
            CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_DELETE_ON_CLOSE
        ),
        file_open.close()

    def test_change_notify_on_dir(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "directory-watch")
        try:
            session.connect()
            tree.connect()

            open.create(ImpersonationLevel.Impersonation,
                        DirectoryAccessMask.MAXIMUM_ALLOWED,
                        FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
                        ShareAccess.FILE_SHARE_READ |
                        ShareAccess.FILE_SHARE_WRITE |
                        ShareAccess.FILE_SHARE_DELETE,
                        CreateDisposition.FILE_OPEN_IF,
                        CreateOptions.FILE_DIRECTORY_FILE)

            self._remove_file(tree, "directory-watch\\created file")

            watcher = FileSystemWatcher(open)
            watcher.start(CompletionFilter.FILE_NOTIFY_CHANGE_FILE_NAME)
            assert watcher.result is None
            assert watcher.response_event.is_set() is False

            # Run the wait in a separate thread so we can create the dir
            def watcher_wait():
                watcher.wait()
            watcher_wait_thread = threading.Thread(target=watcher_wait)
            watcher_wait_thread.daemon = True
            watcher_wait_thread.start()

            def watcher_event():
                watcher.response_event.wait()
            watcher_event_thread = threading.Thread(target=watcher_event)
            watcher_event_thread.daemon = True
            watcher_event_thread.start()

            # Create the new file
            file_open = Open(tree, "directory-watch\\created file")
            file_open.create(ImpersonationLevel.Impersonation,
                             FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                             FileAttributes.FILE_ATTRIBUTE_NORMAL,
                             ShareAccess.FILE_SHARE_READ |
                             ShareAccess.FILE_SHARE_WRITE |
                             ShareAccess.FILE_SHARE_DELETE,
                             CreateDisposition.FILE_OPEN_IF,
                             CreateOptions.FILE_NON_DIRECTORY_FILE)
            file_open.close()

            watcher_wait_thread.join(timeout=2)
            watcher_event_thread.join(timeout=2)
            assert watcher_wait_thread.is_alive() is False
            assert watcher_event_thread.is_alive() is False

            assert watcher.response_event.is_set()
            assert len(watcher.result) == 1

            assert watcher.result[0]['file_name'].get_value() == u"created file"
            assert watcher.result[0]['action'].get_value() == FileAction.FILE_ACTION_ADDED

            open.close()
        finally:
            connection.disconnect(True)

    def test_change_notify_no_data(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "directory-watch")
        try:
            session.connect()
            tree.connect()

            open.create(ImpersonationLevel.Impersonation,
                        DirectoryAccessMask.MAXIMUM_ALLOWED,
                        FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
                        ShareAccess.FILE_SHARE_READ |
                        ShareAccess.FILE_SHARE_WRITE |
                        ShareAccess.FILE_SHARE_DELETE,
                        CreateDisposition.FILE_OPEN_IF,
                        CreateOptions.FILE_DIRECTORY_FILE)

            self._remove_file(tree, "directory-watch\\created file")

            watcher = FileSystemWatcher(open)
            watcher.start(CompletionFilter.FILE_NOTIFY_CHANGE_FILE_NAME, output_buffer_length=0)
            assert watcher.result is None
            assert watcher.response_event.is_set() is False

            # Run the wait in a separate thread so we can create the dir
            def watcher_wait():
                watcher.wait()
            watcher_wait_thread = threading.Thread(target=watcher_wait)
            watcher_wait_thread.daemon = True
            watcher_wait_thread.start()

            def watcher_event():
                watcher.response_event.wait()
            watcher_event_thread = threading.Thread(target=watcher_event)
            watcher_event_thread.daemon = True
            watcher_event_thread.start()

            # Create the new file
            file_open = Open(tree, "directory-watch\\created file")
            file_open.create(ImpersonationLevel.Impersonation,
                             FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                             FileAttributes.FILE_ATTRIBUTE_NORMAL,
                             ShareAccess.FILE_SHARE_READ |
                             ShareAccess.FILE_SHARE_WRITE |
                             ShareAccess.FILE_SHARE_DELETE,
                             CreateDisposition.FILE_OPEN_IF,
                             CreateOptions.FILE_NON_DIRECTORY_FILE)
            file_open.close()

            watcher_wait_thread.join(timeout=2)
            watcher_event_thread.join(timeout=2)
            assert watcher_wait_thread.is_alive() is False
            assert watcher_event_thread.is_alive() is False

            assert watcher.response_event.is_set()
            assert watcher.result == []

            open.close()
        finally:
            connection.disconnect(True)

    def test_change_notify_underlying_close(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "directory-watch")
        try:
            session.connect()
            tree.connect()

            open.create(ImpersonationLevel.Impersonation,
                        DirectoryAccessMask.MAXIMUM_ALLOWED,
                        FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
                        ShareAccess.FILE_SHARE_READ |
                        ShareAccess.FILE_SHARE_WRITE |
                        ShareAccess.FILE_SHARE_DELETE,
                        CreateDisposition.FILE_OPEN_IF,
                        CreateOptions.FILE_DIRECTORY_FILE)

            watcher = FileSystemWatcher(open)
            watcher.start(CompletionFilter.FILE_NOTIFY_CHANGE_FILE_NAME)
            assert watcher.result is None
            assert watcher.response_event.is_set() is False

            open.close()

            expected = "Received unexpected status from the server: (267) STATUS_NOTIFY_CLEANUP"
            with pytest.raises(SMBResponseException, match=re.escape(expected)):
                watcher.wait()
        finally:
            connection.disconnect(True)

    def test_change_notify_cancel(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()
        session = Session(connection, smb_real[0], smb_real[1], require_encryption=False)
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "directory-watch")
        try:
            session.connect()
            tree.connect()

            open.create(ImpersonationLevel.Impersonation,
                        DirectoryAccessMask.MAXIMUM_ALLOWED,
                        FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
                        ShareAccess.FILE_SHARE_READ |
                        ShareAccess.FILE_SHARE_WRITE |
                        ShareAccess.FILE_SHARE_DELETE,
                        CreateDisposition.FILE_OPEN_IF,
                        CreateOptions.FILE_DIRECTORY_FILE)

            watcher = FileSystemWatcher(open)
            watcher.start(CompletionFilter.FILE_NOTIFY_CHANGE_FILE_NAME)
            assert watcher.result is None
            assert watcher.response_event.is_set() is False

            # Makes sure that we cancel after the async response has been returned from the server.
            while watcher._request.async_id is None:
                pass

            watcher.cancel()

            watcher.wait()
            assert watcher.cancelled is True
            assert watcher.result is None

            # Make sure it doesn't cause any weird errors when calling it again
            watcher.cancel()
        finally:
            connection.disconnect(True)

    def test_change_notify_on_a_file(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect()
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        open = Open(tree, "file-watch.txt")
        try:
            session.connect()
            tree.connect()

            open.create(ImpersonationLevel.Impersonation,
                        FilePipePrinterAccessMask.MAXIMUM_ALLOWED,
                        FileAttributes.FILE_ATTRIBUTE_NORMAL,
                        ShareAccess.FILE_SHARE_READ |
                        ShareAccess.FILE_SHARE_WRITE |
                        ShareAccess.FILE_SHARE_DELETE,
                        CreateDisposition.FILE_OPEN_IF,
                        CreateOptions.FILE_NON_DIRECTORY_FILE)

            watcher = FileSystemWatcher(open)
            watcher.start(CompletionFilter.FILE_NOTIFY_CHANGE_FILE_NAME)
            assert watcher.result is None
            assert watcher.response_event.is_set() is False

            expected = "Received unexpected status from the server: (3221225485) STATUS_INVALID_PARAMETER"
            with pytest.raises(SMBResponseException, match=re.escape(expected)):
                watcher.wait()
        finally:
            connection.disconnect(True)
