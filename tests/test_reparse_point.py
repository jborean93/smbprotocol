# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from smbprotocol._text import (
    to_bytes,
)

from smbprotocol.reparse_point import (
    ReparseDataBuffer,
    ReparseTags,
    SymbolicLinkFlags,
    SymbolicLinkReparseDataBuffer,
)


class TestReparseTags(object):

    def test_tag_is_microsoft(self):
        """
        Check if the test tag > = <tag > tag.

        Args:
            self: (todo): write your description
        """
        assert ReparseTags.is_reparse_tag_microsoft(ReparseTags.IO_REPARSE_TAG_SYMLINK)
        assert not ReparseTags.is_reparse_tag_microsoft(1)

    def test_tag_is_name_surrogate(self):
        """
        Check if the name tag is a valid name tag.

        Args:
            self: (todo): write your description
        """
        assert ReparseTags.is_reparse_tag_name_surrogate(ReparseTags.IO_REPARSE_TAG_SYMLINK)
        assert not ReparseTags.is_reparse_tag_name_surrogate(ReparseTags.IO_REPARSE_TAG_HSM)

    def test_tag_is_directory(self):
        """
        Check if the is a tag tag.

        Args:
            self: (todo): write your description
        """
        assert ReparseTags.is_reparse_tag_directory(ReparseTags.IO_REPARSE_TAG_CLOUD)
        assert not ReparseTags.is_reparse_tag_directory(ReparseTags.IO_REPARSE_TAG_SYMLINK)


class TestReparseDataBuffer(object):

    DATA = b"\x0c\x00\x00\xa0" \
           b"\x04\x00" \
           b"\x00\x00" \
           b"\x01\x02\x03\x04"

    def test_create_message(self):
        """
        Create a test message.

        Args:
            self: (todo): write your description
        """
        message = ReparseDataBuffer()
        message['reparse_tag'] = ReparseTags.IO_REPARSE_TAG_SYMLINK
        message['data_buffer'] = b"\x01\x02\x03\x04"

        actual = message.pack()
        assert len(message) == 12
        assert actual == self.DATA

    def test_parse_message(self):
        """
        Parses a message.

        Args:
            self: (todo): write your description
        """
        actual = ReparseDataBuffer()
        data = actual.unpack(self.DATA)

        assert data == b""
        assert len(actual) == 12
        assert actual['reparse_tag'].get_value() == ReparseTags.IO_REPARSE_TAG_SYMLINK
        assert actual['reparse_data_length'].get_value() == 4
        assert actual['data_buffer'].get_value() == b"\x01\x02\x03\x04"


class TestSymbolicLinkReparseDataBuffer(object):

    # Purposefully but the print name before sub name to test that the get_*_name() functions can handle any order.
    DATA = b"\x08\x00" \
           b"\x10\x00" \
           b"\x00\x00" \
           b"\x08\x00" \
           b"\x01\x00\x00\x00" \
           b"\x63\x00\x61\x00\x66\x00\xe9\x00" \
           b"\x5c\x00\x3f\x00\x3f\x00\x5c\x00" \
           b"\x63\x00\x61\x00\x66\x00\xe9\x00"

    def test_create_message(self):
        """
        Create a test message for a test message.

        Args:
            self: (todo): write your description
        """
        message = SymbolicLinkReparseDataBuffer()
        message['substitute_name_offset'] = 8
        message['substitute_name_length'] = 16
        message['print_name_offset'] = 0
        message['print_name_length'] = 8
        message['flags'] = SymbolicLinkFlags.SYMLINK_FLAG_RELATIVE
        message['buffer'] = to_bytes(u"café\\??\\café", encoding='utf-16-le')

        actual = message.pack()
        assert len(message) == 36
        assert actual == self.DATA

    def test_create_message_with_set_name(self):
        """
        Creates a test message with a message.

        Args:
            self: (todo): write your description
        """
        message = SymbolicLinkReparseDataBuffer()
        message.set_name(u"\\??\\café", u"café")
        message['flags'] = SymbolicLinkFlags.SYMLINK_FLAG_RELATIVE

        expected = b"\x00\x00" \
                   b"\x10\x00" \
                   b"\x10\x00" \
                   b"\x08\x00" \
                   b"\x01\x00\x00\x00" \
                   b"\x5c\x00\x3f\x00\x3f\x00\x5c\x00" \
                   b"\x63\x00\x61\x00\x66\x00\xe9\x00" \
                   b"\x63\x00\x61\x00\x66\x00\xe9\x00"

        actual = message.pack()
        assert len(message) == 36
        assert actual == expected

    def test_parse_message(self):
        """
        Parse a message.

        Args:
            self: (todo): write your description
        """
        actual = SymbolicLinkReparseDataBuffer()
        data = actual.unpack(self.DATA)

        assert data == b""
        assert len(actual) == 36
        assert actual['substitute_name_offset'].get_value() == 8
        assert actual['substitute_name_length'].get_value() == 16
        assert actual['print_name_offset'].get_value() == 0
        assert actual['print_name_length'].get_value() == 8
        assert actual['flags'].get_value() == SymbolicLinkFlags.SYMLINK_FLAG_RELATIVE
        assert actual['buffer'].get_value() == to_bytes(u"café\\??\\café", encoding='utf-16-le')
        assert actual.get_substitute_name() == u"\\??\\café"
        assert actual.get_print_name() == u"café"
