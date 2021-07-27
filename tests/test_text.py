# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from smbprotocol._text import (
    to_bytes,
    to_text,
)


def test_text_to_bytes_default():
    expected = b"\x61\x62\x63"
    actual = to_bytes(u"abc")
    assert actual == expected


def test_text_to_bytes_diff_encoding():
    expected = b"\x61\x00\x62\x00\x63\x00"
    actual = to_bytes(u"abc", encoding='utf-16-le')
    assert actual == expected


def test_bytes_to_bytes():
    expected = b"\x01\x02\x03\x04"
    actual = to_bytes(b"\x01\x02\x03\x04")
    assert actual == expected


def test_native_to_bytes():
    # Python 3 the default string type is unicode so the expected value will
    # be "abc" in UTF-16 form while Python 2 "abc" is the bytes representation
    # already
    expected = b"\x61\x00\x62\x00\x63\x00"
    actual = to_bytes("abc", encoding='utf-16-le')
    assert actual == expected


def test_text_to_text():
    expected = u"abc"
    actual = to_text(u"abc")
    assert actual == expected


def test_byte_to_text():
    expected = u"abc"
    actual = to_text(b"\x61\x62\x63")
    assert actual == expected


def test_byte_to_text_diff_encoding():
    expected = u"abc"
    actual = to_text(b"\x61\x00\x62\x00\x63\x00", encoding='utf-16-le')
    assert actual == expected


def test_native_to_unicode():
    expected = u"a\x00b\x00c\x00"
    actual = to_text("a\x00b\x00c\x00", encoding='utf-16-le')
    assert actual == expected
