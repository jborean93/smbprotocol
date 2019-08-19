# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import six


def to_bytes(value, encoding='utf-8'):
    """
    Makes sure the value is encoded as a byte string.

    :param value: The Python string value to encode.
    :param encoding: The encoding to use.
    :return: The byte string that was encoded.
    """
    if isinstance(value, six.binary_type):
        return value
    return value.encode(encoding)


def to_text(value, encoding='utf-8'):
    """
    Makes sure the value is decoded as a text string.

    :param value: The Python byte string value to decode.
    :param encoding: The encoding to use.
    :return: The text/unicode string that was decoded.
    """
    if isinstance(value, six.text_type):
        return value
    return value.decode(encoding)


# On Python 2 a native string is a byte string and on Python 3 a native string is a text (unicode) string.
if six.PY2:  # pragma: no cover
    to_native = to_bytes
else:  # pragma: no cover
    to_native = to_text
