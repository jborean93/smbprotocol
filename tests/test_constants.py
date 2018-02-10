import hashlib

import pytest
from cryptography.hazmat.primitives.ciphers import aead

from smbprotocol.connection import HashAlgorithms, Ciphers


def test_valid_hash_algorithm():
    expected = hashlib.sha512
    actual = HashAlgorithms.get_algorithm(0x1)
    assert actual == expected


def test_invalid_hash_algorithm():
    with pytest.raises(KeyError) as exc:
        HashAlgorithms.get_algorithm(0x2)
        assert False  # shouldn't be reached


def test_valid_cipher():
    expected = aead.AESCCM
    actual = Ciphers.get_cipher(0x1)
    assert actual == expected


def test_invalid_cipher():
    with pytest.raises(KeyError) as exc:
        Ciphers.get_cipher(0x3)
        assert False  # shouldn't be reached
