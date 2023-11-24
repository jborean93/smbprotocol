# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import types
import uuid
from collections import OrderedDict
from datetime import datetime, timezone

import pytest

from smbprotocol import Dialects
from smbprotocol.connection import Capabilities
from smbprotocol.header import Commands
from smbprotocol.structure import (
    BoolField,
    BytesField,
    DateTimeField,
    EnumField,
    FlagField,
    IntField,
    InvalidFieldDefinition,
    ListField,
    Structure,
    StructureField,
    TextField,
    UuidField,
    _bytes_to_hex,
)


def test_bytes_to_hex_pretty_newline():
    bytes_str = b"\x00\x01abc123new"
    expected = "00 01 61 62 63 31 32 33\n6E 65 77"
    actual = _bytes_to_hex(bytes_str, pretty=True)
    assert actual == expected


def test_bytes_to_hex_pretty_newline_override():
    bytes_str = b"\x00\x01abc123new"
    expected = "00 01 61 62\n63 31 32 33\n6E 65 77"
    actual = _bytes_to_hex(bytes_str, pretty=True, hex_per_line=4)
    assert actual == expected


def test_bytes_to_hex_pretty_nonewline():
    bytes_str = b"\x00\x01abc123new"
    expected = "00 01 61 62 63 31 32 33 6E 65 77"
    actual = _bytes_to_hex(bytes_str, pretty=True, hex_per_line=0)
    assert actual == expected


def test_bytes_to_hex_not_pretty():
    bytes_str = b"\x00\x01abc123new"
    expected = "00016162633132336e6577"
    actual = _bytes_to_hex(bytes_str, pretty=False)
    assert actual == expected


class Structure2(Structure):
    def __init__(self):
        self.fields = OrderedDict(
            [
                (
                    "field",
                    IntField(
                        size=4,
                        default=125,
                    ),
                ),
                (
                    "bytes",
                    BytesField(
                        size=4,
                        default=b"\x10\x11\x12\x13",
                    ),
                ),
            ]
        )
        super().__init__()


class Structure1(Structure):
    def __init__(self):
        self.fields = OrderedDict(
            [
                ("int_field", IntField(size=4)),
                ("bytes_field", BytesField(size=2)),
                (
                    "var_field",
                    BytesField(
                        size=lambda s: s["int_field"].get_value(),
                    ),
                ),
                (
                    "default_field",
                    IntField(
                        size=2,
                        default=b"\x01a",
                    ),
                ),
                (
                    "list_field",
                    ListField(
                        list_count=lambda s: s["int_field"].get_value(),
                        list_type=BytesField(size=8),
                        size=lambda s: s["int_field"].get_value() * 8,
                    ),
                ),
                (
                    "structure_length",
                    IntField(
                        size=2,
                        little_endian=False,
                        default=lambda s: len(s["structure_field"]),
                    ),
                ),
                (
                    "structure_field",
                    StructureField(
                        size=lambda s: s["structure_length"].get_value(),
                        structure_type=Structure2,
                    ),
                ),
            ]
        )

        super().__init__()


class TestStructure:
    def test_structure_defaults(self):
        actual = Structure1()
        assert len(actual.fields) == 7
        assert actual["int_field"].get_value() == 0
        assert actual["bytes_field"].get_value() == b""
        assert actual["var_field"].get_value() == b""
        assert actual["default_field"].get_value() == 24833
        assert actual["list_field"].get_value() == []
        assert actual["structure_length"].get_value() == 0
        assert actual["structure_field"].get_value() == b""

    def test_get_field(self):
        structure = Structure1()
        actual = structure["default_field"]
        assert actual.name == "default_field"
        assert actual.size == 2
        assert actual.get_value() == 24833

    def test_set_field(self):
        structure = Structure1()
        assert structure["int_field"].get_value() == 0
        structure["int_field"] = 10
        assert structure["int_field"].get_value() == 10

    def test_remove_field(self):
        structure = Structure1()
        assert len(structure.fields) == 7
        del structure["int_field"]
        assert len(structure.fields) == 6
        with pytest.raises(ValueError) as exc:
            value = structure["int_field"]
        assert str(exc.value) == "Structure does not contain field int_field"

    def test_pack_structure(self):
        structure = Structure1()
        sub_structure = Structure2()
        structure["int_field"] = 3
        structure["bytes_field"] = b"\x01\x02"
        structure["var_field"] = b"\x03\x04\x05"
        structure["list_field"] = [
            b"\x31\x00\x32\x00\x33\x00\x34\x00",
            b"1\x002\x003\x004\00",
            sub_structure,
        ]
        structure["structure_field"] = sub_structure

        expected = (
            b"\x03\x00\x00\x00"
            b"\x01\x02"
            b"\x03\x04\x05"
            b"\x01\x61"
            b"\x31\x00\x32\x00\x33\x00\x34\x00"
            b"\x31\x00\x32\x00\x33\x00\x34\x00"
            b"\x7d\x00\x00\x00\x10\x11\x12\x13"
            b"\x00\x08"
            b"\x7d\x00\x00\x00\x10\x11\x12\x13"
        )
        actual = structure.pack()
        assert actual == expected
        assert len(structure) == len(actual)

    def test_unpack_structure(self):
        packed_data = (
            b"\x03\x00\x00\x00"
            b"\x01\x02"
            b"\x03\x04\x05"
            b"\x01\x61"
            b"\x31\x00\x32\x00\x33\x00\x34\x00"
            b"\x31\x00\x32\x00\x33\x00\x34\x00"
            b"\x7d\x00\x00\x00\x10\x11\x12\x13"
            b"\x00\x08"
            b"\x7d\x00\x00\x00\x10\x11\x12\x13"
        )

        actual = Structure1()
        actual.unpack(packed_data)
        assert actual["int_field"].get_value() == 3
        assert actual["bytes_field"].get_value() == b"\x01\x02"
        assert actual["var_field"].get_value() == b"\x03\x04\x05"
        assert actual["default_field"].get_value() == 24833
        assert actual["list_field"].get_value() == [
            b"\x31\x00\x32\x00\x33\x00\x34\x00",
            b"\x31\x00\x32\x00\x33\x00\x34\x00",
            b"\x7d\x00\x00\x00\x10\x11\x12\x13",
        ]
        assert actual["structure_length"].get_value() == 8
        expected_struct = Structure2().pack()
        assert actual["structure_field"].get_value().pack() == expected_struct
        assert len(actual) == len(packed_data)

    def test_structure_string(self):
        structure = Structure1()
        sub_structure = Structure2()
        structure["int_field"] = 3
        structure["bytes_field"] = b"\x01\x02"
        structure["var_field"] = b"\x03\x04\x05"
        structure["list_field"] = [
            b"\x31\x00\x32\x00\x33\x00\x34\x00",
            b"1\x002\x003\x004\x00",
            sub_structure,
        ]
        structure["structure_field"] = sub_structure

        expected = """Structure1:
    int_field = 3
    bytes_field = 01 02
    var_field = 03 04 05
    default_field = 24833
    list_field = [
        31 00 32 00 33 00 34 00,
        31 00 32 00 33 00 34 00,
        Structure2:
            field = 125
            bytes = 10 11 12 13

            Raw Hex:
                7D 00 00 00 10 11 12 13
    ]
    structure_length = 8
    structure_field =
    Structure2:
        field = 125
        bytes = 10 11 12 13

        Raw Hex:
            7D 00 00 00 10 11 12 13

    Raw Hex:
        03 00 00 00 01 02 03 04
        05 01 61 31 00 32 00 33
        00 34 00 31 00 32 00 33
        00 34 00 7D 00 00 00 10
        11 12 13 00 08 7D 00 00
        00 10 11 12 13"""
        actual = str(structure)
        assert actual == expected

    def test_end_field_no_size(self):
        class Structure3(Structure):
            def __init__(self):
                self.fields = OrderedDict(
                    [
                        ("field", IntField(size=2, default=1)),
                        ("end", BytesField()),
                    ]
                )
                super().__init__()

        structure = Structure3()
        structure["end"] = b"\x01\x02\x03\x04"
        expected_pack = b"\x01\x00\x01\x02\x03\x04"
        actual_pack = structure.pack()
        assert actual_pack == expected_pack
        assert len(structure["end"]) == 4

        structure.unpack(b"\x02\x00\x05\x06\x07\x08\x09\x10")
        assert structure["field"].get_value() == 2
        assert structure["end"].get_value() == b"\x05\x06\x07\x08\x09\x10"
        assert len(structure["end"]) == 6


class TestIntField:
    class StructureTest(Structure):
        def __init__(self):
            self.fields = OrderedDict([("field", IntField(size=4, default=1234))])
            super().__init__()

    def test_get_size(self):
        field = self.StructureTest()["field"]
        expected = 4
        actual = len(field)
        assert actual == expected

    def test_to_string(self):
        field = self.StructureTest()["field"]
        expected = "1234"
        actual = str(field)
        assert actual == expected

    def test_get_value(self):
        field = self.StructureTest()["field"]
        expected = 1234
        actual = field.get_value()
        assert actual == expected

    def test_pack(self):
        field = self.StructureTest()["field"]
        expected = b"\xd2\x04\x00\x00"
        actual = field.pack()
        assert actual == expected

    def test_pack_signed(self):
        class UnsignedStructure(Structure):
            def __init__(self):
                self.fields = OrderedDict([("field", IntField(size=2, unsigned=False, default=-1))])
                super().__init__()

        field = UnsignedStructure()["field"]
        expected = b"\xff\xff"
        actual = field.pack()
        assert actual == expected

    def test_pack_with_lambda_size(self):
        structure = self.StructureTest()
        field = structure["field"]
        field.name = "field"
        field.structure = self.StructureTest
        field.size = lambda s: 2
        field.set_value(4)
        expected = b"\x04\x00"
        actual = field.pack()
        assert actual == expected

    def test_unpack(self):
        field = self.StructureTest()["field"]
        field.unpack(b"\xd2\x05\x00\x00")
        expected = 1490
        actual = field.get_value()
        assert actual == expected

    def test_invalid_size_none(self):
        with pytest.raises(InvalidFieldDefinition) as exc:
            IntField(size=None)
        assert str(exc.value) == "IntField size must have a value of 1, 2, 4, or 8 not None"

    def test_invalid_size_bad_int(self):
        with pytest.raises(InvalidFieldDefinition) as exc:
            IntField(size=3)
        assert str(exc.value) == "IntField size must have a value of 1, 2, 4, or 8 not 3"

    def test_set_none(self):
        field = self.StructureTest()["field"]
        field.set_value(None)
        expected = 0
        actual = field.get_value()
        assert isinstance(field.value, int)
        assert actual == expected

    def test_set_lambda(self):
        structure = self.StructureTest()
        field = structure["field"]
        field.name = "field"
        field.structure = self.StructureTest
        field.set_value(lambda s: 4567)
        expected = 4567
        actual = field.get_value()
        assert isinstance(field.value, types.LambdaType)
        assert actual == expected
        assert len(field) == 4

    def test_set_bytes(self):
        field = self.StructureTest()["field"]
        field.set_value(b"\x12\x34\x00\x00")
        expected = 13330
        actual = field.get_value()
        assert isinstance(field.value, int)
        assert actual == expected

    def test_set_int(self):
        field = self.StructureTest()["field"]
        field.set_value(9876)
        expected = 9876
        actual = field.get_value()
        assert isinstance(field.value, int)
        assert actual == expected

    def test_set_invalid(self):
        field = self.StructureTest()["field"]
        field.name = "field"
        with pytest.raises(TypeError) as exc:
            field.set_value([])
        assert str(exc.value) == "Cannot parse value for field field of type list to an int"

    def test_byte_order(self):
        class ByteOrderStructure(Structure):
            def __init__(self):
                self.fields = OrderedDict([("field", IntField(size=2, little_endian=False, default=10))])
                super().__init__()

        field = ByteOrderStructure()["field"]
        expected = b"\x00\x0a"
        actual = field.pack()
        assert actual == expected


class TestBytesField:
    class StructureTest(Structure):
        def __init__(self):
            self.fields = OrderedDict([("field", BytesField(size=4, default=b"\x10\x11\x12\x13"))])
            super().__init__()

    def test_get_size(self):
        field = self.StructureTest()["field"]
        expected = 4
        actual = len(field)
        assert actual == expected

    def test_to_string(self):
        field = self.StructureTest()["field"]
        expected = "10 11 12 13"
        actual = str(field)
        assert actual == expected

    def test_get_value(self):
        field = self.StructureTest()["field"]
        expected = b"\x10\x11\x12\x13"
        actual = field.get_value()
        assert actual == expected

    def test_pack(self):
        field = self.StructureTest()["field"]
        expected = b"\x10\x11\x12\x13"
        actual = field.pack()
        assert actual == expected

    def test_unpack(self):
        field = self.StructureTest()["field"]
        field.unpack(b"\x7a\x00\x79\x00")
        expected = b"\x7a\x00\x79\x00"
        actual = field.get_value()
        assert actual == expected

    def test_set_none(self):
        field = self.StructureTest()["field"]
        field.set_value(None)
        expected = b""
        actual = field.get_value()
        assert isinstance(field.value, bytes)
        assert actual == expected

    def test_set_lambda(self):
        structure = self.StructureTest()
        field = structure["field"]
        field.name = "field"
        field.structure = self.StructureTest
        field.set_value(lambda s: b"\x10\x11\x12\x13")
        expected = b"\x10\x11\x12\x13"
        actual = field.get_value()
        assert isinstance(field.value, types.LambdaType)
        assert actual == expected
        assert len(field) == 4

    def test_set_bytes(self):
        field = self.StructureTest()["field"]
        field.set_value(b"\x78\x00\x77\x00")
        expected = b"\x78\x00\x77\x00"
        actual = field.get_value()
        assert isinstance(field.value, bytes)
        assert actual == expected

    def test_set_int(self):
        field = self.StructureTest()["field"]
        field.set_value(11)
        expected = b"\x0b\x00\x00\x00"
        actual = field.get_value()
        assert isinstance(field.value, bytes)
        assert actual == expected

    def test_set_structure(self):
        field = self.StructureTest()["field"]
        field.size = 8
        field.set_value(Structure2())
        expected = b"\x7d\x00\x00\x00\x10\x11\x12\x13"
        actual = field.get_value()
        assert isinstance(field.value, bytes)
        assert actual == expected
        assert len(field) == 8

    def test_set_invalid(self):
        field = self.StructureTest()["field"]
        field.name = "field"
        with pytest.raises(TypeError) as exc:
            field.set_value([])
        assert str(exc.value) == "Cannot parse value for field field of type list to a byte string"

    def test_pack_invalid_size(self):
        field = self.StructureTest()["field"]
        field.name = "field"
        field.set_value(b"\x01\x02")
        assert len(field) == 2
        with pytest.raises(ValueError) as exc:
            field.pack()
        assert str(exc.value) == "Invalid packed data length for field field of 2 does not fit field size of 4"

    def test_set_int_invalid_size(self):
        class InvalidSizeStructure(Structure):
            def __init__(self):
                self.fields = OrderedDict([("field", BytesField(size=3))])
                super().__init__()

        with pytest.raises(InvalidFieldDefinition) as exc:
            field = InvalidSizeStructure()["field"]
            field.set_value(1)
        assert str(exc.value) == "Cannot struct format of size 3"

    def test_set_invalid_size(self):
        class InvalidSizeStructure(Structure):
            def __init__(self):
                self.fields = OrderedDict([("field", BytesField(size="a"))])
                super().__init__()

        with pytest.raises(InvalidFieldDefinition) as exc:
            InvalidSizeStructure()
        assert str(exc.value) == "BytesField size for field must be an int or None for a variable length"


class TestListField:
    # unpack variable length list

    class StructureTest(Structure):
        def __init__(self):
            self.fields = OrderedDict(
                [
                    (
                        "field",
                        ListField(
                            size=4, list_count=2, list_type=BytesField(size=2), default=[b"\x01\x02", b"\x03\x04"]
                        ),
                    )
                ]
            )
            super().__init__()

    def test_get_size(self):
        field = self.StructureTest()["field"]
        expected = 4
        actual = len(field)
        assert actual == expected

    def test_get_item(self):
        field = self.StructureTest()["field"]
        assert field[0] == b"\x01\x02"
        assert field[1] == b"\x03\x04"

    def test_to_string(self):
        field = self.StructureTest()["field"]
        expected = "[\n    01 02,\n    03 04\n]"
        actual = str(field)
        assert actual == expected

    def test_to_string_empty(self):
        field = self.StructureTest()["field"]
        field.set_value([])
        expected = "[]"
        actual = str(field)
        assert actual == expected

    def test_get_value(self):
        field = self.StructureTest()["field"]
        expected = [b"\x01\x02", b"\x03\x04"]
        actual = field.get_value()
        assert actual == expected

    def test_pack(self):
        field = self.StructureTest()["field"]
        expected = b"\x01\x02\x03\x04"
        actual = field.pack()
        assert actual == expected

    def test_unpack(self):
        field = self.StructureTest()["field"]
        data = field.unpack(b"\x7a\x00\x79\x00")
        expected = [b"\x7a\x00", b"\x79\x00"]
        actual = field.get_value()
        assert actual == expected

    def test_unpack_func(self):
        class UnpackListStructure(Structure):
            def __init__(self):
                self.fields = OrderedDict(
                    [("field", ListField(size=7, unpack_func=lambda s, d: [b"\x01\x02", b"\x03\x04\x05\x06", b"\07"]))]
                )
                super().__init__()

        field = UnpackListStructure()["field"]
        field.unpack(b"\x00")
        expected = [b"\x01\x02", b"\x03\x04\x05\x06", b"\07"]
        actual = field.get_value()
        assert len(field) == 7
        assert actual == expected

    def test_set_none(self):
        field = self.StructureTest()["field"]
        field.set_value(None)
        expected = []
        actual = field.get_value()
        assert isinstance(field.value, list)
        assert actual == expected
        assert len(field) == 0
        assert len(field.get_value()) == 0

    def test_set_lambda_as_bytes(self):
        structure = self.StructureTest()
        field = structure["field"]
        field.name = "field"
        field.structure = self.StructureTest
        field.set_value(lambda s: b"\x10\x11\x12\x13")
        expected = [b"\x10\x11", b"\x12\x13"]
        actual = field.get_value()
        assert isinstance(field.value, types.LambdaType)
        assert actual == expected
        assert len(field) == 4

    def test_set_lambda_as_list(self):
        structure = self.StructureTest()
        field = structure["field"]
        field.name = "field"
        field.structure = self.StructureTest
        field.set_value(lambda s: [b"\x10\x11", b"\x12\x13"])
        expected = [b"\x10\x11", b"\x12\x13"]
        actual = field.get_value()
        assert isinstance(field.value, types.LambdaType)
        assert actual == expected
        assert len(field) == 4

    def test_set_bytes_fixed(self):
        field = self.StructureTest()["field"]
        field.set_value(b"\x78\x00\x77\x00")
        expected = [b"\x78\x00", b"\x77\x00"]
        actual = field.get_value()
        assert isinstance(field.value, list)
        assert actual == expected

    def test_set_list(self):
        field = self.StructureTest()["field"]
        field.set_value([b"\x7d\x00", b"\x00\x00"])
        expected = [b"\x7d\x00", b"\x00\x00"]
        actual = field.get_value()
        assert isinstance(field.value, list)
        assert actual == expected
        assert len(field) == 4
        assert len(field.get_value()) == 2

    def test_set_invalid(self):
        field = self.StructureTest()["field"]
        field.name = "field"
        with pytest.raises(TypeError) as exc:
            field.set_value(0)
        assert str(exc.value) == "Cannot parse value for field field of type int to a list"

    def test_list_count_not_int_or_lambda(self):
        class InvalidListField(Structure):
            def __init__(self):
                self.fields = OrderedDict([("field", ListField(list_count="a"))])
                super().__init__()

        with pytest.raises(InvalidFieldDefinition) as exc:
            InvalidListField()
        assert str(exc.value) == "ListField list_count must be an int, lambda, or None for a variable list length"

    def test_unpack_func_not_lambda(self):
        class InvalidListField(Structure):
            def __init__(self):
                self.fields = OrderedDict([("field", ListField(unpack_func="a"))])
                super().__init__()

        with pytest.raises(InvalidFieldDefinition) as exc:
            InvalidListField()
        assert str(exc.value) == "ListField unpack_func must be a lambda function or None"

    def test_list_field_not_field(self):
        class InvalidListField(Structure):
            def __init__(self):
                self.fields = OrderedDict([("field", ListField(list_type="a"))])
                super().__init__()

        with pytest.raises(InvalidFieldDefinition) as exc:
            InvalidListField()
        assert str(exc.value) == "ListField list_type must be a Field definition"

    def test_list_unpack_list_type_size_not_defined(self):
        class InvalidListField(Structure):
            def __init__(self):
                self.fields = OrderedDict([("field", ListField(list_count=1))])
                super().__init__()

        with pytest.raises(InvalidFieldDefinition) as exc:
            InvalidListField()
        assert (
            str(exc.value) == "ListField must either define unpack_func "
            "as a lambda or set list_count and "
            "list_size with a size"
        )

    def test_list_unpack_list_count_not_defined(self):
        class InvalidListField(Structure):
            def __init__(self):
                self.fields = OrderedDict([("field", ListField(list_type=BytesField(size=1)))])
                super().__init__()

        with pytest.raises(InvalidFieldDefinition) as exc:
            InvalidListField()
        assert (
            str(exc.value) == "ListField must either define unpack_func "
            "as a lambda or set list_count and "
            "list_size with a size"
        )


class TestStructureField:
    class StructureTest(Structure):
        def __init__(self):
            self.fields = OrderedDict(
                [
                    (
                        "field",
                        StructureField(size=8, structure_type=Structure2, default=b"\x7d\x00\x00\x00\x10\x11\x12\x13"),
                    )
                ]
            )
            super().__init__()

    def test_get_size(self):
        field = self.StructureTest()["field"]
        expected = 8
        actual = len(field)
        assert actual == expected

    def test_to_string(self):
        field = self.StructureTest()["field"]
        expected = """Structure2:
    field = 125
    bytes = 10 11 12 13

    Raw Hex:
        7D 00 00 00 10 11 12 13"""
        actual = str(field)
        assert actual == expected

    def test_get_value(self):
        field = self.StructureTest()["field"]
        expected = Structure2()
        actual = field.get_value()
        assert actual.pack() == expected.pack()

    def test_pack(self):
        field = self.StructureTest()["field"]
        expected = b"\x7d\x00\x00\x00\x10\x11\x12\x13"
        actual = field.pack()
        assert actual == expected

    def test_pack_without_type(self):
        field = self.StructureTest()["field"]
        field.structure_type = None

        test_value = b"\x7d\x00\x00\x00\x14\x15\x16\x17"
        field.set_value(test_value)
        actual = field.pack()
        assert actual == test_value

    def test_unpack(self):
        field = self.StructureTest()["field"]
        field.unpack(b"\x7d\x00\x00\x00\x14\x15\x16\x17")
        expected = b"\x7d\x00\x00\x00\x14\x15\x16\x17"
        actual = field.get_value()
        assert actual.pack() == expected
        assert isinstance(actual, Structure2)

    def test_unpack_without_type(self):
        field = self.StructureTest()["field"]
        field.structure_type = None
        field.unpack(b"\x7d\x00\x00\x00\x14\x15\x16\x17")
        expected = b"\x7d\x00\x00\x00\x14\x15\x16\x17"
        actual = field.get_value()
        assert actual == expected

    def test_set_none(self):
        field = self.StructureTest()["field"]
        field.set_value(None)
        expected = b""
        actual = field.get_value()
        assert isinstance(field.value, bytes)
        assert actual == expected

    def test_set_empty_byte(self):
        field = self.StructureTest()["field"]
        field.set_value(b"")
        expected = b""
        actual = field.get_value()
        assert isinstance(field.value, bytes)
        assert actual == expected

    def test_set_lambda(self):
        structure = self.StructureTest()
        field = structure["field"]
        field.name = "field"
        field.structure = self.StructureTest
        field.set_value(lambda s: b"\x7d\x00\x00\x00\x14\x15\x16\x17")
        expected = b"\x7d\x00\x00\x00\x14\x15\x16\x17"
        actual = field.get_value()
        assert isinstance(field.value, types.LambdaType)
        assert actual.pack() == expected
        assert isinstance(actual, Structure2)
        assert len(field) == 8

    def test_set_lambda_without_type(self):
        structure = self.StructureTest()
        field = structure["field"]
        field.name = "field"
        field.structure = self.StructureTest
        field.structure_type = None
        field.set_value(lambda s: b"\x7d\x00\x00\x00\x14\x15\x16\x17")
        expected = b"\x7d\x00\x00\x00\x14\x15\x16\x17"
        actual = field.get_value()
        assert isinstance(field.value, types.LambdaType)
        assert actual == expected
        assert isinstance(actual, bytes)
        assert len(field) == 8

    def test_set_bytes(self):
        field = self.StructureTest()["field"]
        field.set_value(b"\x7d\x00\x00\x00\x14\x15\x16\x17")
        expected = b"\x7d\x00\x00\x00\x14\x15\x16\x17"
        actual = field.get_value()
        assert isinstance(field.value, Structure2)
        assert actual.pack() == expected

    def test_set_bytes_without_type(self):
        field = self.StructureTest()["field"]
        field.structure_type = None
        field.set_value(b"\x7d\x00\x00\x00\x14\x15\x16\x17")
        expected = b"\x7d\x00\x00\x00\x14\x15\x16\x17"
        actual = field.get_value()
        assert isinstance(field.value, bytes)
        assert actual == expected

    def test_set_bytes_then_structure_type(self):
        field = self.StructureTest()["field"]
        field.structure_type = None
        field.set_value(b"\x7d\x00\x00\x00\x14\x15\x16\x17")
        expected = b"\x7d\x00\x00\x00\x14\x15\x16\x17"
        actual = field.get_value()
        assert isinstance(field.value, bytes)
        assert actual == expected
        field.set_structure_type(Structure2)

        actual = field.get_value()
        assert isinstance(field.value, Structure2)
        assert actual.pack() == expected

    def test_set_bytes_with_lambda_type(self):
        field = self.StructureTest()["field"]
        field.structure_type = lambda s: Structure2
        field.set_value(b"\x7d\x00\x00\x00\x14\x15\x16\x17")
        expected = b"\x7d\x00\x00\x00\x14\x15\x16\x17"
        actual = field.get_value()
        assert isinstance(field.value, Structure2)
        assert actual.pack() == expected

    def test_set_structure(self):
        field = self.StructureTest()["field"]
        expected = b"\x7d\x00\x00\x00\x10\x11\x12\x13"
        actual = field.get_value()
        assert isinstance(field.value, Structure)
        assert actual.pack() == expected
        assert len(field) == 8

    def test_get_structure_field(self):
        field = self.StructureTest()["field"]
        expected = 125
        actual = field["field"].get_value()
        assert actual == expected

    def test_fail_get_structure_field_missing(self):
        field = self.StructureTest()["field"]
        with pytest.raises(ValueError) as exc:
            field["fake"]
        assert str(exc.value) == "Structure does not contain field fake"

    def test_fail_get_structure_bytes_value(self):
        field = self.StructureTest()["field"]
        field.structure_type = None
        field.set_value(b"\x7d\x00\x00\x00\x14\x15\x16\x17")
        with pytest.raises(ValueError) as exc:
            field["field"]
        assert str(exc.value) == "Cannot get field field when structure is defined as a byte string"

    def test_set_structure_field(self):
        field = self.StructureTest()["field"]
        test_value = 100
        field["field"] = test_value
        actual = field["field"].get_value()
        assert actual == test_value
        # test out the normal path (convoluted way)
        assert field.get_value()["field"].get_value() == test_value

    def test_set_invalid(self):
        field = self.StructureTest()["field"]
        field.name = "field"
        with pytest.raises(TypeError) as exc:
            field.set_value([])
        assert str(exc.value) == "Cannot parse value for field field of type list to a structure"


class TestUuidField:
    class StructureTest(Structure):
        def __init__(self):
            self.fields = OrderedDict([("field", UuidField())])
            super().__init__()

    def test_get_size(self):
        field = self.StructureTest()["field"]
        expected = 16
        actual = len(field)
        assert actual == expected

    def test_to_string(self):
        field = self.StructureTest()["field"]
        expected = "00000000-0000-0000-0000-000000000000"
        actual = str(field)
        assert actual == expected

    def test_get_value(self):
        field = self.StructureTest()["field"]
        expected = uuid.UUID("00000000-0000-0000-0000-000000000000")
        actual = field.get_value()
        assert actual == expected

    def test_pack(self):
        field = self.StructureTest()["field"]
        expected = b"\x00" * 16
        actual = field.pack()
        assert actual == expected

    def test_unpack(self):
        field = self.StructureTest()["field"]
        field.unpack(b"\x11" * 16)
        expected = uuid.UUID(bytes=b"\x11" * 16)
        actual = field.get_value()
        assert actual == expected

    def test_set_none(self):
        field = self.StructureTest()["field"]
        field.set_value(None)
        expected = uuid.UUID("00000000-0000-0000-0000-000000000000")
        actual = field.get_value()
        assert isinstance(field.value, uuid.UUID)
        assert actual == expected

    def test_set_lambda(self):
        structure = self.StructureTest()
        field = structure["field"]
        field.name = "field"
        field.structure = self.StructureTest
        field.set_value(lambda s: uuid.UUID(bytes=b"\x11" * 16))
        expected = uuid.UUID(bytes=b"\x11" * 16)
        actual = field.get_value()
        assert isinstance(field.value, types.LambdaType)
        assert actual == expected
        assert len(field) == 16

    def test_set_bytes(self):
        field = self.StructureTest()["field"]
        field.set_value(b"\x22" * 16)
        expected = uuid.UUID(bytes=b"\x22" * 16)
        actual = field.get_value()
        assert isinstance(field.value, uuid.UUID)
        assert actual == expected

    def test_set_int(self):
        field = self.StructureTest()["field"]
        field.set_value(45370982256125128461783280990902428194)
        expected = uuid.UUID(int=45370982256125128461783280990902428194)
        actual = field.get_value()
        assert isinstance(field.value, uuid.UUID)
        assert actual == expected

    def test_set_invalid(self):
        field = self.StructureTest()["field"]
        field.name = "field"
        with pytest.raises(TypeError) as exc:
            field.set_value([])
        assert str(exc.value) == "Cannot parse value for field field of type list to a uuid"

    def test_invalid_size_none(self):
        with pytest.raises(InvalidFieldDefinition) as exc:
            UuidField(size=8)
        assert str(exc.value) == "UuidField type must have a size of 16 not 8"

    def test_pack_uuid_field_big_endian(self):
        field = self.StructureTest()["field"]
        field.little_endian = False
        field.set_value(uuid.UUID("00000001-0001-0001-0001-000000000001"))
        expected = b"\x01\x00\x00\x00\x01\x00\x01\x00" b"\x00\x01\x00\x00\x00\x00\x00\x01"
        actual = field.pack()
        assert actual == expected

    def test_unpack_uuid_field_big_endian(self):
        field = self.StructureTest()["field"]
        field.little_endian = False
        field.unpack(b"\x01\x00\x00\x00\x01\x00\x01\x00" b"\x00\x01\x00\x00\x00\x00\x00\x01")
        expected = uuid.UUID("00000001-0001-0001-0001-000000000001")
        actual = field.get_value()
        assert actual == expected


class TestDateTimeField:
    DATE = datetime(year=1993, month=6, day=11, hour=7, minute=52, second=34, microsecond=34)

    class StructureTest(Structure):
        def __init__(self):
            self.fields = OrderedDict(
                [
                    (
                        "field",
                        DateTimeField(
                            default=TestDateTimeField.DATE,
                        ),
                    )
                ]
            )
            super().__init__()

    @pytest.mark.parametrize(
        "raw, expected_dt, expected_bytes",
        [
            (
                b"\x00\x00\x00\x00\x00\x00\x00\x00",
                datetime(1601, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
                b"\x00\x00\x00\x00\x00\x00\x00\x00",
            ),
            (
                b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                datetime(9999, 12, 31, 23, 59, 59, 999999),
                b"\xF6\x3F\xC0\xD1\x5E\x5A\xC8\x24",
            ),
        ],
        ids=["origin", "end"],
    )
    def test_pack_unpack_dates(self, raw, expected_dt, expected_bytes):
        obj = self.StructureTest()
        obj.unpack(raw)

        field = obj["field"]
        actual = field.get_value()
        assert actual == expected_dt

        actual = field.pack()
        assert actual == expected_bytes

    def test_get_size(self):
        field = self.StructureTest()["field"]
        expected = 8
        actual = len(field)
        assert actual == expected

    def test_to_string(self):
        field = self.StructureTest()["field"]
        expected = "1993-06-11 07:52:34.000034"
        actual = str(field)
        assert actual == expected

    def test_get_value(self):
        field = self.StructureTest()["field"]
        expected = self.DATE
        actual = field.get_value()
        assert actual == expected

    def test_pack(self):
        field = self.StructureTest()["field"]
        expected = b"\x54\x0e\x63\x5e\x2d\xfa\xb7\x01"
        actual = field.pack()
        assert actual == expected

    def test_unpack(self):
        field = self.StructureTest()["field"]
        field.unpack(b"\x5e\x70\x27\x4a\x6e\x23\x93\x01")
        expected = datetime(
            year=1960,
            month=8,
            day=1,
            hour=22,
            minute=7,
            second=1,
            microsecond=186774,
            tzinfo=timezone.utc,
        )
        actual = field.get_value()
        assert actual == expected

    def test_set_none(self):
        field = self.StructureTest()["field"]
        field.set_value(None)
        expected = datetime.today()
        actual = field.get_value()
        assert isinstance(field.value, datetime)
        assert actual.year == expected.year
        assert actual.month == expected.month
        assert actual.day == expected.day

    def test_set_lambda(self):
        structure = self.StructureTest()
        field = structure["field"]
        field.name = "field"
        field.structure = self.StructureTest
        field.set_value(
            lambda s: datetime(
                year=1960,
                month=8,
                day=2,
                hour=8,
                minute=7,
                second=1,
                microsecond=186774,
                tzinfo=timezone.utc,
            )
        )
        expected = datetime(
            year=1960,
            month=8,
            day=2,
            hour=8,
            minute=7,
            second=1,
            microsecond=186774,
            tzinfo=timezone.utc,
        )
        actual = field.get_value()
        assert isinstance(field.value, types.LambdaType)
        assert actual == expected
        assert len(field) == 8

    def test_set_bytes(self):
        field = self.StructureTest()["field"]
        field.set_value(b"\x00\x67\x7b\x21\x3d\x5d\xd3\x01")
        expected = datetime(
            year=2017,
            month=11,
            day=14,
            hour=11,
            minute=38,
            second=46,
            tzinfo=timezone.utc,
        )
        actual = field.get_value()
        assert isinstance(field.value, datetime)
        assert actual == expected

    def test_set_int(self):
        field = self.StructureTest()["field"]
        field.set_value(131551331260000000)
        expected = datetime(
            year=2017,
            month=11,
            day=14,
            hour=11,
            minute=38,
            second=46,
            tzinfo=timezone.utc,
        )
        actual = field.get_value()
        assert isinstance(field.value, datetime)
        assert actual == expected

    def test_set_datetime(self):
        field = self.StructureTest()["field"]
        datetime_value = datetime(year=2017, month=11, day=14, hour=21, minute=38, second=46)
        field.set_value(datetime_value)
        actual = field.get_value()
        assert isinstance(field.value, datetime)
        assert actual == datetime_value

    def test_set_invalid(self):
        field = self.StructureTest()["field"]
        field.name = "field"
        with pytest.raises(TypeError) as exc:
            field.set_value([])
        assert str(exc.value) == "Cannot parse value for field field of type list to a datetime"

    def test_invalid_size_none(self):
        with pytest.raises(InvalidFieldDefinition) as exc:
            DateTimeField(size=4)
        assert str(exc.value) == "DateTimeField type must have a size of 8 not 4"


class TestEnumField:
    class StructureTest(Structure):
        def __init__(self):
            self.fields = OrderedDict(
                [
                    (
                        "field",
                        EnumField(
                            size=1,
                            enum_type=Commands,
                            default=Commands.SMB2_IOCTL,
                        ),
                    ),
                ]
            )
            super().__init__()

    def test_get_size(self):
        field = self.StructureTest()["field"]
        expected = 1
        actual = len(field)
        assert actual == expected

    def test_to_string(self):
        field = self.StructureTest()["field"]
        expected = "(11) SMB2_IOCTL"
        actual = str(field)
        assert actual == expected

    def test_to_string_default_as_zero(self):
        class StructureTestDefaultZero(Structure):
            def __init__(self):
                self.fields = OrderedDict(
                    [
                        (
                            "field",
                            EnumField(
                                size=2,
                                enum_type=Dialects,
                            ),
                        )
                    ]
                )
                super().__init__()

        field = StructureTestDefaultZero()["field"]
        expected = "(0) UNKNOWN_ENUM"
        actual = str(field)
        assert actual == expected

    def test_get_value(self):
        field = self.StructureTest()["field"]
        expected = 11
        actual = field.get_value()
        assert actual == expected

    def test_pack(self):
        field = self.StructureTest()["field"]
        expected = b"\x0b"
        actual = field.pack()
        assert actual == expected

    def test_unpack(self):
        field = self.StructureTest()["field"]
        field.unpack(b"\x0b")
        expected = 11
        actual = field.get_value()
        assert actual == expected

    def test_set_none(self):
        field = self.StructureTest()["field"]
        field.set_value(None)
        expected = 0
        actual = field.get_value()
        assert actual == expected
        assert isinstance(field.value, int)
        assert str(field) == "(0) SMB2_NEGOTIATE"

    def test_set_bytes(self):
        field = self.StructureTest()["field"]
        field.set_value(b"\x08")
        expected = 8
        actual = field.get_value()
        assert actual == expected
        assert isinstance(field.value, int)
        assert str(field) == "(8) SMB2_READ"

    def test_set_int(self):
        field = self.StructureTest()["field"]
        field.set_value(8)
        expected = 8
        actual = field.get_value()
        assert actual == expected
        assert isinstance(field.value, int)
        assert str(field) == "(8) SMB2_READ"

    def test_set_invalid(self):
        field = self.StructureTest()["field"]
        field.name = "field"
        with pytest.raises(TypeError) as exc:
            field.set_value([])
        assert str(exc.value) == "Cannot parse value for field field of type list to an int"

    def test_set_invalid_value(self):
        field = self.StructureTest()["field"]
        with pytest.raises(ValueError) as exc:
            field.set_value(0x13)
        assert str(exc.value) == "Enum value 19 does not exist in enum type <class 'smbprotocol.header.Commands'>"


class TestFlagField:
    class StructureTest(Structure):
        def __init__(self):
            self.fields = OrderedDict(
                [
                    (
                        "field",
                        FlagField(
                            size=4,
                            flag_type=Capabilities,
                            default=Capabilities.SMB2_GLOBAL_CAP_LEASING | Capabilities.SMB2_GLOBAL_CAP_ENCRYPTION,
                        ),
                    ),
                ]
            )
            super().__init__()

    def test_get_size(self):
        field = self.StructureTest()["field"]
        expected = 4
        actual = len(field)
        assert actual == expected

    def test_to_string(self):
        field = self.StructureTest()["field"]
        expected = "(66) SMB2_GLOBAL_CAP_ENCRYPTION, SMB2_GLOBAL_CAP_LEASING"
        actual = str(field)
        assert actual == expected

    def test_get_value(self):
        field = self.StructureTest()["field"]
        expected = 66
        actual = field.get_value()
        assert actual == expected

    def test_pack(self):
        field = self.StructureTest()["field"]
        expected = b"\x42\x00\x00\x00"
        actual = field.pack()
        assert actual == expected

    def test_unpack(self):
        field = self.StructureTest()["field"]
        field.unpack(b"\x4a\x00\x00\x00")
        expected = 74
        actual = field.get_value()
        assert actual == expected

    def test_set_none(self):
        field = self.StructureTest()["field"]
        field.set_value(None)
        expected = 0
        actual = field.get_value()
        assert actual == expected
        assert isinstance(field.value, int)
        assert str(field) == "0"

    def test_set_bytes(self):
        field = self.StructureTest()["field"]
        field.set_value(b"\x08\x00\x00\x00")
        expected = 8
        actual = field.get_value()
        assert actual == expected
        assert isinstance(field.value, int)
        assert str(field) == "(8) SMB2_GLOBAL_CAP_MULTI_CHANNEL"

    def test_set_int(self):
        field = self.StructureTest()["field"]
        field.set_value(8)
        expected = 8
        actual = field.get_value()
        assert actual == expected
        assert isinstance(field.value, int)
        assert str(field) == "(8) SMB2_GLOBAL_CAP_MULTI_CHANNEL"

    def test_set_invalid(self):
        field = self.StructureTest()["field"]
        field.name = "field"
        with pytest.raises(TypeError) as exc:
            field.set_value([])
        assert str(exc.value) == "Cannot parse value for field field of type list to an int"

    def test_check_flag_set(self):
        field = self.StructureTest()["field"]
        assert field.has_flag(Capabilities.SMB2_GLOBAL_CAP_ENCRYPTION)
        assert not field.has_flag(Capabilities.SMB2_GLOBAL_CAP_MULTI_CHANNEL)

    def test_set_flag(self):
        field = self.StructureTest()["field"]
        assert not field.has_flag(Capabilities.SMB2_GLOBAL_CAP_MULTI_CHANNEL)
        field.set_flag(Capabilities.SMB2_GLOBAL_CAP_MULTI_CHANNEL)
        assert field.has_flag(Capabilities.SMB2_GLOBAL_CAP_MULTI_CHANNEL)

    def test_set_invalid_flag(self):
        field = self.StructureTest()["field"]
        with pytest.raises(ValueError) as ex:
            field.set_flag(10)
        assert str(ex.value) == "Flag value does not exist in flag type <class 'smbprotocol.connection.Capabilities'>"

    def test_set_invalid_value(self):
        field = self.StructureTest()["field"]
        with pytest.raises(ValueError) as exc:
            field.set_value(0x00000082)
        assert str(exc.value) == "Invalid flag for field field value set 128"


class TestBoolField:
    class StructureTest(Structure):
        def __init__(self):
            self.fields = OrderedDict([("field", BoolField(size=1))])
            super().__init__()

    def test_get_size(self):
        field = self.StructureTest()["field"]
        expected = 1
        actual = len(field)
        assert actual == expected

    def test_to_string(self):
        field = self.StructureTest()["field"]
        expected = "False"
        actual = str(field)
        assert actual == expected

    def test_to_string_true(self):
        field = self.StructureTest()["field"]
        field.set_value(True)
        expected = "True"
        actual = str(field)
        assert actual == expected

    def test_get_value(self):
        field = self.StructureTest()["field"]
        expected = False
        actual = field.get_value()
        assert actual == expected

    def test_get_value_true(self):
        field = self.StructureTest()["field"]
        field.set_value(True)
        expected = True
        actual = field.get_value()
        assert actual == expected

    def test_pack(self):
        field = self.StructureTest()["field"]
        expected = b"\x00"
        actual = field.pack()
        assert actual == expected

    def test_pack_true(self):
        field = self.StructureTest()["field"]
        field.set_value(True)
        expected = b"\x01"
        actual = field.pack()
        assert actual == expected

    def test_unpack(self):
        field = self.StructureTest()["field"]
        field.unpack(b"\x00")
        expected = False
        actual = field.get_value()
        assert actual == expected

    def test_unpack_true(self):
        field = self.StructureTest()["field"]
        field.unpack(b"\x01")
        expected = True
        actual = field.get_value()
        assert actual == expected

    def test_invalid_size_bad_int(self):
        with pytest.raises(InvalidFieldDefinition) as exc:
            BoolField(size=2)
        assert str(exc.value) == "BoolField size must have a value of 1, not 2"

    def test_set_none(self):
        field = self.StructureTest()["field"]
        field.set_value(None)
        expected = False
        actual = field.get_value()
        assert isinstance(field.value, bool)
        assert actual == expected

    def test_set_bytes(self):
        field = self.StructureTest()["field"]
        field.set_value(b"\x01")
        expected = True
        actual = field.get_value()
        assert isinstance(field.value, bool)
        assert actual == expected

    def test_set_bool(self):
        field = self.StructureTest()["field"]
        field.set_value(True)
        expected = True
        actual = field.get_value()
        assert isinstance(field.value, bool)
        assert actual == expected

    def test_set_lambda(self):
        structure = self.StructureTest()
        field = structure["field"]
        field.name = "field"
        field.structure = self.StructureTest
        field.set_value(lambda s: True)
        expected = True
        actual = field.get_value()
        assert isinstance(field.value, types.LambdaType)
        assert actual == expected
        assert len(field) == 1

    def test_set_invalid(self):
        field = self.StructureTest()["field"]
        field.name = "field"
        with pytest.raises(TypeError) as exc:
            field.set_value([])
        assert str(exc.value) == "Cannot parse value for field field of type list to a bool"


class TestTextField:
    STRING_VALUE = "Hello World - café"

    class StructureTest(Structure):
        def __init__(self):
            self.fields = OrderedDict([("field", TextField(encoding="utf-8", default=TestTextField.STRING_VALUE))])
            super().__init__()

    def test_get_size(self):
        field = self.StructureTest()["field"]
        expected = 19
        actual = len(field)
        if field.null_terminated:
            expected += len("\x00".encode(field.encoding))
        assert actual == expected

    def test_to_string(self):
        field = self.StructureTest()["field"]
        expected = "Hello World - café"
        actual = str(field)
        assert actual == expected
        assert field.get_value() == self.STRING_VALUE  # Make's sure the value is a unicode string

    def test_get_value(self):
        field = self.StructureTest()["field"]
        expected = self.STRING_VALUE
        actual = field.get_value()
        assert actual == expected

    def test_pack(self):
        field = self.StructureTest()["field"]
        expected = b"\x48\x65\x6c\x6c\x6f\x20\x57\x6f" b"\x72\x6c\x64\x20\x2d\x20\x63\x61" b"\x66\xc3\xa9"
        if field.null_terminated:
            expected += "\x00".encode(field.encoding)
        actual = field.pack()
        assert actual == expected

    def test_unpack(self):
        field = self.StructureTest()["field"]
        field.unpack(b"\x48\x65\x6c\x6c\x6f\x20\x57\x6f" b"\x72\x6c\x64\x20\x2d\x20\x63\x61" b"\x66\xc3\xa9")
        expected = self.STRING_VALUE
        actual = field.get_value()
        assert actual == expected

    def test_set_lambda(self):
        structure = self.StructureTest()
        field = structure["field"]
        field.name = "field"
        field.structure = self.StructureTest
        field.set_value(lambda s: self.STRING_VALUE)
        expected = self.STRING_VALUE
        actual = field.get_value()
        actual_length = 19
        if field.null_terminated:
            actual_length += len("\x00".encode(field.encoding))
        assert isinstance(field.value, types.LambdaType)
        assert actual == expected
        assert len(field) == actual_length

    def test_set_bytes(self):
        field = self.StructureTest()["field"]
        field.set_value(self.STRING_VALUE.encode("utf-8"))
        expected = self.STRING_VALUE
        actual = field.get_value()
        assert isinstance(field.value, str)
        assert actual == expected

    def test_set_none(self):
        field = self.StructureTest()["field"]
        field.set_value(None)
        expected = ""
        actual = field.get_value()
        assert isinstance(field.value, str)
        assert actual == expected

    def test_set_invalid(self):
        field = self.StructureTest()["field"]
        field.name = "field"
        with pytest.raises(TypeError) as exc:
            field.set_value([])
        assert str(exc.value) == "Cannot parse value for field field of type list to a text string"

    def test_set_with_different_encoding(self):
        structure = self.StructureTest()
        field = structure["field"]
        field.encoding = "utf-16-le"
        field.set_value(self.STRING_VALUE)
        actual_length = 36
        if field.null_terminated:
            actual_length += len("\x00".encode(field.encoding))

        assert len(field) == actual_length
        actual = field.get_value()
        assert actual == self.STRING_VALUE
        actual_pack = field.pack()
        expected_bytes = self.STRING_VALUE.encode("utf-16-le")
        if field.null_terminated:
            expected_bytes += "\x00".encode(field.encoding)
        assert actual_pack == expected_bytes

        field.set_value("")
        field.unpack(actual_pack)
        assert field.get_value() == self.STRING_VALUE


class TestTextFieldNullTerminated(TestTextField):
    class StructureTest(Structure):
        def __init__(self):
            self.fields = OrderedDict(
                [
                    (
                        "field",
                        TextField(
                            encoding="utf-8", default=TestTextFieldNullTerminated.STRING_VALUE, null_terminated=True
                        ),
                    )
                ]
            )
            super().__init__()
