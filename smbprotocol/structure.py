# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import copy
import struct
import textwrap
import types
import uuid

from abc import (
    ABCMeta,
    abstractmethod,
)

from binascii import (
    hexlify,
)

from datetime import (
    datetime,
    timedelta,
)

from six import (
    binary_type,
    integer_types,
    python_2_unicode_compatible,
    text_type,
    with_metaclass,
)

from smbprotocol._text import (
    to_bytes,
    to_native,
    to_text,
)

TAB = "    "  # Instead of displaying a tab on the print, use 4 spaces


class InvalidFieldDefinition(Exception):
    pass


def _bytes_to_hex(bytes, pretty=False, hex_per_line=8):
    hex = to_text(hexlify(bytes))

    if pretty:
        if hex_per_line == 0:  # show hex on 1 line
            hex_list = [hex]
        else:
            idx = hex_per_line * 2
            hex_list = list(hex[i:i + idx] for i in range(0, len(hex), idx))

        hexes = []
        for h in hex_list:
            hexes.append(
                ' '.join(h[i:i + 2] for i in range(0, len(h), 2)).upper())
        hex = "\n".join(hexes)

    return hex


def _indent_lines(string, prefix):
    # Would use textwrap.indent for this but it is not available for Python 2
    def predicate(line):
        return line.strip()

    lines = []
    for line in string.splitlines(True):
        lines.append(prefix + line if predicate(line) else line)
    return ''.join(lines)


class Structure(object):

    def __init__(self):
        # Now that self.fields is set, loop through it again and set the
        # metadata around the fields and set the value based on default.
        # This must be done outside of the OrderedDict definition as set_value
        # relies on the full structure (self) being available and error
        # messages use the field name to be helpful
        for name, field in self.fields.items():
            field.structure = self
            field.name = name
            field.set_value(field.default)

    def __str__(self):
        struct_name = self.__class__.__name__
        raw_hex = _bytes_to_hex(self.pack(), True, hex_per_line=0)
        field_strings = []

        for name, field in self.fields.items():
            # the field header is slightly different for a StructureField
            # remove the leading space and put the value on the next line
            if isinstance(field, StructureField):
                field_header = "%s =\n%s"
            else:
                field_header = "%s = %s"

            field_string = field_header % (field.name, str(field))
            field_strings.append(_indent_lines(field_string, TAB))

        field_strings.append("")
        field_strings.append(_indent_lines("Raw Hex:", TAB))
        hex_wrapper = textwrap.TextWrapper(
            width=33,  # set to show 8 hex values per line, 33 for 8, 56 for 16
            initial_indent=TAB + TAB,
            subsequent_indent=TAB + TAB
        )
        field_strings.append(hex_wrapper.fill(raw_hex))

        string = "%s:\n%s" % (to_native(struct_name), '\n'.join([to_native(s) for s in field_strings]))

        return string

    def __setitem__(self, key, value):
        field = self._get_field(key)
        field.set_value(value)

    def __getitem__(self, key):
        return self._get_field(key)

    def __delitem__(self, key):
        self._get_field(key)
        del self.fields[key]

    def __len__(self):
        length = 0
        for field in self.fields.values():
            length += len(field)
        return length

    def pack(self):
        data = b""
        for field in self.fields.values():
            field_data = field.pack()
            data += field_data

        return data

    def unpack(self, data):
        for key, field in self.fields.items():
            data = field.unpack(data)
        return data  # remaining data

    def _get_field(self, key):
        field = self.fields.get(key, None)
        if field is None:
            raise ValueError("Structure does not contain field %s" % key)
        return field


@python_2_unicode_compatible
class Field(with_metaclass(ABCMeta, object)):

    def __init__(self, little_endian=True, default=None, size=None):
        """
        The base class of a Field object. This contains the framework that a
        field SHOULD implement in regards to packing and unpacking a value.
        There should be little need to call this particular object as it is
        designed to be a base class for *Type classes.

        :param little_endian: When converting an int/uuid to bytes, the byte
            order to pack as, False means it will be big endian
        :param default: The default value of the field, this can be any
            supported value such as as well as a lambda function or None
            (default).
        :param size: The size of the field, this can be an int, lambda function
            or None (for variable length end field) unless overridden in Class
            definition.
        """
        field_type = self.__class__.__name__
        self.little_endian = little_endian

        if not (size is None or isinstance(size, integer_types) or
                isinstance(size, types.LambdaType)):
            raise InvalidFieldDefinition("%s size for field must be an int or "
                                         "None for a variable length"
                                         % field_type)
        self.size = size
        self.default = default
        self.value = None

    def __str__(self):
        return self._to_string()

    def __len__(self):
        return self._get_packed_size()

    def pack(self):
        """
        Packs the field value into a byte string so it can be sent to the
        server.

        :param structure: The message structure class object
        :return: A byte string of the packed field's value
        """
        value = self._get_calculated_value(self.value)
        packed_value = self._pack_value(value)
        size = self._get_calculated_size(self.size, packed_value)
        if len(packed_value) != size:
            raise ValueError("Invalid packed data length for field %s of %d "
                             "does not fit field size of %d"
                             % (self.name, len(packed_value), size))

        return packed_value

    def get_value(self):
        """
        Returns the value set for the field, will run any lambda functions
        that is set under the value attribute and return the final value.

        :return: The value attribute with lambda functions run if value is a
            lambda function
        """
        return self._get_calculated_value(self.value)

    def set_value(self, value):
        """
        Parses, and sets the value attribute for the field.

        :param value: The value to be parsed and set, the allowed input types
            vary depending on the Field used
        """
        parsed_value = self._parse_value(value)
        self.value = parsed_value

    def unpack(self, data):
        """
        Takes in a byte string and set's the field value based on field
        definition.

        :param structure: The message structure class object
        :param data: The byte string of the data to unpack
        :return: The remaining data for subsequent fields
        """
        size = self._get_calculated_size(self.size, data)
        self.set_value(data[0:size])
        return data[len(self):]

    @abstractmethod
    def _pack_value(self, value):
        """
        Packs the value passed in according to the rules of the FieldType.

        :param value: The value to be packed, this is derived by
            _get_calculated_value(self.value)
        :return: A byte string of the data once packed
        """
        pass  # pragma: no cover

    @abstractmethod
    def _parse_value(self, value):
        """
        Parses the value into the FieldType type, this also validates that
        the value is allowable by the FieldType.

        :param value: The value to parse
        :return: The value that has been parsed/casted to the correct value
        """
        pass  # pragma: no cover

    @abstractmethod
    def _get_packed_size(self):
        """
        Get's the size of the data once it has been packed. Depending on the
        FieldType, this can either be pre-set or calculated when called.

        :return: The size of the field once it is packed
        """
        pass  # pragma: no cover

    @abstractmethod
    def _to_string(self):
        """
        Creates a string which is a human readable representation of the value.
        The output is dependent on the field implementation.

        :return: string of the field value
        """
        # creates a string which is a friendly representation of the value
        pass  # pragma: no cover

    def _get_calculated_value(self, value):
        """
        Get's the final value of the field and runs the lambda functions
        recursively until a final value is derived.

        :param value: The value to calculate/expand
        :return: The final value
        """
        if isinstance(value, types.LambdaType):
            expanded_value = value(self.structure)
            return self._get_calculated_value(expanded_value)
        else:
            # perform one final parsing of the value in case lambda value
            # returned a different type
            return self._parse_value(value)

    def _get_calculated_size(self, size, data):
        """
        Get's the final size of the field and runs the lambda functions
        recursively until a final size is derived. If size is None then it
        will just return the length of the data as it is assumed it is the
        final field (None should only be set on size for the final field).

        :param size: The size to calculate/expand
        :param data: The data that the size is being calculated for
        :return: The final size
        """
        # if the size is derived from a lambda function, run it now; otherwise
        # return the value we passed in or the length of the data if the size
        # is None (last field value)
        if size is None:
            return len(data)
        elif isinstance(size, types.LambdaType):
            expanded_size = size(self.structure)
            return self._get_calculated_size(expanded_size, data)
        else:
            return size

    def _get_struct_format(self, size, unsigned=True):
        """
        Get's the format specified for use in struct. This is only designed
        for 1, 2, 4, or 8 byte values and will throw an exception if it is
        anything else.

        :param size: The size as an int
        :return: The struct format specifier for the size specified
        """
        if isinstance(size, types.LambdaType):
            size = size(self.structure)

        struct_format = {
            1: 'B',
            2: 'H',
            4: 'L',
            8: 'Q'
        }
        if size not in struct_format.keys():
            raise InvalidFieldDefinition("Cannot struct format of size %s"
                                         % size)
        format_char = struct_format[size]
        if not unsigned:
            format_char = format_char.lower()

        return format_char


class IntField(Field):

    def __init__(self, size, unsigned=True, **kwargs):
        """
        Used to store an int value for a field. The size for these values MUST
        be 1, 2, 4, or 8 and if another size is required use the BytesField
        instead and store the values as bytes.

        :param size: The size of the integer when packed
        :param kwargs: Any other kwarg to be sent to Field()
        """
        if size not in [1, 2, 4, 8]:
            raise InvalidFieldDefinition("IntField size must have a value of "
                                         "1, 2, 4, or 8 not %s" % str(size))
        self.unsigned = unsigned
        super(IntField, self).__init__(size=size, **kwargs)

    def _pack_value(self, value):
        format = self._get_struct_format(self.size, self.unsigned)
        struct_string = "%s%s" % ("<" if self.little_endian else ">", format)
        packed_int = struct.pack(struct_string, value)
        return packed_int

    def _parse_value(self, value):
        if value is None:
            int_value = 0
        elif isinstance(value, types.LambdaType):
            int_value = value
        elif isinstance(value, bytes):
            format = self._get_struct_format(self.size, self.unsigned)
            struct_string = "%s%s"\
                            % ("<" if self.little_endian else ">", format)
            int_value = struct.unpack(struct_string, value)[0]
        elif isinstance(value, integer_types):
            int_value = value
        else:
            raise TypeError("Cannot parse value for field %s of type %s to "
                            "an int" % (self.name, type(value).__name__))
        return int_value

    def _get_packed_size(self):
        return self.size

    def _to_string(self):
        return str(self._get_calculated_value(self.value))


class BytesField(Field):
    """
    Used to store a raw bytes value as a field. Is the most universal and can
    convert from most objects to a bytes string. Use this is the field can
    contain multiple values and parsing will be done outside of the class.
    """

    def _pack_value(self, value):
        return value

    def _parse_value(self, value):
        if value is None:
            bytes_value = b""
        elif isinstance(value, types.LambdaType):
            bytes_value = value
        elif isinstance(value, integer_types):
            format = self._get_struct_format(self.size)
            struct_string = "%s%s"\
                            % ("<" if self.little_endian else ">", format)
            bytes_value = struct.pack(struct_string, value)
        elif isinstance(value, Structure):
            bytes_value = value.pack()
        elif isinstance(value, bytes):
            bytes_value = value
        else:
            raise TypeError("Cannot parse value for field %s of type %s to a "
                            "byte string" % (self.name, type(value).__name__))
        return bytes_value

    def _get_packed_size(self):
        bytes_value = self._get_calculated_value(self.value)
        return len(bytes_value)

    def _to_string(self):
        bytes_value = self._get_calculated_value(self.value)
        return _bytes_to_hex(bytes_value, pretty=True, hex_per_line=0)


class ListField(Field):

    def __init__(self, list_count=None, list_type=BytesField(),
                 unpack_func=None, **kwargs):
        """
        Used to store a list of values that are the same time, the list can
        contain both fixed length values or variable length values but the
        former is easier to use as it does not require lambda functions to
        unpack the values. If the list values are different types, then the
        BytesField list_type should be used and the data will automatically
        will be converted to a bytes object. If appending a value to the list,
        ensure the value it added as an actual *Field() object and not just
        the raw value.

        :param list_count: The number of entries in the list, the value can be
            an int, lambda function or None (for variable length). The lambda
            function is only evaluated in the pack and unpack methods. This
            must be set if unpack_func is not set so it can unpack the data
            receved from the server.
        :param list_type: The *Field() definition for each list entry, defaults
            to a variable length BytesField. If unpack_func is not set, the
            size attribute must be set.
        :param unpack_func: A lambda function used during the unpack method to
            unpack the data received from the server to a list. It takes in the
            (structure, data) arguments which is the structure of the whole
            packet and the remaining data left to be unpacked. This MUST be
            used when the list contains variable length values.
        :param kwargs: Any other kwarg to be sent to Field()
        """
        if list_count is not None and not \
                (isinstance(list_count, integer_types) or
                 isinstance(list_count, types.LambdaType)):
            raise InvalidFieldDefinition("ListField list_count must be an "
                                         "int, lambda, or None for a variable "
                                         "list length")
        self.list_count = list_count

        if not isinstance(list_type, Field):
            raise InvalidFieldDefinition("ListField list_type must be a "
                                         "Field definition")
        self.list_type = list_type

        if unpack_func is not None and not isinstance(unpack_func,
                                                      types.LambdaType):
            raise InvalidFieldDefinition("ListField unpack_func must be a "
                                         "lambda function or None")
        elif unpack_func is None and \
                (list_count is None or list_type.size is None):
            raise InvalidFieldDefinition("ListField must either define "
                                         "unpack_func as a lambda or set "
                                         "list_count and list_size with a "
                                         "size")
        self.unpack_func = unpack_func

        super(ListField, self).__init__(**kwargs)

    def __getitem__(self, item):
        # TODO: Make this more efficient
        return self.get_value()[item]

    def get_value(self):
        # Override default get_value() so we return a list with the actual
        # value, not the Field definition
        list_value = []
        if isinstance(self.value, types.LambdaType):
            value = self._get_calculated_value(self.value)
        else:
            value = self.value

        for entry in value:
            list_value.append(entry.get_value())
        return list_value

    def _pack_value(self, value):
        data = b""
        for value in list(value):
            data += value.pack()
        return data

    def _parse_value(self, value):
        if value is None:
            list_value = []
        elif isinstance(value, types.LambdaType):
            return value
        elif isinstance(value, bytes) and isinstance(self.unpack_func,
                                                     types.LambdaType):
            # use the lambda function to parse the bytes to a list
            list_value = self.unpack_func(self.structure, value)
        elif isinstance(value, bytes):
            # we have a fixed length array with a specified count
            list_value = self._create_list_from_bytes(self.list_count,
                                                      self.list_type, value)
        elif isinstance(value, list):
            # manually parse each list entry to the field type specified
            list_value = value
        else:
            raise TypeError("Cannot parse value for field %s of type %s to a "
                            "list" % (self.name, type(value).__name__))
        list_value = [self._parse_sub_value(v) for v in list_value]
        return list_value

    def _parse_sub_value(self, value):
        if isinstance(value, Field):
            new_field = value
        elif isinstance(value, Structure):
            new_field = StructureField(
                size=len(value),
                structure_type=type(value),
                default=value,
            )
            new_field.name = "%s list entry" % self.name
            new_field.structure = value
            new_field.set_value(new_field.default)
        else:
            new_field = copy.deepcopy(self.list_type)
            new_field.name = "%s list entry" % self.name
            new_field.set_value(value)
        return new_field

    def _get_packed_size(self):
        list_value = self._get_calculated_value(self.value)
        size = 0
        for field in list(list_value):
            size += len(field)
        return size

    def _to_string(self):
        list_value = self._get_calculated_value(self.value)
        list_string = [_indent_lines(str(v), TAB) for v in list(list_value)]
        if len(list_string) == 0:
            string = "[]"
        else:
            string = "[\n%s\n]" % ',\n'.join(list_string)
        return string

    def _create_list_from_bytes(self, list_count, list_type, value):
        # calculate the list_count and rerun method if a lambda
        if isinstance(list_count, types.LambdaType):
            list_count = list_count(self.structure)
            return self._create_list_from_bytes(list_count, list_type, value)

        list_value = []
        for idx in range(0, list_count):
            new_field = copy.deepcopy(list_type)
            value = new_field.unpack(value)
            list_value.append(new_field)
        return list_value


class StructureField(Field):

    def __init__(self, structure_type, **kwargs):
        """
        Used to store a message packet Structure object as a field. Can store
        both an actual Structure value or a byte string.

        :param structure_type: The message structure type, e.g.
            SMB2NegotiateRequest. Used to marshal a byte string to a structure
            object when unpacking or setting a value
        :param kwargs: Any other kwarg to be sent to Field()
        """
        self.structure_type = structure_type
        super(StructureField, self).__init__(**kwargs)

    def __setitem__(self, key, value):
        field = self._get_field(key)
        field.set_value(value)

    def __getitem__(self, key):
        return self._get_field(key)

    def set_structure_type(self, structure_type):
        # Set's the structure type and convert a byte string to the actual
        # structure specified
        self.structure_type = structure_type
        self.set_value(self.value)

    def _pack_value(self, value):
        # Can either be a Structure or just plain bytes, just pack the
        # structure if needed
        if isinstance(value, Structure):
            value = value.pack()
        return value

    def _parse_value(self, value):
        if value is None:
            structure_value = b""
        elif isinstance(value, types.LambdaType):
            structure_value = value
        elif isinstance(value, bytes):
            structure_value = value
        elif isinstance(value, Structure):
            structure_value = value
        else:
            raise TypeError("Cannot parse value for field %s of type %s to a "
                            "structure" % (self.name, type(value).__name__))

        if isinstance(structure_value, bytes) and self.structure_type and \
                structure_value != b"":
            if isinstance(self.structure_type, types.LambdaType):
                structure_type = self.structure_type(self.structure)
            else:
                structure_type = self.structure_type
            structure = structure_type()
            structure.unpack(structure_value)
            structure_value = structure
        return structure_value

    def _get_packed_size(self):
        structure_value = self._get_calculated_value(self.value)
        return len(structure_value)

    def _to_string(self):
        structure_value = self._get_calculated_value(self.value)
        return str(structure_value)

    def _get_field(self, key):
        structure_value = self._get_calculated_value(self.value)
        if isinstance(structure_value, bytes):
            raise ValueError("Cannot get field %s when structure is defined "
                             "as a byte string" % key)
        field = structure_value._get_field(key)
        return field


class DateTimeField(Field):

    EPOCH_FILETIME = 116444736000000000  # epoch as a MS FILETIME int
    HUNDREDS_NS = 10000000  # How many hundred nanoseconds in a second

    def __init__(self, size=None, **kwargs):
        """
        [MS-DTYP] 0.0 2017-09-15

        2.3.3 FILETIME
        The FILETIME structure is a 64-it value that represents the number of
        100 nanoseconds intervals that have elapsed since January 1, 1601 UTC.
        This is used to convert the FILETIME int value to a native Python
        datetime object.

        While the format FILETIME is used when communicating with the server,
        this type allows Python code to interact with datetime objects natively
        with all the conversions handled at pack/unpack time.

        :param size: Must be set to None or 8, this is so we can check/override
        :param kwargs: Any other kwarg to be sent to Field()
        """
        if not (size is None or size == 8):
            raise InvalidFieldDefinition("DateTimeField type must have a size "
                                         "of 8 not %d" % size)
        super(DateTimeField, self).__init__(size=8, **kwargs)

    def _pack_value(self, value):
        epoch_seconds = self._seconds_since_epoch(value)
        int_value = self.EPOCH_FILETIME + (epoch_seconds * self.HUNDREDS_NS)
        int_value += value.microsecond * 10

        format = self._get_struct_format(8)
        struct_string = "%s%s"\
                        % ("<" if self.little_endian else ">", format)
        bytes_value = struct.pack(struct_string, int_value)

        return bytes_value

    def _parse_value(self, value):
        if value is None:
            datetime_value = datetime.today()
        elif isinstance(value, types.LambdaType):
            datetime_value = value
        elif isinstance(value, bytes):
            format = self._get_struct_format(8)
            struct_string = "%s%s"\
                            % ("<" if self.little_endian else ">", format)
            int_value = struct.unpack(struct_string, value)[0]
            return self._parse_value(int_value)  # just parse the value again
        elif isinstance(value, integer_types):

            time_microseconds = (value - self.EPOCH_FILETIME) // 10
            datetime_value = datetime(1970, 1, 1) + \
                timedelta(microseconds=time_microseconds)
        elif isinstance(value, datetime):
            datetime_value = value
        else:
            raise TypeError("Cannot parse value for field %s of type %s to a "
                            "datetime" % (self.name, type(value).__name__))
        return datetime_value

    def _get_packed_size(self):
        return self.size

    def _to_string(self):
        datetime_value = self._get_calculated_value(self.value)
        return datetime_value.isoformat(' ')

    def _seconds_since_epoch(self, datetime_value):
        # total_seconds was not present in Python 2.6, this is suggested by
        # Python docs as an alternative
        # https://docs.python.org/2/library/datetime.html#datetime.timedelta.total_seconds
        td = datetime_value - datetime.utcfromtimestamp(0)
        seconds = (td.microseconds +
                   (td.seconds + td.days * 24 * 3600) * 10 ** 6) / 10 ** 6
        return int(seconds)


class UuidField(Field):

    def __init__(self, size=None, **kwargs):
        """
        Used to store a UUID (GUID) as a Python UUID object.

        :param size: Must be set to None or 16, this is so we can
            check/override
        :param kwargs: Any other kwarg to be sent to Field()
        """
        if not (size is None or size == 16):
            raise InvalidFieldDefinition("UuidField type must have a size of "
                                         "16 not %d" % size)
        super(UuidField, self).__init__(size=16, **kwargs)

    def _pack_value(self, value):
        if self.little_endian:
            return value.bytes
        else:
            return value.bytes_le

    def _parse_value(self, value):
        if value is None:
            uuid_value = uuid.UUID(bytes=b"\x00" * 16)
        elif isinstance(value, bytes) and self.little_endian:
            uuid_value = uuid.UUID(bytes=value)
        elif isinstance(value, bytes) and not self.little_endian:
            uuid_value = uuid.UUID(bytes_le=value)
        elif isinstance(value, integer_types):
            uuid_value = uuid.UUID(int=value)
        elif isinstance(value, uuid.UUID):
            uuid_value = value
        elif isinstance(value, types.LambdaType):
            uuid_value = value
        else:
            raise TypeError("Cannot parse value for field %s of type %s to a "
                            "uuid" % (self.name, type(value).__name__))
        return uuid_value

    def _get_packed_size(self):
        return self.size

    def _to_string(self):
        uuid_value = self._get_calculated_value(self.value)
        return str(uuid_value)


class EnumField(IntField):

    def __init__(self, enum_type, enum_strict=True, **kwargs):
        self.enum_type = enum_type
        self.enum_strict = enum_strict
        super(EnumField, self).__init__(**kwargs)

    def _parse_value(self, value):
        int_value = super(EnumField, self)._parse_value(value)
        valid = False
        for flag_value in vars(self.enum_type).values():
            if int_value == flag_value:
                valid = True
                break

        if not valid and int_value != 0 and self.enum_strict:
            raise ValueError("Enum value %d does not exist in enum type %s"
                             % (int_value, self.enum_type))
        return int_value

    def _to_string(self):
        enum_name = None
        value = self._get_calculated_value(self.value)
        for enum, enum_value in vars(self.enum_type).items():
            if value == enum_value:
                enum_name = enum
                break
        if enum_name is None:
            return "(%d) UNKNOWN_ENUM" % value
        else:
            return "(%d) %s" % (value, enum_name)


class FlagField(IntField):

    def __init__(self, flag_type, flag_strict=True, **kwargs):
        self.flag_type = flag_type
        self.flag_strict = flag_strict
        super(FlagField, self).__init__(**kwargs)

    def set_flag(self, flag):
        valid = False
        for value in vars(self.flag_type).values():
            if flag == value:
                valid = True
                break

        if not valid and self.flag_strict:
            raise ValueError("Flag value does not exist in flag type %s"
                             % self.flag_type)
        self.set_value(self.value | flag)

    def has_flag(self, flag):
        return self.value & flag == flag

    def _parse_value(self, value):
        int_value = super(FlagField, self)._parse_value(value)
        current_val = int_value
        for value in vars(self.flag_type).values():
            if isinstance(value, int):
                current_val &= ~value
        if current_val != 0 and self.flag_strict:
            raise ValueError("Invalid flag for field %s value set %d"
                             % (self.name, current_val))

        return int_value

    def _to_string(self):
        field_value = self._get_calculated_value(self.value)
        if field_value == 0:
            return "0"
        flags = []
        for flag, value in vars(self.flag_type).items():
            if isinstance(value, int) and self.has_flag(value):
                flags.append(flag)
        flags.sort()
        return "(%d) %s" % (field_value, ", ".join(flags))


class BoolField(Field):

    def __init__(self, size=1, **kwargs):
        """
        Used to store a boolean value in 1 byte. b"\x00" is False while b"\x01"
        is True.

        :param kwargs: Any other kwargs to be sent to Field()
        """
        if size != 1:
            raise InvalidFieldDefinition("BoolField size must have a value of "
                                         "1, not %d" % size)
        super(BoolField, self).__init__(size=size, **kwargs)

    def _pack_value(self, value):
        return b"\x01" if value else b"\x00"

    def _parse_value(self, value):
        if value is None:
            bool_value = False
        elif isinstance(value, bool):
            bool_value = value
        elif isinstance(value, bytes):
            bool_value = value == b"\x01"
        elif isinstance(value, types.LambdaType):
            bool_value = value
        else:
            raise TypeError("Cannot parse value for field %s of type %s to a "
                            "bool" % (self.name, type(value).__name__))
        return bool_value

    def _get_packed_size(self):
        return 1

    def _to_string(self):
        return str(self._get_calculated_value(self.value))


class TextField(BytesField):

    def __init__(self, encoding='utf-16-le', **kwargs):
        self.encoding = encoding
        super(TextField, self).__init__(**kwargs)

    def _pack_value(self, value):
        return to_bytes(value, encoding=self.encoding)

    def _parse_value(self, value):
        if value is None:
            text_value = u""
        elif isinstance(value, binary_type):
            text_value = to_text(value, encoding=self.encoding)
        elif isinstance(value, text_type):
            text_value = value
        elif isinstance(value, types.LambdaType):
            text_value = value
        else:
            raise TypeError("Cannot parse value for field %s of type %s to a "
                            "text string" % (self.name, type(value).__name__))

        return text_value

    def _get_packed_size(self):
        text_value = self._get_calculated_value(self.value)
        return len(to_bytes(text_value, encoding=self.encoding))

    def _to_string(self):
        return self.value
