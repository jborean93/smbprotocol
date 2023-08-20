# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from collections import OrderedDict

from smbprotocol.header import NtStatus
from smbprotocol.structure import (
    BoolField,
    BytesField,
    DateTimeField,
    EnumField,
    FlagField,
    IntField,
    Structure,
    UuidField,
)


class CreateContextName:
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.13.2 SMB2_CREATE_CONTEXT Request Values
    Valid names for the name to set on a SMB2_CREATE_CONTEXT Request entry
    """

    SMB2_CREATE_EA_BUFFER = b"\x45\x78\x74\x41"

    # note: the structures for this are located in security_descriptor.py
    SMB2_CREATE_SD_BUFFER = b"\x53\x65\x63\x44"
    SMB2_CREATE_DURABLE_HANDLE_REQUEST = b"\x44\x48\x6e\x51"
    SMB2_CREATE_DURABLE_HANDLE_RECONNECT = b"\x44\x48\x6e\x43"
    SMB2_CREATE_ALLOCATION_SIZE = b"\x41\x6c\x53\x69"
    SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST = b"\x4d\x78\x41\x63"
    SMB2_CREATE_TIMEWARP_TOKEN = b"\x54\x57\x72\x70"
    SMB2_CREATE_QUERY_ON_DISK_ID = b"\x51\x46\x69\x64"
    SMB2_CREATE_REQUEST_LEASE = b"\x52\x71\x4c\x73"
    SMB2_CREATE_REQUEST_LEASE_V2 = b"\x52\x71\x4c\x73"
    SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2 = b"\x44\x48\x32\x51"
    SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2 = b"\x44\x48\x32\x43"
    SMB2_CREATE_APP_INSTANCE_ID = b"\x45\xBC\xA6\x6A\xEF\xA7\xF7\x4A" b"\x90\x08\xFA\x46\x2E\x14\x4D\x74"
    SMB2_CREATE_APP_INSTANCE_VERSION = b"\xB9\x82\xD0\xB7\x3B\x56\x07\x4F" b"\xA0\x7B\x52\x4A\x81\x16\xA0\x10"
    SVHDX_OPEN_DEVICE_CONTEXT = b"\x9C\xCB\xCF\x9E\x04\xC1\xE6\x43" b"\x98\x0E\x15\x8D\xA1\xF6\xEC\x83"

    @staticmethod
    def get_response_structure(name, size=None):
        """
        Returns the response structure for a know list of create context
        responses.

        :param name: The constant value above
        :param size: Specify the size of the context buffer, used to differenciate between REQUEST_LEASE and
            REQUEST_LEASE_V2.
        :return: The response structure or None if unknown
        """
        # Special handling for request lease here the header name has the same value, use the size to differenciate.
        if name == CreateContextName.SMB2_CREATE_REQUEST_LEASE:
            return {
                32: SMB2CreateResponseLease(),
                52: SMB2CreateResponseLeaseV2(),
            }.get(size, None)

        return {
            CreateContextName.SMB2_CREATE_DURABLE_HANDLE_REQUEST: SMB2CreateDurableHandleResponse(),
            CreateContextName.SMB2_CREATE_DURABLE_HANDLE_RECONNECT: SMB2CreateDurableHandleReconnect(),
            CreateContextName.SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST: SMB2CreateQueryMaximalAccessResponse(),
            CreateContextName.SMB2_CREATE_QUERY_ON_DISK_ID: SMB2CreateQueryOnDiskIDResponse(),
            CreateContextName.SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2: SMB2CreateDurableHandleResponseV2(),
            CreateContextName.SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2: SMB2CreateDurableHandleReconnectV2,
            CreateContextName.SMB2_CREATE_APP_INSTANCE_ID: SMB2CreateAppInstanceId(),
            CreateContextName.SMB2_CREATE_APP_INSTANCE_VERSION: SMB2CreateAppInstanceVersion(),
        }.get(name, None)


class EAFlags:
    """
    [MS-FSCC]

    2.4.15 FileFullEaInformation Flags
    Specifies the flag used when setting extended attributes.
    """

    NONE = 0x0000000
    FILE_NEED_EA = 0x00000080


class LeaseState:
    """
    [MS-SMB2]

    2.2.13.2.8 SMB2_CREATE_REQUEST_LEASE LeaseState
    The requested lease state, field is constructed with a combination of the
    following values.
    """

    SMB2_LEASE_NONE = 0x00
    SMB2_LEASE_READ_CACHING = 0x01
    SMB2_LEASE_HANDLE_CACHING = 0x02
    SMB2_LEASE_WRITE_CACHING = 0x04


class LeaseRequestFlags:
    """
    [MS-SMB2]

    2.2.13.2.10 SMB2_CREATE_REQUEST_LEASE_V2
    The flags to use on an SMB2CreateRequestLeaseV2 packet.
    """

    SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET = 0x00000004


class LeaseResponseFlags:
    """
    [MS-SMB2]

    2.2.14.2.10 SMB2_CREATE_RESPONSE_LEASE
    """

    SMB2_LEASE_FLAG_BREAK_IN_PROGRESS = 0x00000002
    SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET = 0x00000004  # V2 Response


class DurableHandleFlags:
    """
    [MS-SMB2]

    2.2.13.2.11 SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2
    Flags used on an SMB2CreateDurableHandleRequestV2 packet.
    """

    SMB2_DHANDLE_FLAG_PERSISTENT = 0x00000002


class SVHDXOriginatorFlags:
    """
    [MS-RSVD] 2.2.4.12 SVHDX_OPEN_DEVICE_CONTEXT OriginatorFlags
    Used to indicate which component has originated or issued the operations.
    """

    SVHDX_ORIGINATOR_PVHDPARSER = 0x00000001
    SVHDX_ORIGINATOR_VHDMP = 0x00000004


class SMB2CreateContextRequest(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.13.2 SMB2_CREATE_CONTEXT Request Values
    Structure used in the SMB2 CREATE Request and SMB2 CREATE Response to
    encode additional flags and attributes
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("next", IntField(size=4)),
                ("name_offset", IntField(size=2, default=16)),
                ("name_length", IntField(size=2, default=lambda s: len(s["buffer_name"]))),
                ("reserved", IntField(size=2)),
                ("data_offset", IntField(size=2, default=lambda s: self._buffer_data_offset(s))),
                ("data_length", IntField(size=4, default=lambda s: len(s["buffer_data"]))),
                ("buffer_name", BytesField(size=lambda s: s["name_length"].get_value())),
                (
                    "padding",
                    BytesField(size=lambda s: self._padding_size(s), default=lambda s: b"\x00" * self._padding_size(s)),
                ),
                ("buffer_data", BytesField(size=lambda s: s["data_length"].get_value())),
                # not actually a field but each list entry must start at the 8 byte
                # alignment
                (
                    "padding2",
                    BytesField(
                        size=lambda s: self._padding2_size(s), default=lambda s: b"\x00" * self._padding2_size(s)
                    ),
                ),
            ]
        )
        super().__init__()

    def _buffer_data_offset(self, structure):
        if structure["data_length"].get_value() == 0:
            return 0
        else:
            return structure["name_offset"].get_value() + len(structure["buffer_name"]) + len(structure["padding"])

    def _padding_size(self, structure):
        if structure["data_length"].get_value() == 0:
            return 0

        buffer_name_len = structure["name_length"].get_value()
        mod = buffer_name_len % 8
        return mod if mod == 0 else 8 - mod

    def _padding2_size(self, structure):
        data_length = len(structure["buffer_name"]) + len(structure["padding"]) + len(structure["buffer_data"])
        mod = data_length % 8
        return mod if mod == 0 else 8 - mod

    def get_context_data(self):
        """
        Get the buffer_data value of a context response and try to convert it
        to the relevant structure based on the buffer_name used. If it is an
        unknown structure then the raw bytes are returned.

        :return: relevant Structure of buffer_data or bytes if unknown name
        """
        buffer_name = self["buffer_name"].get_value()
        structure = CreateContextName.get_response_structure(buffer_name, size=self["data_length"].get_value())
        if structure:
            structure.unpack(self["buffer_data"].get_value())
            return structure
        else:
            # unknown structure, just return the raw bytes
            return self["buffer_data"].get_value()

    @staticmethod
    def pack_multiple(messages):
        """
        Converts a list of SMB2CreateContextRequest structures and packs them
        as a bytes object used when setting to the SMB2CreateRequest
        buffer_contexts field. This should be used as it would calculate the
        correct next field value for each context entry.

        :param messages: List of SMB2CreateContextRequest structures
        :return: bytes object that is set on the SMB2CreateRequest
            buffer_contexts field.
        """
        data = b""
        msg_count = len(messages)
        for i, msg in enumerate(messages):
            if not isinstance(msg, SMB2CreateContextRequest):
                buffer = msg
                buffer_name = getattr(msg, "NAME", None)
                if buffer_name is None:
                    raise ValueError(
                        "Invalid context message, must be either a SMB2CreateContextRequest or a "
                        "predefined structure object with NAME defined."
                    )
                msg = SMB2CreateContextRequest()
                msg["buffer_name"] = buffer_name
                msg["buffer_data"] = buffer

            if i == msg_count - 1:
                msg["next"] = 0
            else:
                # because the end padding2 val won't be populated if the entry
                # offset is 0, we set to 1 so the len calc is correct
                msg["next"] = 1
                msg["next"] = len(msg)

            data += msg.pack()
        return data


class SMB2CreateEABuffer(Structure):
    """
    [MS-SMB2] 2.2.13.2.1 SMB2_CREATE_EA_BUFFER
    [MS-FSCC] 2.4.15 FileFullEaInformation

    Used to apply extended attributes as part of creating a new file.
    """

    NAME = CreateContextName.SMB2_CREATE_EA_BUFFER

    def __init__(self):
        self.fields = OrderedDict(
            [
                # 0 if no more entries, otherwise offset after ea_value
                ("next_entry_offset", IntField(size=4)),
                ("flags", FlagField(size=1, flag_type=EAFlags)),
                ("ea_name_length", IntField(size=1, default=lambda s: len(s["ea_name"]) - 1)),  # minus \x00
                ("ea_value_length", IntField(size=2, default=lambda s: len(s["ea_value"]))),
                # ea_name is ASCII byte encoded and needs a null terminator '\x00'
                ("ea_name", BytesField(size=lambda s: s["ea_name_length"].get_value() + 1)),
                ("ea_value", BytesField(size=lambda s: s["ea_value_length"].get_value())),
                # not actually a field but each list entry must start at the 4 byte
                # alignment
                (
                    "padding",
                    BytesField(size=lambda s: self._padding_size(s), default=lambda s: b"\x00" * self._padding_size(s)),
                ),
            ]
        )
        super().__init__()

    def _padding_size(self, structure):
        if structure["next_entry_offset"].get_value() == 0:
            return 0

        data_length = len(structure["ea_name"]) + len(structure["ea_value"])
        mod = data_length % 4
        return mod if mod == 0 else 4 - mod

    @staticmethod
    def pack_multiple(messages):
        """
        Converts a list of SMB2CreateEABuffer structures and packs them as a
        bytes object used when setting to the SMB2CreateContextRequest
        buffer_data field. This should be used as it would calculate the
        correct next_entry_offset field value for each buffer entry.

        :param messages: List of SMB2CreateEABuffer structures
        :return: bytes object that is set on the SMB2CreateContextRequest
            buffer_data field.
        """
        data = b""
        msg_count = len(messages)
        for i, msg in enumerate(messages):
            if i == msg_count - 1:
                msg["next_entry_offset"] = 0
            else:
                # because the end padding val won't be populated if the entry
                # offset is 0, we set to 1 so the len calc is correct
                msg["next_entry_offset"] = 1
                msg["next_entry_offset"] = len(msg)
            data += msg.pack()

        return data


class SMB2CreateDurableHandleRequest(Structure):
    """
    [MS-SMB2] 2.2.13.2.3 SMB2_CREATE_DURABLE_HANDLE_REQUEST

    Used by the client to mark the open as a durable open.
    """

    NAME = CreateContextName.SMB2_CREATE_DURABLE_HANDLE_REQUEST

    def __init__(self):
        self.fields = OrderedDict([("durable_request", BytesField(size=16, default=b"\x00" * 16))])
        super().__init__()


class SMB2CreateDurableHandleResponse(Structure):
    """
    [MS-SMB2] 2.2.14.2.3 SMB2_CREATE_DURABLE_HANDLE_RESPONSE

    Sent by the server in response to an SMB2CreateDurableHandleRequest packet.
    """

    def __init__(self):
        self.fields = OrderedDict([("reserved", IntField(size=8))])
        super().__init__()


class SMB2CreateDurableHandleReconnect(Structure):
    """
    [MS-SMB2] 2.2.13.2.4 SMB2_CREATE_DURABLE_HANDLE_RECONNECT

    Used by the client when attempting to reestablish a durable open
    """

    NAME = CreateContextName.SMB2_CREATE_DURABLE_HANDLE_RECONNECT

    def __init__(self):
        self.fields = OrderedDict([("data", BytesField(size=16))])
        super().__init__()


class SMB2CreateQueryMaximalAccessRequest(Structure):
    """
    [MS-SMB2] 2.2.13.2.5 SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST

    Used by the client to retrieve maximal access information as part of
    processing the open.
    """

    NAME = CreateContextName.SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST

    def __init__(self):
        self.fields = OrderedDict([("timestamp", DateTimeField())])
        super().__init__()


class SMB2CreateQueryMaximalAccessResponse(Structure):
    """
    [MS-SMB2] 2.2.14.2.5 SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE

    Used by the server in response to an SMB2CreateQueryMaximalAccessRequest
    packet.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("query_status", EnumField(size=4, enum_type=NtStatus, enum_strict=False)),
                # either FilePipePrinterAccessMask or DirectoryAccessMask
                ("maximal_access", IntField(size=4)),
            ]
        )
        super().__init__()


class SMB2CreateAllocationSize(Structure):
    """
    [MS-SMB2] 2.2.13.2.6 SMB2_CREATE_ALLOCATION_SIZE

    Used by the client to set the allocation size of a file that is being
    newly created or overwritten.
    """

    NAME = CreateContextName.SMB2_CREATE_ALLOCATION_SIZE

    def __init__(self):
        self.fields = OrderedDict([("allocation_size", IntField(size=8))])
        super().__init__()


class SMB2CreateTimewarpToken(Structure):
    """
    [MS-SMB2] 2.2.13.2.7 SMB2_CREATE_TIMEWARP_TOKEN

    Used by the client when requesting the server to open a version of the file
    at a previous point in time.
    """

    NAME = CreateContextName.SMB2_CREATE_TIMEWARP_TOKEN

    def __init__(self):
        self.fields = OrderedDict([("timestamp", DateTimeField())])
        super().__init__()


class SMB2CreateRequestLease(Structure):
    """
    [MS-SMB2] 2.2.13.2.8 SMB2_CREATE_REQUEST_LEASE

    Used by the cliet when requesting the server to return a lease.
    """

    NAME = CreateContextName.SMB2_CREATE_REQUEST_LEASE

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("lease_key", BytesField(size=16)),
                ("lease_state", FlagField(size=4, flag_type=LeaseState)),
                ("lease_flags", IntField(size=4)),
                ("lease_duration", IntField(size=8)),
            ]
        )
        super().__init__()


class SMB2CreateResponseLease(Structure):
    """
    [MS-SMB2] 2.2.14.2.10 SMB2_CREATE_RESPONSE_LEASE

    Sent by the server in response to an SMB2CreateRequestLease
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("lease_key", BytesField(size=16)),
                ("lease_state", FlagField(size=4, flag_type=LeaseState)),
                ("lease_flags", FlagField(size=4, flag_type=LeaseResponseFlags)),
                ("lease_duration", IntField(size=8)),
            ]
        )
        super().__init__()


class SMB2CreateQueryOnDiskIDResponse(Structure):
    """
    [MS-SMB2] 2.2.14.2.9 SMB2_CREATE_QUERY_ON_DISK_ID

    Sent by the server in response to an SMB2CreateQueryOnDiskIDRequest packet.
    """

    NAME = CreateContextName.SMB2_CREATE_QUERY_ON_DISK_ID

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("disk_file_id", IntField(size=8)),
                ("volume_id", IntField(size=8)),
                ("reserved", BytesField(size=16, default=b"\x00" * 16)),
            ]
        )
        super().__init__()


class SMB2CreateRequestLeaseV2(Structure):
    """
    [MS-SMB2] 2.2.13.2.10 SMB2_CREATE_REQUEST_LEASE_V2

    Used when the client is requesting the server to return a lease on a file
    or directory.
    Valid for the SMB 3.x family only
    """

    NAME = CreateContextName.SMB2_CREATE_REQUEST_LEASE_V2

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("lease_key", BytesField(size=16)),
                ("lease_state", FlagField(size=4, flag_type=LeaseState)),
                ("lease_flags", FlagField(size=4, flag_type=LeaseRequestFlags)),
                ("lease_duration", IntField(size=8)),
                ("parent_lease_key", BytesField(size=16)),
                ("epoch", BytesField(size=2)),
                ("reserved", IntField(size=2)),
            ]
        )
        super().__init__()


class SMB2CreateResponseLeaseV2(Structure):
    """
    [MS-SMB2] 2.2.14.2.11 SMB2_CREATE_RESPONSE_LEASE_V2

    Sent by the server in response to an SMB2CreateRequestLeaseV2 packet.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("lease_key", BytesField(size=16)),
                ("lease_state", FlagField(size=4, flag_type=LeaseState)),
                ("flags", FlagField(size=4, flag_type=LeaseResponseFlags)),
                ("lease_duration", IntField(size=8)),
                ("parent_lease_key", BytesField(size=16)),
                ("epoch", IntField(size=2)),
                ("reserved", IntField(size=2)),
            ]
        )
        super().__init__()


class SMB2CreateDurableHandleRequestV2(Structure):
    """
    [MS-SMB2] 2.2.13.2.11 SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2

    Used by the client to request the server mark the open as durable or
    persistent.
    Valid for the SMB 3.x family only
    """

    NAME = CreateContextName.SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2

    def __init__(self):
        self.fields = OrderedDict(
            [
                # timeout in milliseconds
                ("timeout", IntField(size=4)),
                ("flags", FlagField(size=4, flag_type=DurableHandleFlags)),
                ("reserved", IntField(size=8)),
                ("create_guid", UuidField(size=16)),
            ]
        )
        super().__init__()


class SMB2CreateDurableHandleReconnectV2(Structure):
    """
    [MS-SMB2] 2.2.13.2.12 SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2

    Used by the client when reestablishing a durable open.
    Valid for the SMB 3.x family only
    """

    NAME = CreateContextName.SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("file_id", BytesField(size=16)),
                ("create_guid", UuidField(size=16)),
                ("flags", FlagField(size=4, flag_type=DurableHandleFlags)),
            ]
        )
        super().__init__()


class SMB2CreateDurableHandleResponseV2(Structure):
    """
    [MS-SMB2] 2.2.14.2.12 SMB2_CREATE_DURABLE_HANDLE_RESPONSE_V2

    Sent by the server in response to an SMB2CreateDurableHandleRequestV2
    packet.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [("timeout", IntField(size=4)), ("flags", FlagField(size=4, flag_type=DurableHandleFlags))]
        )
        super().__init__()


class SMB2CreateAppInstanceId(Structure):
    """
    [MS-SMB2] 2.2.13.2.13 SMB2_CREATE_APP_INSTANCE_ID

    Used by the client when supplying an identifier provided by an application.
    Valid for the SMB 3.x family and should also have an durable handle on the
    create request.
    """

    NAME = CreateContextName.SMB2_CREATE_APP_INSTANCE_ID

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("structure_size", IntField(size=2, default=20)),
                ("reserved", IntField(size=2)),
                ("app_instance_id", BytesField(size=16)),
            ]
        )
        super().__init__()


class SMB2SVHDXOpenDeviceContextRequest(Structure):
    """
    [MS-SMB2] 2.2.13.2.14 SVHDX_OPEN_DEVICE_CONTEXT
    [MS-RSVD] 2.2.4.12 SVHDX_OPEN_DEVICE_CONTEXT

    Used to open the shared virtual disk file.
    """

    NAME = CreateContextName.SVHDX_OPEN_DEVICE_CONTEXT

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("version", IntField(size=4, default=1)),
                ("has_initiator_id", BoolField(size=1, default=lambda s: len(s["initiator_host_name"]) > 0)),
                ("reserved", BytesField(size=3, default=b"\x00\x00\x00")),
                ("initiator_id", UuidField(size=16)),
                ("originator_flags", EnumField(size=4, enum_type=SVHDXOriginatorFlags)),
                ("open_request_id", IntField(size=8)),
                ("initiator_host_name_length", IntField(size=2, default=lambda s: len(s["initiator_host_name"]))),
                # utf-16-le encoded string
                ("initiator_host_name", BytesField(size=lambda s: s["initiator_host_name_length"].get_value())),
            ]
        )
        super().__init__()


class SMB2SVHDXOpenDeviceContextResponse(Structure):
    """
    [MS-SMB2] 2.2.14.2.14 SVHDX_OPEN_DEVICE_CONTEXT_RESPONSE
    [MS-RSVD] 2.2.4.31  SVHDX_OPEN_DEVICE_CONTEXT_RESPONSE

    The response packet sent by the server in response to an
    SMB2VHDXOpenDeviceContextRequest
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("version", IntField(size=4, default=1)),
                ("has_initiator_id", BoolField(size=1, default=lambda s: len(s["initiator_host_name"]) > 0)),
                ("reserved", BytesField(size=3, default=b"\x00\x00\x00")),
                ("initiator_id", UuidField(size=16)),
                ("flags", IntField(size=4)),
                ("originator_flags", EnumField(size=4, enum_type=SVHDXOriginatorFlags)),
                ("open_request_id", IntField(size=8)),
                ("initiator_host_name_length", IntField(size=2, default=lambda s: len(s["initiator_host_name"]))),
                # utf-16-le encoded string
                ("initiator_host_name", BytesField(size=lambda s: s["initiator_host_name_length"].get_value())),
            ]
        )
        super().__init__()


class SMB2SVHDXOpenDeviceContextV2Request(Structure):
    """
    [MS-SMB2] 2.2.13.2.14 SVHDX_OPEN_DEVICE_CONTEXT
    [MS-RSVD] 2.2.4.32 SVHDX_OPEN_DEVICE_CONTEXT_V2

    Used to open the shared virtual disk file on the RSVD Protocol version 2
    """

    NAME = CreateContextName.SVHDX_OPEN_DEVICE_CONTEXT

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("version", IntField(size=4, default=2)),
                ("has_initiator_id", BoolField(size=1, default=lambda s: len(s["initiator_host_name"]) > 0)),
                ("reserved", BytesField(size=3, default=b"\x00\x00\x00")),
                ("initiator_id", UuidField(size=16)),
                ("originator_flags", EnumField(size=4, enum_type=SVHDXOriginatorFlags)),
                ("open_request_id", IntField(size=8)),
                ("initiator_host_name_length", IntField(size=2, default=lambda s: len(s["initiator_host_name"]))),
                # utf-16-le encoded string
                ("initiator_host_name", BytesField(size=lambda s: s["initiator_host_name_length"].get_value())),
                ("virtual_disk_properties_initialized", IntField(size=4)),
                ("server_service_version", IntField(size=4)),
                ("virtual_sector_size", IntField(size=4)),
                ("physical_sector_size", IntField(size=4)),
                ("virtual_size", IntField(size=8)),
            ]
        )
        super().__init__()


class SMB2SVHDXOpenDeviceContextV2Response(Structure):
    """
    [MS-SMB2] 2.2.14.2.14 SVHDX_OPEN_DEVICE_CONTEXT_RESPONSE
    [MS-RSVD] 2.2.4.32 SVHDX_OPEN_DEVICE_CONTEXT_V2_RESPONSE

    The response packet sent by the server in response to an
    SMB2VHDXOpenDeviceContextV2Request
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("version", IntField(size=4, default=2)),
                ("has_initiator_id", BoolField(size=1, default=lambda s: len(s["initiator_host_name"]) > 0)),
                ("reserved", BytesField(size=3, default=b"\x00\x00\x00")),
                ("initiator_id", UuidField(size=16)),
                ("flags", IntField(size=4)),
                ("originator_flags", EnumField(size=4, enum_type=SVHDXOriginatorFlags)),
                ("open_request_id", IntField(size=8)),
                ("initiator_host_name_length", IntField(size=2, default=lambda s: len(s["initiator_host_name"]))),
                # utf-16-le encoded string
                ("initiator_host_name", BytesField(size=lambda s: s["initiator_host_name_length"].get_value())),
                ("virtual_disk_properties_initialized", IntField(size=4)),
                ("server_service_version", IntField(size=4)),
                ("virtual_sector_size", IntField(size=4)),
                ("physical_sector_size", IntField(size=4)),
                ("virtual_size", IntField(size=8)),
            ]
        )
        super().__init__()


class SMB2CreateAppInstanceVersion(Structure):
    """
    [MS-SMB2] 2.2.13.2.15 SMB2_CREATE_APP_INSTANCE_VERSION

    Used when the client is supplying a version for the app instance identifier
    provided by an application.
    Valid for the SMB 3.1.1+ family
    """

    NAME = CreateContextName.SMB2_CREATE_APP_INSTANCE_VERSION

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("structure_size", IntField(size=2, default=24)),
                ("reserved", IntField(size=2)),
                ("padding", IntField(size=4)),
                ("app_instance_version_high", IntField(size=8)),
                ("app_instance_version_low", IntField(size=8)),
            ]
        )
        super().__init__()
