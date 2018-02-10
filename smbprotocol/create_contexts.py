import smbprotocol.open
from smbprotocol.structure import BoolField, BytesField, DateTimeField,\
    EnumField, FlagField, IntField, Structure, StructureField, UuidField

try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict


class CreateContextName(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.13.2 SMB2_CREATE_CONTEXT Request Values
    Valid names for the name to set on a SMB2_CREATE_CONTEXT Request entry
    """
    SMB2_CREATE_EA_BUFFER = 0x45787441
    SMB2_CREATE_SD_BUFFER = 0x53656344
    SMB2_CREATE_DURABLE_HANDLE_REQUEST = 0x44486e51
    SMB2_CREATE_DURABLE_HANDLE_RECONNECT = 0x44486e43
    SMB2_CREATE_ALLOCATION_SIZE = 0x416c5369
    SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST = 0x4d784163
    SMB2_CREATE_TIMEWARP_TOKEN = 0x54577270
    SMB2_CREATE_QUERY_ON_DISK_ID = 0x51466964
    SMB2_CREATE_REQUEST_LEASE = 0x52714c73
    SMB2_CREATE_REQUEST_LEASE_V2 = 0x52714c73
    SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2 = 0x44483251
    SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2 = 0x44483243
    SMB2_CREATE_APP_INSTANCE_ID = 0x45BCA66AEFA7F74A9008FA462E144D74
    SMB2_CREATE_APP_INSTANCE_VERSION = 0xB982D0B73B56074FA07B524A8116A010
    SVHDX_OPEN_DEVICE_CONTEXT = 0x9CCBCF9E04C1E643980E158DA1F6EC83


class EAFlags(object):
    NONE = 0x0000000
    FILE_NEED_EA = 0x00000080


class SDControl(object):
    SELF_RELATIVE = 0x8000
    RM_CONTROL_VALID = 0x4000
    SACL_PROTECTED = 0x2000
    DACL_PROTECTED = 0x1000
    SACL_AUTO_INHERITED = 0x0800
    DACL_AUTO_INHERITED = 0x0400
    SACL_COMPUTED_INHERITANCE_REQUIRED = 0x0200
    DACL_COMPUTED_INHERITANCE_REQUIRED = 0x0100
    SERVER_SECURITY = 0x0080
    DACL_TRUSTED = 0x0040
    SACL_DEFAULTED = 0x0020
    SACL_PRESENT = 0x0010
    DACL_DEFAULTED = 0x0008
    DACL_PRESENT = 0x0004
    GROUP_DEFAULTED = 0x0002
    OWNER_DEFAULTED = 0x0001
    NONE = 0x0000


class LeaseState(object):
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


class LeaseFlags(object):
    """
    [MS-SMB2]

    2.2.13.2.10 SMB2_CREATE_REQUEST_LEASE_V2
    The flags to use on an SMB2CreateRequestLeaseV2 packet.
    """
    SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET = 0x00000004


class DurableHandleFlags(object):
    """
    [MS-SMB2]

    2.2.13.2.11 SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2
    Flags used on an SMB2CreateDurableHandleRequestV2 packet.
    """
    SMB2_DHANDLE_FLAG_PERSISTENT = 0x00000002


class SVHDXOriginatorFlags(object):
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
        self.fields = OrderedDict([
            ('next', IntField(size=4)),
            ('name_offset', IntField(
                size=2,
                default=16
            )),
            ('name_length', IntField(
                size=2,
                default=lambda s: len(s['buffer_name'])
            )),
            ('reserved', IntField(size=2)),
            ('data_offset', IntField(
                size=2,
                default=lambda s: self._buffer_data_offset(s)
            )),
            ('data_length', IntField(
                size=4,
                default=lambda s: len(s['buffer_data'])
            )),
            ('buffer_name', EnumField(
                size=lambda s: s['name_length'].get_value(),
                enum_type=CreateContextName
            )),
            ('padding', BytesField(
                size=lambda s: self._padding_size(s),
                default=lambda s: b"\x00" * self._padding_size(s)
            )),
            ('buffer_data', BytesField(
                size=lambda s: s['data_length'].get_value()
            ))
        ])
        super(SMB2CreateContextRequest, self).__init__()

    def _buffer_data_offset(self, structure):
        if structure['data_length'].get_value() == 0:
            return 0
        else:
            return structure['name_offset'].get_value() + \
                   len(structure['padding'])

    def _padding_size(self, structure):
        if structure['data_length'].get_value() == 0:
            return 0

        mod = structure['data_length'].get_value() % 8
        return 0 if mod == 0 else 8 - mod


class SMB2CreateEABuffer(Structure):
    """
    [MS-SMB2] 2.2.13.2.1 SMB2_CREATE_EA_BUFFER
    [MS-FSCC] 2.4.15 FileFullEaInformation

    Used to apply extended attributes as part of creating a new file.
    """

    def __init__(self):
        self.fields = OrderedDict([
            # 0 if no more entries, otherwise offset after ea_value
            ('next_entry_offset', IntField(size=4)),
            ('flags', FlagField(
                size=1,
                flag_type=EAFlags
            )),
            ('ea_name_length', IntField(
                size=1,
                default=lambda s: len(s['ea_name']) - 1  # minus \x00
            )),
            ('ea_value_length', IntField(
                size=2,
                default=lambda s: len(s['ea_value'])
            )),
            # ea_name is ASCII byte encoded
            ('ea_name', BytesField(
                size=lambda s: s['ea_name_length'].get_value() + 1
            )),
            ('ea_value', BytesField(
                size=lambda s: s['ea_value_length'].get_value()
            ))

        ])
        super(SMB2CreateEABuffer, self).__init__()


class SMB2CreateSDBuffer(Structure):
    """
    [MS-SMB2] 2.2.13.2.2 SMB2_CREATE_SD_BUFFER
    [MS-DTYP] 2.4.6 SECURITY_DESCRIPTOR

    Used to apply a security descriptor to a newly created file.
    """

    def __init__(self):
        # TODO: auto calculate offset and add ACL field type
        self.fields = OrderedDict([
            ('revision', IntField(
                size=1,
                default=1
            )),
            ('sbz1', IntField(size=1)),
            ('control', FlagField(
                size=2,
                flag_type=SDControl
            )),
            ('offset_owner', IntField(size=4)),
            ('offset_group', IntField(size=4)),
            ('offset_sacl', IntField(size=4)),
            ('offset_dacl', IntField(size=4)),
            ('owner_size', BytesField()),
            ('group_sid', BytesField()),
            ('sacl', BytesField()),
            ('dacl', BytesField())
        ])
        super(SMB2CreateSDBuffer, self).__init__()


class SMB2CreateDurableHandleRequest(Structure):
    """
    [MS-SMB2] 2.2.13.2.3 SMB2_CREATE_DURABLE_HANDLE_REQUEST

    Used by the client to mark the open as a durable open.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('durable_request', BytesField(size=16, default=b"\x00" * 16))
        ])
        super(SMB2CreateDurableHandleRequest, self).__init__()


class SMB2CreateDurableHandleReconnect(Structure):
    """
    [MS-SMB2] 2.2.13.2.4 SMB2_CREATE_DURABLE_HANDLE_RECONNECT

    Used by the client when attempting to reestablish a durable open
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('data', StructureField(
                size=16,
                structure_type=smbprotocol.open.SMB2FileId
            ))
        ])
        super(SMB2CreateDurableHandleReconnect, self).__init__()


class SMB2CreateQueryMaximalAccessRequest(Structure):
    """
    [MS-SMB2] 2.2.13.2.5 SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST

    Used by the client to retrieve maximal access information as part of
    processing the open.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('timestamp', DateTimeField())
        ])
        super(SMB2CreateQueryMaximalAccessRequest, self).__init__()


class SMB2CreateAllocationSize(Structure):
    """
    [MS-SMB2] 2.2.13.2.6 SMB2_CREATE_ALLOCATION_SIZE

    Used by the client to set the allocation size of a file that is being
    newly created or overwritten.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('allocation_size', IntField(size=8))
        ])
        super(SMB2CreateAllocationSize, self).__init__()


class SMB2CreateTimewarpToken(Structure):
    """
    [MS-SMB2] 2.2.13.2.7 SMB2_CREATE_TIMEWARP_TOKEN

    Used by the client when requesting the server to open a version of the file
    at a previous point in time.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('timestamp', DateTimeField())
        ])
        super(SMB2CreateTimewarpToken, self).__init__()


class SMB2CreateRequestLease(Structure):
    """
    [MS-SMB2] 2.2.13.2.8 SMB2_CREATE_REQUEST_LEASE

    Used by the cliet when requesting the server to return a lease.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('lease_key', BytesField(size=16)),
            ('lease_state', FlagField(
                size=4,
                flag_type=LeaseState
            )),
            ('lease_flags', IntField(size=4)),
            ('lease_duration', IntField(size=8))
        ])
        super(SMB2CreateRequestLease, self).__init__()


class SMB2CreateQueryOnDiskID(Structure):
    """
    [MS-SMB2] 2.2.13.2.9 SMB2_CREATE_QUERY_ON_DISK_ID
    Used by the client when requesting that the server return an identifier
    for an open file. This is an empty structure
    """

    def __init__(self):
        self.fields = OrderedDict([])
        super(SMB2CreateQueryOnDiskID, self).__init__()


class SMB2CreateRequestLeaseV2(Structure):
    """
    [MS-SMB2] 2.2.13.2.10 SMB2_CREATE_REQUEST_LEASE_V2

    Used when the client is requesting the server to return a lease on a file
    or directory.
    Valid for the SMB 3.x family only
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('lease_key', BytesField(size=16)),
            ('lease_state', FlagField(
                size=4,
                flag_type=LeaseState
            )),
            ('lease_flags', FlagField(
                size=4,
                flag_type=LeaseFlags
            )),
            ('lease_duration', IntField(size=8)),
            ('parent_lease_key', BytesField(size=16)),
            ('epoch', BytesField(size=16)),
            ('reserved', IntField(size=2))
        ])
        super(SMB2CreateRequestLeaseV2, self).__init__()


class SMB2CreateDurableHandleRequestV2(Structure):
    """
    [MS-SMB2] 2.2.13.2.11 SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2

    Used by the client to request the server mark the open as durable or
    persistent.
    Valid for the SMB 3.x family only
    """

    def __init__(self):
        self.fields = OrderedDict([
            # timeout in milliseconds
            ('timeout', IntField(size=4)),
            ('flags', FlagField(
                size=4,
                flag_type=DurableHandleFlags
            )),
            ('reserved', IntField(size=8)),
            ('create_guid', UuidField(size=16))
        ])
        super(SMB2CreateDurableHandleRequestV2, self).__init__()


class SMB2CreateDurableHandleReconnectV2(Structure):
    """
    [MS-SMB2] 2.2.13.2.12 SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2

    Used by the client when reestablishing a durable open.
    Valid for the SMB 3.x family only
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('file_id', StructureField(
                size=16,
                structure_type=smbprotocol.open.SMB2FileId
            )),
            ('create_guid', UuidField(size=16)),
            ('flags', FlagField(
                size=4,
                flag_type=DurableHandleFlags
            ))
        ])
        super(SMB2CreateDurableHandleReconnectV2, self).__init__()


class SMB2CreateAppInstanceId(Structure):
    """
    [MS-SMB2] 2.2.13.2.13 SMB2_CREATE_APP_INSTANCE_ID

    Used by the client when supplying an identifier provided by an application.
    Valid for the SMB 3.x family and should also have an durable handle on the
    create request.
    """

    def __init__(self):
        self.fields = OrderedDict(
            ('structure_size', IntField(
                size=2,
                default=20
            )),
            ('reserved', IntField(size=2)),
            ('app_instance_id', BytesField(size=16))
        )
        super(SMB2CreateAppInstanceId, self).__init__()


class SMB2SVHDXOpenDeviceContext(Structure):
    """
    [MS-SMB2] 2.2.13.2.14 SVHDX_OPEN_DEVICE_CONTEXT
    [MS-RSVD] 2.2.4.12 SVHDX_OPEN_DEVICE_CONTEXT

    Used to open the shared virtual disk file.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('version', IntField(
                size=4,
                default=1
            )),
            ('has_initiator_id', BoolField(size=1)),
            ('reserved', BytesField(
                size=3,
                default=b"\x00\x00\x00"
            )),
            ('initiator_id', UuidField(size=16)),
            ('originator_flags', EnumField(
                size=4,
                enum_type=SVHDXOriginatorFlags
            )),
            ('open_request_id', IntField(size=8)),
            ('initiator_host_name_length', IntField(
                size=2,
                default=lambda s: len(s['initiator_host_name'])
            )),
            # utf-16-le encoded string
            ('initiator_host_name', BytesField(
                size=lambda s: s['initiator_host_name_length'].get_value()
            ))
        ])
        super(SMB2SVHDXOpenDeviceContext, self).__init__()


class SMB2SVHDXOpenDeviceContextV2(Structure):
    """
    [MS-SMB2] 2.2.13.2.14 SVHDX_OPEN_DEVICE_CONTEXT
    [MS-RSVD] 2.2.4.32 SVHDX_OPEN_DEVICE_CONTEXT_V2

    Used to open the shared virtual disk file on the RSVD Protocol version 2
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('version', IntField(
                size=4,
                default=2
            )),
            ('has_initiator_id', BoolField(size=1)),
            ('reserved', BytesField(
                size=3,
                default=b"\x00\x00\x00"
            )),
            ('initiator_id', UuidField(size=16)),
            ('originator_flags', EnumField(
                size=4,
                enum_type=SVHDXOriginatorFlags
            )),
            ('open_request_id', IntField(size=8)),
            ('initiator_host_name_length', IntField(
                size=2,
                default=lambda s: len(s['initiator_host_name'])
            )),
            # utf-16-le encoded string
            ('initiator_host_name', BytesField(
                size=lambda s: s['initiator_host_name_length'].get_value()
            )),
            ('virtual_disk_properties_initialized', IntField(size=4)),
            ('server_service_version', IntField(size=4)),
            ('virtual_sector_size', IntField(size=4)),
            ('physical_sector_size', IntField(size=4)),
            ('virtual_size', IntField(size=8))
        ])
        super(SMB2SVHDXOpenDeviceContextV2, self).__init__()


class SMB2CreateAppInstanceVersion(Structure):
    """
    [MS-SMB2] 2.2.13.2.15 SMB2_CREATE_APP_INSTANCE_VERSION

    Used when the client is supplying a version for the app instance identifier
    provided by an application.
    Valid for the SMB 3.1.1+ family
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=24
            )),
            ('reserved', IntField(size=2)),
            ('padding', IntField(size=4)),
            ('app_instance_version_high', IntField(size=8)),
            ('app_instance_version_low', IntField(size=8))
        ])
        super(SMB2CreateAppInstanceVersion, self).__init__()
