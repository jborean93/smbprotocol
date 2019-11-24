# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import struct

from collections import (
    OrderedDict,
)

from smbprotocol.structure import (
    BytesField,
    EnumField,
    FlagField,
    IntField,
    ListField,
    Structure,
    StructureField,
)


class AccessMask(object):
    """
    [MS-DTYP]

    2.4.3 ACCESS_MASK
    32-bit set of flags that are used to encode the user rights to an object.
    This is just a generic setup of access mask flags to set an can vary
    from the object being set. When setting the AccessMask on an ACE packet,
    any 32-bit value can be used and this is just as a guideline.
    """
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    GENERIC_EXECUTE = 0x20000000
    GENERIC_ALL = 0x10000000
    MAXIMUM_ALLOWED = 0x02000000
    ACCESS_SYSTEM_SECURITY = 0x01000000
    SYNCHRONIZE = 0x00100000
    WRITE_OWNER = 0x00080000
    WRITE_DACL = 0x00040000
    READ_CONTROL = 0x00020000
    DELETE = 0x00010000


class AceType(object):
    """
    [MS-DTYP]

    2.4.4.1 ACE_HEADER AceType
    The type of ACE in the ACE packet.
    """
    # Current only have structures for the first 3
    ACCESS_ALLOWED_ACE_TYPE = 0x00
    ACCESS_DENIED_ACE_TYPE = 0x01
    SYSTEM_AUDIT_ACE_TYPE = 0x02

    # No structures are defined for the below
    SYSTEM_ALARM_ACE_TYPE = 0x03
    ACCESS_ALLOWED_COMPOUND_ACE_TYPE = 0x04
    ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
    ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06
    SYSTEM_AUDIT_OBJECT_ACE_TYPE = 0x07
    SYSTEM_ALARM_OBJECT_ACE_TYPE = 0x08
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x09
    ACCESS_DENIED_CALLBACK_ACE_TYPE = 0x0a
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0x0b
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = 0x0c
    SYSTEM_AUDIT_CALLBACK_ACE_TYPE = 0x0d
    SYSTEM_ALARM_CALLBACK_ACE_TYPE = 0x0e
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE = 0x0f
    SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE = 0x10
    SYSTEM_MANDATORY_LABEL_ACE_TYPE = 0x11
    SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE = 0x12
    SYSTEM_SCOPED_POLICY_ID_ACE_TYPE = 0x13


class AceFlags(object):
    """
    [MS-DTYP]

    2.4.4.1 ACE_HEADER AceFlags
    Controls the ACE specified in the ACE packet.
    """
    CONTAINER_INHERIT_ACE = 0x02
    FAILED_ACCESS_ACE_FLAG = 0x80
    INHERIT_ONLY_ACE = 0x08
    INHERITED_ACE = 0x10
    NO_PROPAGATE_INHERITY_ACE = 0x04
    OBJECT_INHERIT_ACE = 0x01
    SUCCESSFUL_ACCESS_ACE_FLAG = 0x40


class AclRevision(object):
    """
    [MS-DTYP]

    2.4.5 ACL AclRevision
    ACL_REVISION - AceType 0, 1, 2, 3, 11, 12, 13 are valid
    ACL_REVISION_DS - AceType 5, 6, 7, 8, 11 are valid (Directory Service)
    """
    ACL_REVISION = 0x02
    ACL_REVISION_DS = 0x04  # not natively supported yet


class SDControl(object):
    """
    [MS-DTYP]

    2.4.6 SECURITY_DESCRIPTOR Control
    Specifies control access bit flags.
    """
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


class SIDPacket(Structure):
    """
    [MS-DTYP] 2.4.2.2 SID--Packet Representation

    The packet representation of the SID type for use by block protocols. While
    the values can be set explicitly, it may be easier to use the from_string
    function store the byte structure from the string format.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('revision', IntField(
                size=1,
                default=1
            )),
            ('sub_authority_count', IntField(
                size=1,
                default=lambda s: len(s['sub_authorities'].get_value())
            )),
            ('reserved', IntField(size=2)),
            ('identifier_authority', IntField(
                size=4,
                little_endian=False
            )),
            ('sub_authorities', ListField(
                list_type=IntField(size=4),
                list_count=lambda s: s['sub_authority_count'].get_value()
            ))
        ])
        super(SIDPacket, self).__init__()

    def __str__(self):
        revision = self['revision'].get_value()
        id_authority = self['identifier_authority'].get_value()
        sub_authorities = self['sub_authorities'].get_value()
        sid_string = "S-%d-%d-%s" % (revision, id_authority,
                                     "-".join(str(x) for x in sub_authorities))
        return sid_string

    def from_string(self, sid_string):
        """
        Used to set the structure parameters based on the input string

        :param sid_string: String of the sid in S-x-x-x-x form
        """
        if not sid_string.startswith("S-"):
            raise ValueError("A SID string must start with S-")

        sid_entries = sid_string.split("-")
        if len(sid_entries) < 3:
            raise ValueError("A SID string must start with S and contain a "
                             "revision and identifier authority, e.g. S-1-0")

        revision = int(sid_entries[1])
        id_authority = int(sid_entries[2])
        sub_authorities = [int(i) for i in sid_entries[3:]]

        self['revision'].set_value(revision)
        self['identifier_authority'].set_value(id_authority)
        self['sub_authorities'] = sub_authorities


class AccessAllowedAce(Structure):
    """
    [MS-DTYP] 2.4.4.3 ACCESS_ALLOWED_ACE

    Used for the DACL that controls access to an object.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('ace_type', EnumField(
                size=1,
                default=AceType.ACCESS_ALLOWED_ACE_TYPE,
                enum_type=AceType
            )),
            ('ace_flags', FlagField(
                size=1,
                flag_type=AceFlags
            )),
            ('ace_size', IntField(
                size=2,
                default=lambda s: 8 + len(s['sid'])
            )),
            ('mask', FlagField(
                size=4,
                flag_type=AccessMask,
                flag_strict=False
            )),
            ('sid', StructureField(
                structure_type=SIDPacket
            ))
        ])
        super(AccessAllowedAce, self).__init__()


class AccessDeniedAce(Structure):
    """
    [MS-DTYP] 2.4.4.4 ACCESS_DENIED_ACE

    Used for the DACL that controls denies to an object.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('ace_type', EnumField(
                size=1,
                default=AceType.ACCESS_DENIED_ACE_TYPE,
                enum_type=AceType
            )),
            ('ace_flags', FlagField(
                size=1,
                flag_type=AceFlags
            )),
            ('ace_size', IntField(
                size=2,
                default=lambda s: 8 + len(s['sid'])
            )),
            ('mask', FlagField(
                size=4,
                flag_type=AccessMask,
                flag_strict=False
            )),
            ('sid', StructureField(
                structure_type=SIDPacket
            ))
        ])
        super(AccessDeniedAce, self).__init__()


class SystemAuditAce(Structure):
    """
    [MS-DTYP] 2.4.4.10 SYSTEM_AUDIT_ACE

    Used for the SACL that specifies what types of access cause system-level
    notifications.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('ace_type', EnumField(
                size=1,
                default=AceType.SYSTEM_AUDIT_ACE_TYPE,
                enum_type=AceType
            )),
            ('ace_flags', FlagField(
                size=1,
                flag_type=AceFlags
            )),
            ('ace_size', IntField(
                size=2,
                default=lambda s: 8 + len(s['sid'])
            )),
            ('mask', FlagField(
                size=4,
                flag_type=AccessMask,
                flag_strict=False
            )),
            ('sid', StructureField(
                structure_type=SIDPacket
            ))
        ])
        super(SystemAuditAce, self).__init__()


class AclPacket(Structure):
    """
    [MS-DTYP] 2.4.5 ACL

    Access Control List packet is used to specify a list of individual ACEs.
    An ACL is said to be in canonical form if:
        All explicit ACEs are placed before inherited ACEs
        Within the explicit ACEs, deny ACEs come before grant ACEs
        Deny ACEs on the object come before deny ACEs on a child or property
        Grant ACEs on the object come before grant ACEs on a child or property
        Inherited ACEs are placed in the order in which they were inherited
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('acl_revision', EnumField(
                size=1,
                default=AclRevision.ACL_REVISION,
                enum_type=AclRevision
            )),
            ('sbz1', IntField(size=1)),
            ('acl_size', IntField(
                size=2,
                default=lambda s: 8 + len(s['aces'])
            )),
            ('ace_count', IntField(
                size=2,
                default=lambda s: len(s['aces'].get_value())
            )),
            ('sbz2', IntField(size=2)),
            ('aces', ListField(
                list_count=lambda s: s['ace_count'].get_value(),
                unpack_func=lambda s, d: self._unpack_aces(s, d)
            ))
        ])
        super(AclPacket, self).__init__()

    def _unpack_aces(self, structure, data):
        aces = []
        while data != b"":
            ace_type = struct.unpack("<B", data[:1])[0]
            ace_struct = {
                AceType.ACCESS_ALLOWED_ACE_TYPE: AccessAllowedAce(),
                AceType.ACCESS_DENIED_ACE_TYPE: AccessDeniedAce(),
                AceType.SYSTEM_AUDIT_ACE_TYPE: SystemAuditAce()
            }.get(ace_type, None)

            if not ace_struct:
                ace_size = struct.unpack("<H", data[2:4])[0]
                aces.append(data[:ace_size])
                data = data[ace_size:]
            else:
                ace_struct.unpack(data)
                aces.append(ace_struct)
                data = data[len(ace_struct):]

        return aces


class SMB2CreateSDBuffer(Structure):
    """
    [MS-SMB2] 2.2.13.2.2 SMB2_CREATE_SD_BUFFER
    [MS-DTYP] 2.4.6 SECURITY_DESCRIPTOR

    Used to apply a security descriptor to a newly created file.
    """

    def __init__(self):
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
            # buffer contains owner_sid, owner_group, sacl and dacl at
            # different offset, use get/set_* to get and set the individual
            # components instead of touching the buffer directly
            ('buffer', BytesField()),
        ])
        # used to store the buffer values so it can easily be rebuilt
        self._buffer = OrderedDict()
        super(SMB2CreateSDBuffer, self).__init__()

    def get_owner(self):
        return self._get_sid_from_buffer('offset_owner')

    def set_owner(self, sid):
        self._buffer['owner'] = sid
        self._rebuild_buffer()

    def get_group(self):
        return self._get_sid_from_buffer('offset_group')

    def set_group(self, sid):
        self._buffer['group'] = sid
        self._rebuild_buffer()

    def get_sacl(self):
        return self._get_acl_from_buffer('offset_sacl', SDControl.SACL_PRESENT)

    def set_sacl(self, acl):
        if acl:
            self['control'].set_flag(SDControl.SACL_PRESENT)
        self._buffer["sacl"] = acl
        self._rebuild_buffer()

    def get_dacl(self):
        return self._get_acl_from_buffer('offset_dacl', SDControl.DACL_PRESENT)

    def set_dacl(self, acl):
        if acl:
            self['control'].set_flag(SDControl.DACL_PRESENT)
        self._buffer["dacl"] = acl
        self._rebuild_buffer()

    def _get_sid_from_buffer(self, offset_field):
        offset = self[offset_field].get_value()
        if offset == 0:
            return None

        buffer_data = self['buffer'].get_value()[offset - 20:]
        sid = SIDPacket()
        sid.unpack(buffer_data)
        return sid

    def _get_acl_from_buffer(self, offset_field, flag):
        if not self['control'].has_flag(flag):
            return None

        offset = self[offset_field].get_value() - 20
        buffer_data = self['buffer'].get_value()[offset:]
        length = struct.unpack("<H", buffer_data[2:4])[0]
        data = buffer_data[:length]
        acl = AclPacket()
        acl.unpack(data)
        return acl

    def _rebuild_buffer(self):
        buffer = b""
        offset_count = 20

        for field, value in self._buffer.items():
            if not value:
                continue
            offset_field = "offset_%s" % field
            field_bytes = value.pack()
            buffer += field_bytes
            self[offset_field].set_value(offset_count)
            offset_count += len(field_bytes)

        self['buffer'].set_value(buffer)
