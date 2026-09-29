import enum

from smbclient._io import (
    SMBFileTransaction,
    SMBRawIO,
    query_info,
    set_info,
)
from smbprotocol.file_info import FileInformationClass, InfoType
from smbprotocol.open import (
    CreateOptions,
    DirectoryAccessMask,
    InfoAdditionalInformation,
)
from smbprotocol.security_descriptor import (
    AccessAllowedAce,
    AccessDeniedAce,
)
from smbprotocol.security_descriptor import AccessMask as _AccessMask
from smbprotocol.security_descriptor import AceFlags as _AceFlags
from smbprotocol.security_descriptor import AceType as _AceType
from smbprotocol.security_descriptor import (
    AclPacket,
    SDControl,
    SIDPacket,
    SMB2CreateSDBuffer,
)


class _flagsEnum(enum.Enum):
    """Base class to help convert between bitmask fields and pythonic enums."""

    @classmethod
    def parse(cls, value):
        _flags = []
        _remain = value
        for flag in cls:
            fvalue = flag.value
            if fvalue & value == fvalue:
                _flags.append(flag.name)
                _remain &= ~fvalue
        if _remain != 0:
            _flags.append(hex(_remain))
        return _flags

    @classmethod
    def joined(cls, value, sep="|"):
        _flags = cls.parse(value)
        if not _flags:
            return "0"
        return sep.join(sorted(_flags))

    def __or__(self, other):
        if isinstance(other, _flagsEnum):
            other = other.value
        return self.value | int(other)

    def __int__(self):
        return self.value


class ACEType(enum.Enum):
    """Enumeration of NT ACL Entry types."""

    ALLOWED = _AceType.ACCESS_ALLOWED_ACE_TYPE
    DENIED = _AceType.ACCESS_DENIED_ACE_TYPE
    AUDIT = _AceType.SYSTEM_AUDIT_ACE_TYPE

    def __int__(self):
        return self.value


class ACEFlags(_flagsEnum):
    """Enumeration of bit fields in the ACE flags field."""

    OBJECT_INHERIT = _AceFlags.OBJECT_INHERIT_ACE
    CONTAINER_INHERIT = _AceFlags.CONTAINER_INHERIT_ACE
    NO_PROPAGATE_INHERIT = _AceFlags.NO_PROPAGATE_INHERITY_ACE
    INHERIT_ONLY = _AceFlags.INHERIT_ONLY_ACE
    INHERITED_ACE = _AceFlags.INHERITED_ACE
    SUCCESSFUL_ACCESS = _AceFlags.SUCCESSFUL_ACCESS_ACE_FLAG
    FAILED_ACCESS = _AceFlags.FAILED_ACCESS_ACE_FLAG


class ShortACEFlags(_flagsEnum):
    """Variation of ACEFlags compatible with the output of smbcacls tool."""

    OI = ACEFlags.OBJECT_INHERIT.value
    CI = ACEFlags.CONTAINER_INHERIT.value
    NP = ACEFlags.NO_PROPAGATE_INHERIT.value
    IO = ACEFlags.INHERIT_ONLY.value
    ID = ACEFlags.INHERITED_ACE.value
    SA = ACEFlags.SUCCESSFUL_ACCESS.value
    FA = ACEFlags.FAILED_ACCESS.value


class AccessMask(_flagsEnum):
    """Enumeration of bit fields in the ACE mask field."""

    GENERIC_READ = _AccessMask.GENERIC_READ
    GENERIC_WRITE = _AccessMask.GENERIC_WRITE
    GENERIC_EXECUTE = _AccessMask.GENERIC_EXECUTE
    GENERIC_ALL = _AccessMask.GENERIC_ALL
    MAXIMUM_ALLOWED = _AccessMask.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = _AccessMask.ACCESS_SYSTEM_SECURITY
    SYNCHRONIZE = _AccessMask.SYNCHRONIZE
    WRITE_OWNER = _AccessMask.WRITE_OWNER
    WRITE_DACL = _AccessMask.WRITE_DACL
    READ_CONTROL = _AccessMask.READ_CONTROL
    DELETE = _AccessMask.DELETE

    FILE_READ_DATA = 0x00000001
    FILE_WRITE_DATA = 0x00000002
    FILE_APPEND_DATA = 0x00000004
    FILE_READ_EA = 0x00000008
    FILE_WRITE_EA = 0x00000010
    FILE_EXECUTE = 0x00000020
    FILE_READ_ATTRIBUTE = 0x00000080
    FILE_WRITE_ATTRIBUTE = 0x00000100


class AccessMaskCompound(enum.Enum):
    """ACE mask field well known compound bit mask values."""

    FULL = 0x001F01FF

    @classmethod
    def _pick(cls, value):
        for flag in cls:
            if flag.value == value:
                return flag
        return None

    @classmethod
    def joined(cls, value):
        compound = cls._pick(value)
        if compound is not None:
            return compound.name
        return AccessMask.joined(value)

    def __int__(self):
        return self.value


class ACE:
    """High-level representation of an Acess Control List Entry for
    the SMB NT discretionary ACL.
    """

    def __init__(self, *, ace_type, ace_flags, mask, sid):
        self.ace_type = ace_type
        self.ace_flags = int(ace_flags)
        self.mask = int(mask)
        self.sid = sid

    @classmethod
    def _load(cls, sd_ace):
        ace_type = ACEType(sd_ace["ace_type"].get_value())
        ace_flags = sd_ace["ace_flags"].get_value()
        mask = sd_ace["mask"].get_value()
        sid = str(sd_ace["sid"])
        return cls(ace_type=ace_type, ace_flags=ace_flags, mask=mask, sid=sid)

    def __repr__(self):
        return (
            f"{self.__class__.__name__}("
            f"ace_type={self.ace_type!r},"
            f" ace_flags={self.ace_flags!r},"
            f" mask={self.mask!r},"
            f" sid={self.sid!r}"
            ")"
        )

    def numeric_str(self, label="ACE"):
        return (
            f"{label}:{self.sid}:"  # format label and sid
            f"{self.ace_type.value:#x}/"  # type
            f"{self.ace_flags:#x}/"  # flags
            f"{self.mask:#010x}"  # mask
        )

    def symbolic_str(self, label="ACE"):
        return (
            f"{label}:{self.sid}:"  # format label and sid
            f"{self.ace_type.name}/"  # type
            f"{ShortACEFlags.joined(self.ace_flags)}/"  # flags
            f"{AccessMaskCompound.joined(self.mask)}"  # mask
        )

    __str__ = symbolic_str


class SecurityDescriptor:
    """High-level representation of a Security Descriptor used to read
    or update the access control of an object.
    """

    def __init__(self, *, owner, group, d_acl=None, s_acl=None):
        self.owner = owner
        self.group = group
        self.d_acl = d_acl
        self.s_acl = s_acl

    @classmethod
    def _load(cls, smb_sd):
        owner = str(smb_sd.get_owner())
        group = str(smb_sd.get_group())
        dacl = smb_sd.get_dacl()
        unpacked_d_acl = [ACE._load(a) for a in dacl["aces"]]
        return cls(owner=owner, group=group, d_acl=unpacked_d_acl)

    def __str__(self):
        if self.s_acl:
            raise NotImplementedError("s_acl")
        return (
            f"{self.__class__.__name__}("
            f"owner={self.owner!r},"
            f" group={self.group!r},"
            f" d_acl={self.d_acl!r},"
            f" s_acl={self.s_acl!r}"
            ")"
        )

    __repr__ = __str__


def get_security_descriptor(path, follow_symlinks=True, **kwargs):
    """
    Return a high-level security descriptor for the given path.
    The returned security descriptor will container owner information and
    the discretionary ACL value.

    :param path: The path to check if it exists.
    :param follow_symlinks: Whether to follow the symlink at path if encountered.
    :param kwargs: Common SMB Session arguments for smbclient.
    :return: A SecurityDescriptor object.
    """
    raw = SMBRawIO(
        path,
        mode="r",
        share_access="rw",
        desired_access=DirectoryAccessMask.READ_CONTROL,
        file_attributes=0,
        create_options=(0 if follow_symlinks else CreateOptions.FILE_OPEN_REPARSE_POINT),
        **kwargs,
    )
    with SMBFileTransaction(raw) as transaction:
        query_info(
            transaction,
            _SecurityDescriptorInformation,
            output_buffer_length=65536,
            additional_information=(
                InfoAdditionalInformation.OWNER_SECURTIY_INFORMATION
                | InfoAdditionalInformation.GROUP_SECURITY_INFORMATION
                | InfoAdditionalInformation.DACL_SECURITY_INFORMATION
            ),
        )
    (sd_info,) = transaction.results
    return SecurityDescriptor._load(sd_info)


def set_security_descriptor(path, sec_desc, follow_symlinks=True, **kwargs):
    """
    Update an objects discretionary ACL using a security descriptor object.
    This security will not update owner or group. These values must be
    set to None.

    :param path: The path to check if it exists.
    :param sec_desc: A SecurityDescriptor object.
    :param follow_symlinks: Whether to follow the symlink at path if encountered.
    :param kwargs: Common SMB Session arguments for smbclient.
    :return: None
    """
    sd = _sec_desc_to_low_level(sec_desc)
    raw = SMBRawIO(
        path,
        mode="r",
        share_access="rw",
        desired_access=DirectoryAccessMask.WRITE_DAC,
        file_attributes=0,
        create_options=(0 if follow_symlinks else CreateOptions.FILE_OPEN_REPARSE_POINT),
        **kwargs,
    )
    with SMBFileTransaction(raw) as transaction:
        set_info(
            transaction,
            sd,
            additional_information=InfoAdditionalInformation.DACL_SECURITY_INFORMATION,
        )
    (_result,) = transaction.results
    return


class _SecurityDescriptorInformation(SMB2CreateSDBuffer):
    INFO_TYPE = InfoType.SMB2_0_INFO_SECURITY
    INFO_CLASS = FileInformationClass.FILE_NONE


def _sec_desc_to_low_level(sec_desc):
    """Convert a security descriptor to a low-level protocol security
    descriptor.
    """
    assert not sec_desc.owner, "not supported"
    assert not sec_desc.group, "not supported"
    sd = _SecurityDescriptorInformation()
    sd["control"].set_flag(SDControl.SELF_RELATIVE)
    sd.set_dacl(_sec_desc_to_dacl(sec_desc))
    return sd


def _sec_desc_to_dacl(sec_desc):
    """Convert a security descriptor DACL to a low-level protocol acl packet."""
    acl = AclPacket()
    acl["aces"] = [_ace_to_low_level(a) for a in sec_desc.d_acl]
    return acl


def _ace_to_low_level(ace):
    """Convert a high-level ACE object to a low-level protocol ACE object."""
    if ace.ace_type is ACEType.ALLOWED:
        ll_ace = AccessAllowedAce()
    else:
        ll_ace = AccessDeniedAce()
    ll_ace["ace_flags"] = int(ace.ace_flags)
    ll_ace["mask"] = int(ace.mask)
    ll_sid = SIDPacket()
    ll_sid.from_string(ace.sid)
    ll_ace["sid"] = ll_sid
    return ll_ace
