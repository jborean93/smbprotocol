from smbclient import mkdir, open_file
from smbclient.security import (
    ACE,
    AccessMaskCompound,
    ACEFlags,
    ACEType,
    SecurityDescriptor,
    _sec_desc_to_low_level,
    get_security_descriptor,
    set_security_descriptor,
)
from smbprotocol.security_descriptor import (
    AccessAllowedAce,
    AceType,
    AclPacket,
    SDControl,
    SIDPacket,
    SMB2CreateSDBuffer,
)


def test_aceflags_enum():
    e1 = ACEFlags.OBJECT_INHERIT | ACEFlags.CONTAINER_INHERIT
    assert int(e1) == 0x3
    flags = ACEFlags.parse(0x3)
    assert set(flags) == {
        ACEFlags.OBJECT_INHERIT.name,
        ACEFlags.CONTAINER_INHERIT.name,
    }
    assert ACEFlags.joined(0x3) == "CONTAINER_INHERIT|OBJECT_INHERIT"

    # find a unknown flag value
    flags = ACEFlags.parse(0x3 | 0x1000)
    assert set(flags) == {
        ACEFlags.OBJECT_INHERIT.name,
        ACEFlags.CONTAINER_INHERIT.name,
        "0x1000",
    }

    assert int(ACEFlags.OBJECT_INHERIT) == 0x1


def test_acetype_enum():
    assert int(ACEType.ALLOWED) == 0
    assert int(ACEType.DENIED) == 1


def test_access_mask_compount_enum():
    assert AccessMaskCompound._pick(0x001F01FF) is AccessMaskCompound.FULL
    assert AccessMaskCompound._pick(0x001F01F0) is None

    assert AccessMaskCompound.joined(0x001F01FF) == "FULL"
    assert AccessMaskCompound.joined(0x00100100) == "FILE_WRITE_ATTRIBUTE|SYNCHRONIZE"

    assert int(AccessMaskCompound.FULL) == 0x001F01FF


def test_convert_to_sd():
    # internal function converting low level protocol type to a high level
    # SecurityDescriptor
    sid1 = SIDPacket()
    sid1.from_string("S-1-1-0")
    sid2 = SIDPacket()
    sid2.from_string("S-1-5-21-3242954042-3778974373-1659123385-1104")
    sid3 = SIDPacket()
    sid3.from_string("S-1-2-0")

    ace1 = AccessAllowedAce()
    ace1["sid"] = sid1
    ace1["mask"] = 0x001F01FF
    ace2 = AccessAllowedAce()
    ace2["sid"] = sid2
    ace2["mask"] = 0x001F01FF
    ace3 = AccessAllowedAce()
    ace3["sid"] = sid3
    ace3["mask"] = 0x001200A9

    acl = AclPacket()
    acl["aces"] = [ace1, ace2, ace3]

    ll_sd = SMB2CreateSDBuffer()
    ll_sd["control"].set_flag(SDControl.SELF_RELATIVE)
    ll_sd.set_dacl(acl)
    ll_sd.set_owner(sid2)
    ll_sd.set_group(sid1)
    ll_sd.set_sacl(None)

    sd = SecurityDescriptor._load(ll_sd)

    assert sd.owner == "S-1-5-21-3242954042-3778974373-1659123385-1104"
    assert sd.group == "S-1-1-0"

    rsd = repr(sd)
    assert rsd.startswith("SecurityDescriptor(")
    assert "owner" in rsd
    assert "group" in rsd
    assert "d_acl" in rsd
    assert "s_acl" in rsd
    assert repr(sd.d_acl[0]) == "ACE(ace_type=<ACEType.ALLOWED: 0>, ace_flags=0, mask=2032127, sid='S-1-1-0')"
    assert sd.d_acl[0].numeric_str() == "ACE:S-1-1-0:0x0/0x0/0x001f01ff"
    assert sd.d_acl[0].symbolic_str() == "ACE:S-1-1-0:ALLOWED/0/FULL"


def test_convert_from_sd():
    # internal function converting high level SecurityDescriptor type to
    # protocol level type
    sd = SecurityDescriptor(
        owner=None,
        group=None,
        d_acl=[
            ACE(
                sid="S-1-1-0",
                ace_type=ACEType.ALLOWED,
                ace_flags=0,
                mask=0x001F01FF,
            ),
            ACE(
                sid="S-1-5-21-3242954042-3778974373-1659123385-1104",
                ace_type=ACEType.ALLOWED,
                ace_flags=0,
                mask=0x001F01FF,
            ),
            ACE(
                sid="S-1-2-0",
                ace_type=ACEType.ALLOWED,
                ace_flags=0,
                mask=0x001200A9,
            ),
        ],
    )
    actual = _sec_desc_to_low_level(sd)

    assert actual["offset_owner"].get_value() == 0
    assert actual["offset_group"].get_value() == 0
    assert actual["offset_sacl"].get_value() == 0
    assert actual["offset_dacl"].get_value() == 20
    assert len(actual["buffer"]) == 84

    assert not actual.get_owner()
    assert not actual.get_group()
    assert not actual.get_sacl()
    dacl = actual.get_dacl()
    assert dacl["acl_size"].get_value() == 84
    assert dacl["ace_count"].get_value() == 3

    aces = dacl["aces"].get_value()
    assert isinstance(aces, list)
    assert len(aces) == 3

    ace1, _, ace3 = aces
    assert ace1["ace_type"].get_value() == AceType.ACCESS_ALLOWED_ACE_TYPE
    assert ace1["ace_flags"].get_value() == 0
    assert ace1["ace_size"].get_value() == 20
    assert ace1["mask"].get_value() == 0x001F01FF
    assert str(ace1["sid"]) == "S-1-1-0"

    assert ace3["ace_type"].get_value() == AceType.ACCESS_ALLOWED_ACE_TYPE
    assert ace3["ace_flags"].get_value() == 0
    assert ace3["ace_size"].get_value() == 20
    assert ace3["mask"].get_value() == 0x001200A9
    assert str(ace3["sid"]) == "S-1-2-0"


def test_get_security_descriptor(smb_share):
    d1 = "%s\\dir1" % smb_share
    d2 = "%s\\dir1\\dir2" % smb_share
    f1 = "%s\\dir1\\aaa" % smb_share

    mkdir(d1)
    mkdir(d2)
    with open_file(f1, mode="w") as fd:
        fd.write("content")

    # read security descriptor from dir
    sd = get_security_descriptor(d2)
    assert sd.owner.startswith("S-")
    assert sd.group.startswith("S-")
    assert sd.d_acl
    assert len(sd.d_acl) == 3

    # read security descriptor from file
    sd = get_security_descriptor(f1)
    assert sd.owner.startswith("S-")
    assert sd.group.startswith("S-")
    assert sd.d_acl
    assert len(sd.d_acl) == 3


def test_set_security_descriptor(smb_share):
    d1 = "%s\\dir1" % smb_share
    d2 = "%s\\dir1\\dir2" % smb_share
    f1 = "%s\\dir1\\aaa" % smb_share

    mkdir(d1)
    mkdir(d2)
    with open_file(f1, mode="w") as fd:
        fd.write("content")

    sd = get_security_descriptor(d2)
    newsd = SecurityDescriptor(
        owner=None,
        group=None,
        d_acl=sd.d_acl
        + [
            ACE(
                sid="S-1-1-0",
                ace_type=ACEType.ALLOWED,
                ace_flags=0,
                mask=0x001F01FF,
            )
        ],
    )
    set_security_descriptor(d2, newsd)
    sd = get_security_descriptor(d2)
    assert sd.owner.startswith("S-")
    assert sd.group.startswith("S-")
    assert sd.d_acl
    assert len(sd.d_acl) >= 4
