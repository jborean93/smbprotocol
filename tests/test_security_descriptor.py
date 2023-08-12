# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import pytest

from smbprotocol.security_descriptor import (
    AccessAllowedAce,
    AccessDeniedAce,
    AceType,
    AclPacket,
    AclRevision,
    SDControl,
    SIDPacket,
    SMB2CreateSDBuffer,
    SystemAuditAce,
)


class TestSIDPacket:
    def test_create_message(self):
        sid = "S-1-1-0"
        message = SIDPacket()
        message.from_string(sid)
        expected = b"\x01" b"\x01" b"\x00\x00" b"\x00\x00\x00\x01" b"\x00\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 12
        assert actual == expected
        assert str(message) == sid

    def test_create_domain_sid(self):
        sid = "S-1-5-21-3242954042-3778974373-1659123385-1104"
        message = SIDPacket()
        message.from_string(sid)
        expected = (
            b"\x01"
            b"\x05"
            b"\x00\x00"
            b"\x00\x00\x00\x05"
            b"\x15\x00\x00\x00"
            b"\x3a\x8d\x4b\xc1"
            b"\xa5\x92\x3e\xe1"
            b"\xb9\x36\xe4\x62"
            b"\x50\x04\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 28
        assert actual == expected
        assert str(message) == sid

    def test_parse_string_fail_no_s(self):
        sid = SIDPacket()
        with pytest.raises(ValueError) as exc:
            sid.from_string("A-1-1-0")
        assert str(exc.value) == "A SID string must start with S-"

    def test_parse_string_fail_too_small(self):
        sid = SIDPacket()
        with pytest.raises(ValueError) as exc:
            sid.from_string("S-1")
        assert (
            str(exc.value) == "A SID string must start with S and contain"
            " a revision and identifier authority, e.g."
            " S-1-0"
        )

    def test_parse_message(self):
        actual = SIDPacket()
        data = b"\x01" b"\x01" b"\x00\x00" b"\x00\x00\x00\x01" b"\x00\x00\x00\x00"
        actual.unpack(data)
        assert len(actual) == 12
        assert str(actual) == "S-1-1-0"
        assert actual["revision"].get_value() == 1
        assert actual["sub_authority_count"].get_value() == 1
        assert actual["reserved"].get_value() == 0
        assert actual["identifier_authority"].get_value() == 1
        sub_auth = actual["sub_authorities"].get_value()
        assert isinstance(sub_auth, list)
        assert len(sub_auth) == 1
        assert sub_auth[0] == 0

    def test_parse_message_domain_sid(self):
        actual = SIDPacket()
        data = (
            b"\x01"
            b"\x05"
            b"\x00\x00"
            b"\x00\x00\x00\x05"
            b"\x15\x00\x00\x00"
            b"\x3a\x8d\x4b\xc1"
            b"\xa5\x92\x3e\xe1"
            b"\xb9\x36\xe4\x62"
            b"\x50\x04\x00\x00"
        )
        actual.unpack(data)
        assert len(actual) == 28
        assert str(actual) == "S-1-5-21-3242954042-3778974373-1659123385-1104"
        assert actual["revision"].get_value() == 1
        assert actual["sub_authority_count"].get_value() == 5
        assert actual["reserved"].get_value() == 0
        assert actual["identifier_authority"].get_value() == 5
        sub_auth = actual["sub_authorities"].get_value()
        assert isinstance(sub_auth, list)
        assert len(sub_auth) == 5
        assert sub_auth[0] == 21
        assert sub_auth[1] == 3242954042
        assert sub_auth[2] == 3778974373
        assert sub_auth[3] == 1659123385
        assert sub_auth[4] == 1104


class TestAccessAllowedAce:
    def test_create_message(self):
        sid = SIDPacket()
        sid.from_string("S-1-1-0")

        message = AccessAllowedAce()
        message["mask"] = 2032127
        message["sid"] = sid
        expected = (
            b"\x00"
            b"\x00"
            b"\x14\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 20
        assert actual == expected

    def test_parse_message(self):
        actual = AccessAllowedAce()
        data = (
            b"\x00"
            b"\x00"
            b"\x14\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 20
        assert data == b""
        assert actual["ace_type"].get_value() == AceType.ACCESS_ALLOWED_ACE_TYPE
        assert actual["ace_flags"].get_value() == 0
        assert actual["ace_size"].get_value() == 20
        assert actual["mask"].get_value() == 2032127
        assert str(actual["sid"].get_value()) == "S-1-1-0"


class TestAccessDeniedAce:
    def test_create_message(self):
        sid = SIDPacket()
        sid.from_string("S-1-1-0")

        message = AccessDeniedAce()
        message["mask"] = 2032127
        message["sid"] = sid
        expected = (
            b"\x01"
            b"\x00"
            b"\x14\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 20
        assert actual == expected

    def test_parse_message(self):
        actual = AccessDeniedAce()
        data = (
            b"\x01"
            b"\x00"
            b"\x14\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 20
        assert data == b""
        assert actual["ace_type"].get_value() == AceType.ACCESS_DENIED_ACE_TYPE
        assert actual["ace_flags"].get_value() == 0
        assert actual["ace_size"].get_value() == 20
        assert actual["mask"].get_value() == 2032127
        assert str(actual["sid"].get_value()) == "S-1-1-0"


class TestSystemAuditAce:
    def test_create_message(self):
        sid = SIDPacket()
        sid.from_string("S-1-1-0")

        message = SystemAuditAce()
        message["mask"] = 2032127
        message["sid"] = sid
        expected = (
            b"\x02"
            b"\x00"
            b"\x14\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 20
        assert actual == expected

    def test_parse_message(self):
        actual = SystemAuditAce()
        data = (
            b"\x02"
            b"\x00"
            b"\x14\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 20
        assert data == b""
        assert actual["ace_type"].get_value() == AceType.SYSTEM_AUDIT_ACE_TYPE
        assert actual["ace_flags"].get_value() == 0
        assert actual["ace_size"].get_value() == 20
        assert actual["mask"].get_value() == 2032127
        assert str(actual["sid"].get_value()) == "S-1-1-0"


class TestAclPacket:
    def test_create_message(self):
        sid1 = SIDPacket()
        sid1.from_string("S-1-1-0")
        sid2 = SIDPacket()
        sid2.from_string("S-1-5-21-3242954042-3778974373-1659123385-1104")

        ace1 = AccessAllowedAce()
        ace1["mask"] = 2032127
        ace1["sid"] = sid1
        ace2 = AccessAllowedAce()
        ace2["mask"] = 2032127
        ace2["sid"] = sid2
        # define an illegal ACE for tests to see if it is flexible for custom
        # aces'
        ace3 = AccessAllowedAce()
        ace3["ace_type"] = AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE
        ace3["sid"] = sid1

        message = AclPacket()
        message["aces"] = [ace1, ace2, ace3.pack()]
        expected = (
            b"\x02"
            b"\x00"
            b"\x54\x00"
            b"\x03\x00"
            b"\x00\x00"
            b"\x00"
            b"\x00"
            b"\x14\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x00"
            b"\x24\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x05"
            b"\x00\x00"
            b"\x00\x00\x00\x05"
            b"\x15\x00\x00\x00"
            b"\x3a\x8d\x4b\xc1"
            b"\xa5\x92\x3e\xe1"
            b"\xb9\x36\xe4\x62"
            b"\x50\x04\x00\x00"
            b"\x05"
            b"\x00"
            b"\x14\x00"
            b"\x00\x00\x00\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 84
        assert actual == expected

    def test_parse_message(self):
        actual = AclPacket()
        data = (
            b"\x02"
            b"\x00"
            b"\x54\x00"
            b"\x03\x00"
            b"\x00\x00"
            b"\x00"
            b"\x00"
            b"\x14\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x00"
            b"\x24\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x05"
            b"\x00\x00"
            b"\x00\x00\x00\x05"
            b"\x15\x00\x00\x00"
            b"\x3a\x8d\x4b\xc1"
            b"\xa5\x92\x3e\xe1"
            b"\xb9\x36\xe4\x62"
            b"\x50\x04\x00\x00"
            b"\x05"
            b"\x00"
            b"\x14\x00"
            b"\x00\x00\x00\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
        )

        actual.unpack(data)
        assert len(actual) == 84
        assert actual["acl_revision"].get_value() == AclRevision.ACL_REVISION
        assert actual["sbz1"].get_value() == 0
        assert actual["acl_size"].get_value() == 84
        assert actual["ace_count"].get_value() == 3
        assert actual["sbz2"].get_value() == 0
        aces = actual["aces"].get_value()
        assert len(aces) == 3

        assert aces[0]["ace_type"].get_value() == AceType.ACCESS_ALLOWED_ACE_TYPE
        assert aces[0]["ace_flags"].get_value() == 0
        assert aces[0]["ace_size"].get_value() == 20
        assert aces[0]["mask"].get_value() == 2032127
        assert str(aces[0]["sid"].get_value()) == "S-1-1-0"

        assert aces[1]["ace_type"].get_value() == AceType.ACCESS_ALLOWED_ACE_TYPE
        assert aces[1]["ace_flags"].get_value() == 0
        assert aces[1]["ace_size"].get_value() == 36
        assert aces[1]["mask"].get_value() == 2032127
        assert str(aces[1]["sid"].get_value()) == "S-1-5-21-3242954042-3778974373-1659123385-1104"

        assert isinstance(aces[2], bytes)
        assert aces[2] == b"\x05\x00\x14\x00\x00\x00\x00\x00" b"\x01\x01\x00\x00\x00\x00\x00\x01" b"\x00\x00\x00\x00"


class TestSMB2SDBuffer:
    def test_create_message(self):
        sid1 = SIDPacket()
        sid1.from_string("S-1-1-0")
        sid2 = SIDPacket()
        sid2.from_string("S-1-5-21-3242954042-3778974373-1659123385-1104")

        ace1 = AccessAllowedAce()
        ace1["mask"] = 2032127
        ace1["sid"] = sid1
        ace2 = AccessAllowedAce()
        ace2["mask"] = 2032127
        ace2["sid"] = sid2
        acl = AclPacket()
        acl["aces"] = [ace1, ace2]

        message = SMB2CreateSDBuffer()
        message["control"].set_flag(SDControl.SELF_RELATIVE)
        message.set_dacl(acl)
        message.set_owner(sid2)
        message.set_group(sid1)
        message.set_sacl(None)

        expected = (
            b"\x01"
            b"\x00"
            b"\x04\x80"
            b"\x54\x00\x00\x00"
            b"\x70\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x14\x00\x00\x00"
            b"\x02"
            b"\x00"
            b"\x40\x00"
            b"\x02\x00"
            b"\x00\x00"
            b"\x00"
            b"\x00"
            b"\x14\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x00"
            b"\x24\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x05"
            b"\x00\x00"
            b"\x00\x00\x00\x05"
            b"\x15\x00\x00\x00"
            b"\x3a\x8d\x4b\xc1"
            b"\xa5\x92\x3e\xe1"
            b"\xb9\x36\xe4\x62"
            b"\x50\x04\x00\x00"
            b"\x01\x05"
            b"\x00\x00"
            b"\x00\x00\x00\x05"
            b"\x15\x00\x00\x00"
            b"\x3a\x8d\x4b\xc1"
            b"\xa5\x92\x3e\xe1"
            b"\xb9\x36\xe4\x62"
            b"\x50\x04\x00\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 124
        assert actual == expected

    def test_create_message_sacl_group(self):
        sid = SIDPacket()
        sid.from_string("S-1-1-0")

        ace = AccessAllowedAce()
        ace["sid"] = sid
        acl = AclPacket()
        acl["aces"] = [ace]

        message = SMB2CreateSDBuffer()
        message.set_dacl(None)
        message.set_owner(None)
        message.set_group(sid)
        message.set_sacl(acl)

        expected = (
            b"\x01"
            b"\x00"
            b"\x10\x00"
            b"\x00\x00\x00\x00"
            b"\x14\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
            b"\x02"
            b"\x00"
            b"\x1c\x00"
            b"\x01\x00"
            b"\x00\x00"
            b"\x00"
            b"\x00"
            b"\x14\x00"
            b"\x00\x00\x00\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 60
        assert actual == expected

    def test_parse_message_sacl_group(self):
        actual = SMB2CreateSDBuffer()
        data = (
            b"\x01"
            b"\x00"
            b"\x10\x00"
            b"\x00\x00\x00\x00"
            b"\x14\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
            b"\x02"
            b"\x00"
            b"\x1c\x00"
            b"\x01\x00"
            b"\x00\x00"
            b"\x00"
            b"\x00"
            b"\x14\x00"
            b"\x00\x00\x00\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
        )
        actual.unpack(data)
        assert len(actual) == 60
        assert actual["revision"].get_value() == 1
        assert actual["sbz1"].get_value() == 0
        assert actual["control"].get_value() == 16
        assert actual["offset_owner"].get_value() == 0
        assert actual["offset_group"].get_value() == 20
        assert actual["offset_sacl"].get_value() == 32
        assert actual["offset_dacl"].get_value() == 0
        assert len(actual["buffer"]) == 40

        assert not actual.get_owner()
        assert str(actual.get_group()) == "S-1-1-0"
        sacl = actual.get_sacl()
        assert sacl["acl_revision"].get_value() == AclRevision.ACL_REVISION
        assert sacl["sbz1"].get_value() == 0
        assert sacl["acl_size"].get_value() == 28
        assert sacl["ace_count"].get_value() == 1
        assert sacl["sbz2"].get_value() == 0
        saces = sacl["aces"].get_value()
        assert isinstance(saces, list)
        assert len(saces) == 1
        assert saces[0]["ace_type"].get_value() == AceType.ACCESS_ALLOWED_ACE_TYPE
        assert saces[0]["ace_flags"].get_value() == 0
        assert saces[0]["ace_size"].get_value() == 20
        assert saces[0]["mask"].get_value() == 0
        assert str(saces[0]["sid"]) == "S-1-1-0"

        assert not actual.get_dacl()

    def test_parse_message(self):
        actual = SMB2CreateSDBuffer()
        data = (
            b"\x01"
            b"\x00"
            b"\x04\x80"
            b"\x54\x00\x00\x00"
            b"\x70\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x14\x00\x00\x00"
            b"\x02"
            b"\x00"
            b"\x40\x00"
            b"\x02\x00"
            b"\x00\x00"
            b"\x00"
            b"\x00"
            b"\x14\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x00"
            b"\x24\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x05"
            b"\x00\x00"
            b"\x00\x00\x00\x05"
            b"\x15\x00\x00\x00"
            b"\x3a\x8d\x4b\xc1"
            b"\xa5\x92\x3e\xe1"
            b"\xb9\x36\xe4\x62"
            b"\x50\x04\x00\x00"
            b"\x01\x05"
            b"\x00\x00"
            b"\x00\x00\x00\x05"
            b"\x15\x00\x00\x00"
            b"\x3a\x8d\x4b\xc1"
            b"\xa5\x92\x3e\xe1"
            b"\xb9\x36\xe4\x62"
            b"\x50\x04\x00\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
        )
        actual.unpack(data)
        assert len(actual) == 124
        assert actual["revision"].get_value() == 1
        assert actual["sbz1"].get_value() == 0
        assert actual["control"].get_value() == 32772
        assert actual["offset_owner"].get_value() == 84
        assert actual["offset_group"].get_value() == 112
        assert actual["offset_sacl"].get_value() == 0
        assert actual["offset_dacl"].get_value() == 20
        assert len(actual["buffer"]) == 104

        assert str(actual.get_owner()) == "S-1-5-21-3242954042-3778974373-1659123385-1104"
        assert str(actual.get_group()) == "S-1-1-0"
        assert not actual.get_sacl()
        dacl = actual.get_dacl()
        assert dacl["acl_revision"].get_value() == AclRevision.ACL_REVISION
        assert dacl["sbz1"].get_value() == 0
        assert dacl["acl_size"].get_value() == 64
        assert dacl["ace_count"].get_value() == 2
        assert dacl["sbz2"].get_value() == 0
        daces = dacl["aces"].get_value()
        assert isinstance(daces, list)
        assert len(daces) == 2
        assert daces[0]["ace_type"].get_value() == AceType.ACCESS_ALLOWED_ACE_TYPE
        assert daces[0]["ace_flags"].get_value() == 0
        assert daces[0]["ace_size"].get_value() == 20
        assert daces[0]["mask"].get_value() == 2032127
        assert str(daces[0]["sid"]) == "S-1-1-0"
        assert daces[1]["ace_type"].get_value() == AceType.ACCESS_ALLOWED_ACE_TYPE
        assert daces[1]["ace_flags"].get_value() == 0
        assert daces[1]["ace_size"].get_value() == 36
        assert daces[1]["mask"].get_value() == 2032127
        assert str(daces[1]["sid"]) == "S-1-5-21-3242954042-3778974373-1659123385-1104"

    def test_parse_acl_respect_ace_count(self):
        actual = AclPacket()
        data = (
            b"\x02"
            b"\x00"
            b"\x93\x00"
            b"\x03\x00"
            b"\x00\x00"
            b"\x00\x00\x14\x00\x02\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00"
            b"\x00\x00\x14\x00\x02\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0c\x00\x00\x00"
            b"\x00\x00\x14\x00\x02\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x05\x07\x00\x00\x00"
            b"exceeding data after ACEs after ace_count which should be ignored while parsing"
        )
        actual.unpack(data)

        assert actual["acl_revision"].get_value() == 2
        assert actual["sbz1"].get_value() == 0
        assert actual["acl_size"].get_value() == 147
        assert actual["ace_count"].get_value() == 3
        assert actual["sbz2"].get_value() == 0
        # Only 3 ACEs parsed, exceeding data after ace_count is ignored
        aces = actual["aces"].get_value()
        assert isinstance(aces, list)
        assert len(aces) == 3
