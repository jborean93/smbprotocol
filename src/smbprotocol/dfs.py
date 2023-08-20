# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import time
from collections import OrderedDict, namedtuple
from typing import Iterator

from smbprotocol.structure import (
    BytesField,
    EnumField,
    FlagField,
    IntField,
    ListField,
    Structure,
    TextField,
)

DFSTarget = namedtuple("DFSTarget", ["target_path", "set_boundary"])
"""A TargetEntry element in the TargetList ReferralCache.

Contains the DFS target details for a referral request. This object is defined in [MS-DFSC] under
`ReferralCache TargetList`_.

Attributes:
    target_path (str): The NetworkPath value in the referral entry.
    set_boundary (bool): Whether the TARGET_SET_BOUNDARY flag was set in the referral entry.

.. _ReferralCache TargetList:
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsc/0f9ef683-b497-47d0-8c2c-e56e34fde2e3
"""


class DomainEntry:
    """A DomainCache entry.

    A processed domain and DC referral request.

    Args:
        referral: The DFSReferralResponse entry for a domain referral request to cache.

    Attributes:
        domain_list (List[str]): A list of known domain controller hostnames for the domain.
    """

    def __init__(self, referral: DFSReferralEntryV3):
        self.domain_list = []
        self._referral = referral
        self._start_time: float = time.time()
        self._domain_hint_idx: int | None = None

    @property
    def domain_name(self) -> str:
        """The domain DFS path."""
        return self._referral.dfs_path

    @property
    def dc_hint(self) -> str:
        """The last known good domain hostname in domain_list."""
        return self.domain_list[self._domain_hint_idx]

    @dc_hint.setter
    def dc_hint(self, value: str) -> None:
        for idx, target in enumerate(self.domain_list):
            if target == value:
                self._domain_hint_idx = idx
                break

        else:
            raise ValueError("The specific domain hint does not exist in this domain cache entry")

    @property
    def is_expired(self) -> bool:
        """Whether the hint has expired or not."""
        return ((time.time() - self._start_time) - self._referral["time_to_live"].get_value()) >= 0

    @property
    def is_valid(self) -> bool:
        """Whether the domain entry has had a DC referral response or not."""
        return self._domain_hint_idx is not None and not self.is_expired

    def process_dc_referral(self, referral: DFSReferralResponse) -> None:
        if self._domain_hint_idx is None:
            self._domain_hint_idx = 0

        for dc_entry in referral["referral_entries"].get_value():
            for dc_hostname in dc_entry.network_address:
                if dc_hostname not in self.domain_list:
                    self.domain_list.append(dc_hostname)


class ReferralEntry:
    """A ReferralCache entry.

    A parsed referral response that is cached by the client for future connection requests.

    Args:
        referral: The DFSReferralResponse to cache.
    """

    def __init__(self, referral: DFSReferralResponse):
        referrals = referral["referral_entries"].get_value()
        self._referral_header_flags = referral["referral_header_flags"]
        self._referrals: list[DFSReferralEntryV1 | DFSReferralEntryV2 | DFSReferralEntryV3] = referrals
        self._start_time: float = time.time()
        self._target_hint_idx: int = 0

    @property
    def dfs_path(self) -> str:
        return self._referrals[self._target_hint_idx].dfs_path

    @property
    def is_root(self) -> bool:
        return self._referrals[self._target_hint_idx]["server_type"].has_flag(DFSServerTypes.ROOT_TARGETS)

    @property
    def is_link(self) -> bool:
        return not self.is_root

    # @property
    # def is_interlink(self) -> bool:
    #     return False

    @property
    def is_expired(self) -> bool:
        referral = self._referrals[self._target_hint_idx]
        return ((time.time() - self._start_time) - referral["time_to_live"].get_value()) >= 0

    @property
    def target_failback(self) -> bool:
        return self._referral_header_flags.has_flag(DFSReferralHeaderFlags.TARGET_FAIL_BACK)

    @property
    def target_hint(self) -> DFSTarget:
        return self.target_list[self._target_hint_idx]

    @target_hint.setter
    def target_hint(self, value: DFSTarget) -> None:
        for idx, target in enumerate(self.target_list):
            if target == value:
                self._target_hint_idx = idx
                break
        else:
            raise ValueError("The specific target hint does not exist in this referral entry")

    @property
    def target_list(self) -> list[DFSTarget]:
        return [
            DFSTarget(
                target_path=e.network_address,
                set_boundary=e["referral_entry_flags"].has_flag(DFSReferralEntryFlags.TARGET_SET_BOUNDARY),
            )
            for e in self._referrals
        ]

    def __iter__(self) -> Iterator[DFSTarget]:
        """Iterates through the target_list with a priority being the hinted value."""
        yield self.target_list[self._target_hint_idx]

        for idx, target in enumerate(self.target_list):
            if idx == self._target_hint_idx:
                continue

            yield target


class DFSReferralRequestFlags:
    """
    [MS-DFSC] 2.2.3 REQ_GET_DFS_REFERRAL_EX

    RequestFlags
    """

    SITE_NAME = 0x00000001


class DFSReferralHeaderFlags:
    """
    [MS-DFSC] 2.2.4 RESP_GET_DFS_REFERRAL

    ReferralHeaderFlags
    """

    REFERRAL_SERVERS = 0x00000001
    STORAGE_SERVERS = 0x00000002
    TARGET_FAIL_BACK = 0x00000004


class DFSServerTypes:
    """
    [MS-DFSC] 2.2.5.1 DFS_REFERRAL_V1

    ServerType
    """

    NON_ROOT_TARGETS = 0x0000
    ROOT_TARGETS = 0x0001


class DFSReferralEntryFlags:
    """
    [MS-DFSC] 2.2.5.3 DFS_REFERRAL_V3 & 2.2.5.4 DFS_REFERRAL_V4

    ReferralEntryFlags
    """

    NAME_LIST_REFERRAL = 0x0002
    TARGET_SET_BOUNDARY = 0x0004


class DFSReferralRequest(Structure):
    """
    [MS-DFSC] 2.2.2 REQ_GET_DFS_REFERRAL

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsc/663c9b38-41b8-4faa-b6f6-a4576b4cea62
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("max_referral_level", IntField(size=2, default=4)),
                ("request_file_name", TextField(null_terminated=True)),
            ]
        )
        super().__init__()


class DFSReferralRequestEx(Structure):
    """
    [MS-DFSC] 2.2.3 REQ_GET_DFS_REFERRAL_EX

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsc/575ad372-46a7-4ed6-80e5-f87768fad9a0
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("max_referral_level", IntField(size=2, default=4)),
                ("request_flags", FlagField(size=2, flag_type=DFSReferralRequestFlags)),
                (
                    "request_data_length",
                    IntField(
                        size=4,
                        default=lambda s: 4
                        + s["request_file_name_length"].get_value()
                        + s["site_name_length"].get_value(),
                    ),
                ),
                (
                    "request_file_name_length",
                    IntField(
                        size=2,
                        default=lambda s: len(s["request_file_name"]),
                    ),
                ),
                (
                    "request_file_name",
                    TextField(
                        null_terminated=True,
                        size=lambda s: s["request_file_name_length"].get_value(),
                    ),
                ),
                (
                    "site_name_length",
                    IntField(
                        size=2,
                        default=lambda s: len(s["site_name"]),
                    ),
                ),
                (
                    "site_name",
                    TextField(
                        null_terminated=True,
                        size=lambda s: s["site_name_length"].get_value(),
                    ),
                ),
            ]
        )
        super().__init__()


class DFSReferralResponse(Structure):
    """
    [MS-DFSC] 2.2.4 RESP_GET_DFS_REFERRAL

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsc/bd1a7a9d-dfee-4dc6-ba37-bfeb329a7bfa
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("path_consumed", IntField(size=2)),
                ("number_of_referrals", IntField(size=2)),
                ("referral_header_flags", FlagField(size=4, flag_type=DFSReferralHeaderFlags)),
                (
                    "referral_entries",
                    ListField(
                        list_count=lambda s: s["number_of_referrals"].get_value(),
                        unpack_func=lambda s, b: self._create_dfs_referral_entry(b),
                    ),
                ),
                ("string_buffer", BytesField()),
            ]
        )
        super().__init__()

    def _create_dfs_referral_entry(self, data):
        results = []
        for _ in range(self.fields["number_of_referrals"].get_value()):
            b_version = data[:1]
            if b_version == b"\x01":
                referral_entry = DFSReferralEntryV1()

            elif b_version == b"\x02":
                referral_entry = DFSReferralEntryV2()

            else:
                referral_entry = DFSReferralEntryV3()

            data = referral_entry.unpack(data)
            results.append(referral_entry)

        # Now process the string_buffer values. Do it in reverse order as the offset value needs to be calculated based
        # on the entry size(s) that come after that entry.
        entry_offset = 0
        for referral_entry in reversed(results):
            entry_offset += referral_entry["size"].get_value()
            referral_entry.process_string_buffer(data, entry_offset)

        return results


class DFSReferralEntryV1(Structure):
    """
    [MS-DFSC] 2.2.5.1 DFS_REFERRAL_V1

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsc/2f7570f9-cafe-442b-ae9e-3ff119cae7d8
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("version_number", IntField(size=2, default=1)),
                ("size", IntField(size=2)),
                ("server_type", EnumField(size=2, enum_type=DFSServerTypes)),
                ("referral_entry_flags", FlagField(size=2, flag_type=DFSReferralEntryFlags)),
                ("share_name", TextField(null_terminated=True)),
            ]
        )
        super().__init__()

    @property
    def network_address(self):
        return self["share_name"].get_value()

    def process_string_buffer(self, buffer, entry_offset):
        # The V1 entry does not use a string buffer so this is a no-op.
        pass


class DFSReferralEntryV2(Structure):
    """
    [MS-DFSC] 2.2.5.2 DFS_REFERRAL_V2

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsc/3b6ed482-0ca4-4af1-9fd0-254d137c7af4
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("version_number", IntField(size=2, default=2)),
                ("size", IntField(size=2)),
                ("server_type", FlagField(size=2, flag_type=DFSServerTypes)),
                ("referral_entry_flags", FlagField(size=2, flag_type=DFSReferralEntryFlags)),
                ("proximity", IntField(size=4)),
                ("time_to_live", IntField(size=4)),
                ("dfs_path_offset", IntField(size=2)),
                ("dfs_alternate_path_offset", IntField(size=2)),
                ("network_address_offset", IntField(size=2)),
            ]
        )
        self.dfs_path = None
        self.dfs_alternate_path = None
        self.network_address = None
        super().__init__()

    def process_string_buffer(self, buffer, entry_offset):
        buffer_fields = ["dfs_path", "dfs_alternate_path", "network_address"]

        for field_name in buffer_fields:
            field_offset = self[f"{field_name}_offset"].get_value()
            if field_offset == 0:
                continue

            field = TextField(null_terminated=True, encoding="utf-16-le")
            field.unpack(buffer[field_offset - entry_offset :])
            setattr(self, field_name, field.get_value())


class DFSReferralEntryV3(Structure):
    """
    [MS-DFSC] 2.2.5.3 DFS_REFERRAL_V3

    This is also the same as V4 just with the addition of more referral_entry_flags and version_number being 4.

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsc/50a739cf-8211-4b17-9990-63696d37028d
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("version_number", IntField(size=2, default=3)),
                ("size", IntField(size=2)),
                ("server_type", FlagField(size=2, flag_type=DFSServerTypes, flag_strict=False)),
                ("referral_entry_flags", FlagField(size=2, flag_type=DFSReferralEntryFlags, flag_strict=False)),
                ("time_to_live", IntField(size=4)),
                # The follow fields depend on the ReferralEntryFlags, the actual field names are when the entry is not a
                # NameListReferral.
                ("dfs_path_offset", IntField(size=2)),  # SpecialNameOffset
                ("dfs_alternate_path_offset", IntField(size=2)),  # NumberOfExpandedNames
                ("network_address_offset", IntField(size=2)),  # ExpandedNameOffset
                ("service_site_guid", BytesField(size=lambda s: s["size"].get_value() - 18)),  # Padding
            ]
        )
        self.dfs_path = None
        self.dfs_alternate_path = None
        self.network_address = None
        super().__init__()

    def process_string_buffer(self, buffer, entry_offset):
        is_name_list = self["referral_entry_flags"].has_flag(DFSReferralEntryFlags.NAME_LIST_REFERRAL)
        buffer_fields = ["dfs_path", "network_address"]
        if not is_name_list:
            buffer_fields.insert(1, "dfs_alternate_path")

        for field_name in buffer_fields:
            field_offset = self[f"{field_name}_offset"].get_value()
            if field_offset == 0:
                continue

            string_offset = field_offset - entry_offset
            if is_name_list and field_name == "network_address":
                value = []
                for _ in range(self["dfs_alternate_path_offset"].get_value()):
                    field = TextField(null_terminated=True, encoding="utf-16-le")
                    field.unpack(buffer[string_offset:])
                    value.append(field.get_value())
                    string_offset += len(field)

            else:
                field = TextField(null_terminated=True, encoding="utf-16-le")
                field.unpack(buffer[string_offset:])
                value = field.get_value()

            setattr(self, field_name, value)
