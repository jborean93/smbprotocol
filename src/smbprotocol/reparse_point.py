# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import ntpath
from collections import OrderedDict

from smbprotocol._text import to_bytes, to_text
from smbprotocol.structure import BytesField, EnumField, IntField, Structure


class ReparseTags:
    """
    [MS-FSCC] 2.1.2.1 Reparse Tags
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4

    Also includes the tags defined in winnt.h of the Windows 10 SDK.
    """

    IO_REPARSE_TAG_RESERVED_ZERO = 0x00000000
    IO_REPARSE_TAG_RESERVED_ONE = 0x00000001
    IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
    IO_REPARSE_TAG_HSM = 0xC0000004
    IO_REPARSE_TAG_DRIVER_EXTENDER = 0x80000005
    IO_REPARSE_TAG_HSM2 = 0x80000006
    IO_REPARSE_TAG_SIS = 0x80000007
    IO_REPARSE_TAG_WIM = 0x80000008
    IO_REPARSE_TAG_CSV = 0x80000009
    IO_REPARSE_TAG_DFS = 0x8000000A
    IO_REPARSE_TAG_FILTER_MANAGER = 0x8000000B
    IO_REPARSE_TAG_SYMLINK = 0xA000000C
    IO_REPARSE_TAG_IIS_CACHE = 0xA0000010
    IO_REPARSE_TAG_DFSR = 0x80000012
    IO_REPARSE_TAG_DEDUP = 0x80000013
    IO_REPARSE_TAG_NFS = 0x80000014
    IO_REPARSE_TAG_FILE_PLACEHOLDER = 0x80000015
    IO_REPARSE_TAG_WOF = 0x80000017
    IO_REPARSE_TAG_WCI = 0x80000018
    IO_REPARSE_TAG_WCI_1 = 0x90001018
    IO_REPARSE_TAG_GLOBAL_REPARSE = 0xA0000019
    IO_REPARSE_TAG_CLOUD = 0x9000001A
    IO_REPARSE_TAG_CLOUD_1 = 0x9000101A
    IO_REPARSE_TAG_CLOUD_2 = 0x9000201A
    IO_REPARSE_TAG_CLOUD_3 = 0x9000301A
    IO_REPARSE_TAG_CLOUD_4 = 0x9000401A
    IO_REPARSE_TAG_CLOUD_5 = 0x9000501A
    IO_REPARSE_TAG_CLOUD_6 = 0x9000601A
    IO_REPARSE_TAG_CLOUD_7 = 0x9000701A
    IO_REPARSE_TAG_CLOUD_8 = 0x9000801A
    IO_REPARSE_TAG_CLOUD_9 = 0x9000901A
    IO_REPARSE_TAG_CLOUD_A = 0x9000A01A
    IO_REPARSE_TAG_CLOUD_B = 0x9000B01A
    IO_REPARSE_TAG_CLOUD_C = 0x9000C01A
    IO_REPARSE_TAG_CLOUD_D = 0x9000D01A
    IO_REPARSE_TAG_CLOUD_E = 0x9000E01A
    IO_REPARSE_TAG_CLOUD_F = 0x9000F01A
    IO_REPARSE_TAG_CLOUD_MASK = 0x0000F000
    IO_REPARSE_TAG_APPEXECLINK = 0x8000001B
    IO_REPARSE_TAG_PROJFS = 0x9000001C
    IO_REPARSE_TAG_LX_SYMLINK = 0xA000001D
    IO_REPARSE_TAG_STORAGE_SYNC = 0x8000001E
    IO_REPARSE_TAG_WCI_TOMBSTONE = 0xA000001F
    IO_REPARSE_TAG_UNHANDLED = 0x80000020
    IO_REPARSE_TAG_ONEDRIVE = 0x80000021
    IO_REPARSE_TAG_PROJFS_TOMBSTONE = 0xA0000022
    IO_REPARSE_TAG_AF_UNIX = 0x80000023

    @staticmethod
    def is_reparse_tag_microsoft(tag):
        """
        Determine whether a reparse point tag corresponds to a tag owned by Microsoft.

        :param tag: The reparse point tag.
        :return: bool to indicate whether the tag is owned by Microsoft.
        """
        return tag & 0x80000000 == 0x80000000

    @staticmethod
    def is_reparse_tag_name_surrogate(tag):
        """
        Determine whether a reparse point tag is a name surrogate. A name surrogate means that the file or directory
        with this reparse tag represents another named entity in the system, such as a mounted folder or symbolic link.

        :param tag: The reparse point tag.
        :return: bool to indicate whether the tag is a name surrogate.
        """
        return tag & 0x20000000 == 0x20000000

    @staticmethod
    def is_reparse_tag_directory(tag):
        """
        Determine whether a directory with this reparse point can have children.

        :param tag: The reparse point tag.
        :return: bool to indicate whether the directory with the tag can have children.
        """
        return tag & 0x10000000 == 0x10000000


class SymbolicLinkFlags:
    """
    [MS-FSCC] 2.1.2.4 Symbolic Link Reparse Data Buffer - Flags
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/b41f1cbf-10df-4a47-98d4-1c52a833d913
    """

    SYMLINK_FLAG_ABSOLUTE = 0x00000000
    SYMLINK_FLAG_RELATIVE = 0x00000001


class ReparseDataBuffer(Structure):
    """
    [MS-FSCC] 2.1.2.2 REPARSE_DATA_BUFFER
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c3a420cb-8a72-4adf-87e8-eee95379d78f
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                (
                    "reparse_tag",
                    EnumField(
                        size=4,
                        enum_type=ReparseTags,
                        enum_strict=False,
                    ),
                ),
                (
                    "reparse_data_length",
                    IntField(
                        size=2,
                        default=lambda s: len(s["data_buffer"]),
                    ),
                ),
                ("reserved", IntField(size=2)),
                ("data_buffer", BytesField(size=lambda s: s["reparse_data_length"].get_value())),
            ]
        )
        super().__init__()


class SymbolicLinkReparseDataBuffer(Structure):
    """
    [MS-FSCC] 2.1.2.4 Symbolic Link Reparse Data Buffer
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/b41f1cbf-10df-4a47-98d4-1c52a833d913

    Removes the reparse data buffer headings so it is just the data in the data_buffer field of ReparseDataBuffer.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("substitute_name_offset", IntField(size=2)),
                ("substitute_name_length", IntField(size=2)),
                ("print_name_offset", IntField(size=2)),
                ("print_name_length", IntField(size=2)),
                (
                    "flags",
                    EnumField(
                        size=4,
                        enum_type=SymbolicLinkFlags,
                    ),
                ),
                (
                    "buffer",
                    BytesField(
                        size=lambda s: s["substitute_name_length"].get_value() + s["print_name_length"].get_value(),
                    ),
                ),
            ]
        )
        super().__init__()

    def get_substitute_name(self):
        return self._get_name("substitute")

    def get_print_name(self):
        return self._get_name("print")

    def set_name(self, substitute_name, print_name):
        b_substitute_name = to_bytes(to_text(substitute_name), encoding="utf-16-le")
        b_print_name = to_bytes(to_text(print_name), encoding="utf-16-le")

        self["substitute_name_offset"] = 0
        self["substitute_name_length"] = len(b_substitute_name)
        self["print_name_offset"] = len(b_substitute_name)
        self["print_name_length"] = len(b_print_name)
        self["buffer"] = b_substitute_name + b_print_name

    def resolve_link(self, path):
        link_target = self.get_substitute_name()

        if self["flags"].get_value() == SymbolicLinkFlags.SYMLINK_FLAG_ABSOLUTE:
            # The substitute name could use the NT Path prefix \??\UNC\server\share or \??\C:\path which we strip off.
            if link_target.startswith("\\??\\UNC\\"):
                link_target = "\\\\" + link_target[8:]
            elif link_target.startswith("\\??\\"):
                link_target = link_target[4:]
        else:
            link_target = ntpath.join(ntpath.dirname(path), link_target)

        return ntpath.abspath(link_target)

    def _get_name(self, prefix):
        offset = self[f"{prefix}_name_offset"].get_value()
        length = self[f"{prefix}_name_length"].get_value()
        b_name = self["buffer"].get_value()[offset : offset + length]
        return to_text(b_name, encoding="utf-16-le")
