# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from collections import OrderedDict

from smbprotocol.reparse_point import ReparseTags
from smbprotocol.structure import (
    BoolField,
    BytesField,
    DateTimeField,
    EnumField,
    FlagField,
    IntField,
    Structure,
    StructureField,
    TextField,
    UuidField,
)


class AlignmentRequirement:
    """
    [MS-FSCC] 2.4.3 FileAlignmentInformation - AlignmentRequirement
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/9b0b9971-85aa-4651-8438-f1c4298bcb0d
    """

    FILE_BYTE_ALIGNMENT = 0x00000000
    FILE_WORD_ALIGNMENT = 0x00000001
    FILE_LONG_ALIGNMENT = 0x00000003
    FILE_QUAD_ALIGNMENT = 0x00000007
    FILE_OCTA_ALIGNMENT = 0x0000000F
    FILE_32_BYTE_ALIGNMENT = 0x0000001F
    FILE_64_BYTE_ALIGNMENT = 0x0000003F
    FILE_128_BYTE_ALIGNMENT = 0x0000007F
    FILE_256_BYTE_ALIGNMENT = 0x000000FF
    FILE_512_BYTE_ALIGNMENT = 0x000001FF


class InfoType:
    """
    [MS-SMB2] 2.2.39 SMB2 SET_INFO Request - InfoType
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ee9614c4-be54-4a3c-98f1-769a7032a0e4

    The type of information being set.
    """

    SMB2_0_INFO_FILE = 0x01
    SMB2_0_INFO_FILESYSTEM = 0x02
    SMB2_0_INFO_SECURITY = 0x03
    SMB2_0_INFO_QUOTA = 0x04


class ModeInformation:
    """
    [MS-FSCC] 2.4.24 FileModeInformation - Mode
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/52df7798-8330-474b-ac31-9afe8075640c
    """

    FILE_WRITE_THROUGH = 0x00000002
    FILE_SEQUENTIAL_ONLY = 0x00000004
    FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008
    FILE_SYNCHRONOUS_IO_ALERT = 0x00000010
    FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
    FILE_DELETE_ON_CLOSE = 0x00001000


class FileAttributes:
    """
    [MS-FSCC]

    2.6 File Attributes
    Combination of file attributes for a file or directory
    """

    FILE_ATTRIBUTE_ARCHIVE = 0x00000020
    FILE_ATTRIBUTE_COMPRESSED = 0x00000800
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    FILE_ATTRIBUTE_ENCRYPTED = 0x00004000
    FILE_ATTRIBUTE_HIDDEN = 0x00000002
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000
    FILE_ATTRIBUTE_OFFLINE = 0x00001000
    FILE_ATTRIBUTE_READONLY = 0x00000001
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200
    FILE_ATTRIBUTE_SYSTEM = 0x00000004
    FILE_ATTRIBUTE_TEMPORARY = 0x00000100
    FILE_ATTRIBUTE_INTEGRITY_STREAM = 0x00008000
    FILE_ATTRIBUTE_NO_SCRUB_DATA = 0x00020000
    FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x00040000
    FILE_ATTRIBUTE_PINNED = 0x00080000
    FILE_ATTRIBUTE_UNPINNED = 0x00100000
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000


class FileInformationClass:
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.33 SMB2 QUERY_DIRECTORY Request FileInformationClass
    2.2.37 SMB2 QUERY_INFO Request FileInformationClass
    2.2.39 SMB2 SET_INFO Request FileInformationClass
    Describe the format the data MUST be returned in. The format structure must
    is specified in https://msdn.microsoft.com/en-us/library/cc232064.aspx
    """

    FILE_NONE = 0
    FILE_DIRECTORY_INFORMATION = 1
    FILE_FULL_DIRECTORY_INFORMATION = 2
    FILE_BOTH_DIRECTORY_INFORMATION = 3
    FILE_BASIC_INFORMATION = 4
    FILE_STANDARD_INFORMATION = 5
    FILE_INTERNAL_INFORMATION = 6
    FILE_EA_INFORMATION = 7
    FILE_ACCESS_INFORMATION = 8
    FILE_RENAME_INFORMATION = 10
    FILE_LINK_INFORMATION = 11
    FILE_NAMES_INFORMATION = 12
    FILE_DISPOSITION_INFORMATION = 13
    FILE_POSITION_INFORMATION = 14
    FILE_FULL_EA_INFORMATION = 15
    FILE_MODE_INFORMATION = 16
    FILE_ALIGNMENT_INFORMATION = 17
    FILE_ALL_INFORMATION = 18
    FILE_ALLOCATION_INFORMATION = 19
    FILE_END_OF_FILE_INFORMATION = 20
    FILE_ALTERNATE_NAME_INFORMATION = 21
    FILE_STREAM_INFORMATION = 22
    FILE_PIPE_INFORMATION = 23
    FILE_PIPE_LOCAL_INFORMATION = 24
    FILE_PIPE_REMOTE_INFORMATION = 25
    FILE_COMPRESSION_INFORMATION = 28
    FILE_QUOTE_INFORMATION = 32
    FILE_NETWORK_OPEN_INFORMATION = 34
    FILE_ATTRIBUTE_TAG_INFORMATION = 35
    FILE_ID_BOTH_DIRECTORY_INFORMATION = 37
    FILE_ID_FULL_DIRECTORY_INFORMATION = 38
    FILE_VALID_DATA_LENGTH_INFORMATION = 39
    FILE_SHORT_NAME_INFORMATION = 40
    FILE_NORMALIZED_NAME_INFORMATION = 48


class FileSystemInformationClass:
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.33 SMB2 QUERY_DIRECTORY Request FileInformationClass
    2.2.37 SMB2 QUERY_INFO Request FileInformationClass
    2.2.39 SMB2 SET_INFO Request FileInformationClass

    Describe the format the data for a file system information class MUST be
    returned in. The format structure is specified in
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/ee12042a-9352-46e3-9f67-c094b75fe6c3
    """

    FILE_FS_VOLUME_INFORMATION = 1
    FILE_FS_LABEL_INFORMATION = 2
    FILE_FS_SIZE_INFORMATION = 3
    FILE_FS_DEVICE_INFORMATION = 4
    FILE_FS_ATTRIBUTE_INFORMATION = 5
    FILE_FS_CONTROL_INFORMATION = 6
    FILE_FS_FULL_SIZE_INFORMATION = 7
    FILE_FS_OBJECT_ID_INFORMATION = 8
    FILE_FS_DRIVER_PATH_INFORMATION = 9
    FILE_FS_VOLUME_FLAGS_INFORMATION = 10
    FILE_FS_SECTOR_SIZE_INFORMATION = 11


class QueryInfoFlags:
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.37 SMB2 QUERY_INFO Request Flags
    """

    NONE = 0x00000000
    SL_RESTART_SCAN = 0x00000001
    SL_RETURN_SINGLE_ENTRY = 0x00000002
    SL_INDEX_SPECIFIED = 0x00000004


class FileNameInformation(Structure):
    """
    [MS-FSCC] 2.1.7 FILE_NAME_INFORMATION
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/20406fb1-605f-4629-ba9a-c67ee25f23d2
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                (
                    "file_name_length",
                    IntField(
                        size=4,
                        default=lambda s: len(s["file_name"]),
                    ),
                ),
                (
                    "file_name",
                    TextField(
                        encoding="utf-16-le",
                        size=lambda s: s["file_name_length"].get_value(),
                        default="",
                    ),
                ),
            ]
        )
        super().__init__()


class FileAccessInformation(Structure):
    """
    [MS-FSSC] 2.4.1 FileAccessInformation
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/01cf43d2-deb3-40d3-a39b-9e68693d7c90
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILE
    INFO_CLASS = FileInformationClass.FILE_ACCESS_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                # Technically a flag but it depends on the file type in question so keep as a raw int.
                ("access_flags", IntField(size=4)),
            ]
        )
        super().__init__()


class FileAllInformation(Structure):
    """
    [MS-FSSC] 2.4.2 FileAllInformation
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/95f3056a-ebc1-4f5d-b938-3f68a44677a6
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILE
    INFO_CLASS = FileInformationClass.FILE_ALL_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                (
                    "basic_information",
                    StructureField(
                        structure_type=FileBasicInformation,
                        default=FileBasicInformation(),
                    ),
                ),
                (
                    "standard_information",
                    StructureField(
                        structure_type=FileStandardInformation,
                        default=FileStandardInformation(),
                    ),
                ),
                (
                    "internal_information",
                    StructureField(
                        structure_type=FileInternalInformation,
                        default=FileInternalInformation(),
                    ),
                ),
                (
                    "ea_information",
                    StructureField(
                        structure_type=FileEaInformation,
                        default=FileEaInformation(),
                    ),
                ),
                (
                    "access_information",
                    StructureField(
                        structure_type=FileAccessInformation,
                        default=FileAccessInformation(),
                    ),
                ),
                (
                    "position_information",
                    StructureField(
                        structure_type=FilePositionInformation,
                        default=FilePositionInformation(),
                    ),
                ),
                (
                    "mode_information",
                    StructureField(
                        structure_type=FileModeInformation,
                        default=FileModeInformation(),
                    ),
                ),
                (
                    "alignment_information",
                    StructureField(
                        structure_type=FileAlignmentInformation,
                        default=FileAlignmentInformation(),
                    ),
                ),
                (
                    "name_information",
                    StructureField(
                        structure_type=FileNameInformation,
                        default=FileNameInformation(),
                    ),
                ),
            ]
        )
        super().__init__()


class FileAlignmentInformation(Structure):
    """
    [MS-FSCC] 2.4.3 FileAlignmentInformation
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/9b0b9971-85aa-4651-8438-f1c4298bcb0d
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILE
    INFO_CLASS = FileInformationClass.FILE_ALIGNMENT_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                (
                    "alignment_requirement",
                    EnumField(
                        size=4,
                        enum_type=AlignmentRequirement,
                    ),
                ),
            ]
        )
        super().__init__()


class FileAttributeTagInformation(Structure):
    """
    [MS-FSCC] 2.4.6 FileAttributeTagInformation
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/d295752f-ce89-4b98-8553-266d37c84f0e
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILE
    INFO_CLASS = FileInformationClass.FILE_ATTRIBUTE_TAG_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                (
                    "file_attributes",
                    FlagField(
                        size=4,
                        flag_type=FileAttributes,
                        flag_strict=False,
                    ),
                ),
                (
                    "reparse_tag",
                    EnumField(
                        size=4,
                        enum_type=ReparseTags,
                        enum_strict=False,
                    ),
                ),
            ]
        )
        super().__init__()


class FileBasicInformation(Structure):
    """
    [MS-FSCC] 2.4.7 FileBasicInformation
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/16023025-8a78-492f-8b96-c873b042ac50
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILE
    INFO_CLASS = FileInformationClass.FILE_BASIC_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("creation_time", IntField(size=8)),
                ("last_access_time", IntField(size=8)),
                ("last_write_time", IntField(size=8)),
                ("change_time", IntField(size=8)),
                (
                    "file_attributes",
                    FlagField(
                        size=4,
                        flag_type=FileAttributes,
                        flag_strict=False,
                    ),
                ),
                ("reserved", IntField(size=4)),
            ]
        )
        super().__init__()


class FileBothDirectoryInformation(Structure):
    """
    [MS-FSCC] 2.4.8 FileBothDirectoryInformation
    https://msdn.microsoft.com/en-us/library/cc232095.aspx
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILE
    INFO_CLASS = FileInformationClass.FILE_BOTH_DIRECTORY_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("next_entry_offset", IntField(size=4)),
                ("file_index", IntField(size=4)),
                ("creation_time", DateTimeField(size=8)),
                ("last_access_time", DateTimeField(size=8)),
                ("last_write_time", DateTimeField(size=8)),
                ("change_time", DateTimeField(size=8)),
                ("end_of_file", IntField(size=8)),
                ("allocation_size", IntField(size=8)),
                (
                    "file_attributes",
                    FlagField(
                        size=4,
                        flag_type=FileAttributes,
                        flag_strict=False,
                    ),
                ),
                ("file_name_length", IntField(size=4, default=lambda s: len(s["file_name"]))),
                ("ea_size", IntField(size=4)),
                ("short_name_length", IntField(size=1, default=lambda s: len(s["short_name"]))),
                ("reserved", IntField(size=1)),
                ("short_name", BytesField(size=lambda s: s["short_name_length"].get_value())),
                (
                    "short_name_padding",
                    BytesField(
                        size=lambda s: 24 - len(s["short_name"]),
                        default=lambda s: b"\x00" * (24 - len(s["short_name"])),
                    ),
                ),
                ("file_name", BytesField(size=lambda s: s["file_name_length"].get_value())),
            ]
        )
        super().__init__()


class FileDirectoryInformation(Structure):
    """
    [MS-FSCC] 2.4.10 FileDirectoryInformation
    https://msdn.microsoft.com/en-us/library/cc232097.aspx
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILE
    INFO_CLASS = FileInformationClass.FILE_DIRECTORY_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("next_entry_offset", IntField(size=4)),
                ("file_index", IntField(size=4)),
                ("creation_time", DateTimeField(size=8)),
                ("last_access_time", DateTimeField(size=8)),
                ("last_write_time", DateTimeField(size=8)),
                ("change_time", DateTimeField(size=8)),
                ("end_of_file", IntField(size=8)),
                ("allocation_size", IntField(size=8)),
                (
                    "file_attributes",
                    FlagField(
                        size=4,
                        flag_type=FileAttributes,
                        flag_strict=False,
                    ),
                ),
                ("file_name_length", IntField(size=4, default=lambda s: len(s["file_name"]))),
                ("file_name", BytesField(size=lambda s: s["file_name_length"].get_value())),
            ]
        )
        super().__init__()


class FileDispositionInformation(Structure):
    """
    [MS-FSCC] 2.4.11 FileDispositionInformation
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/12c3dd1c-14f6-4229-9d29-75fb2cb392f6
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILE
    INFO_CLASS = FileInformationClass.FILE_DISPOSITION_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("delete_pending", BoolField(size=1)),
            ]
        )
        super().__init__()


class FileEaInformation(Structure):
    """
    [MS-FSCC] 2.4.12 FileEaInformation
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/db6cf109-ead8-441a-b29e-cb2032778b0f
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILE
    INFO_CLASS = FileInformationClass.FILE_EA_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("ea_size", IntField(size=4)),
            ]
        )
        super().__init__()


class FileEndOfFileInformation(Structure):
    """
    [MS-FSCC] 2.4.13 FileEndOfFileInformation
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/75241cca-3167-472f-8058-a52d77c6bb17
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILE
    INFO_CLASS = FileInformationClass.FILE_END_OF_FILE_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("end_of_file", IntField(size=8)),
            ]
        )
        super().__init__()


class FileFullDirectoryInformation(Structure):
    """
    [MS-FSCC] 2.4.14 FileFullDirectoryInformation
    https://msdn.microsoft.com/en-us/library/cc232068.aspx
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILE
    INFO_CLASS = FileInformationClass.FILE_FULL_DIRECTORY_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("next_entry_offset", IntField(size=4)),
                ("file_index", IntField(size=4)),
                ("creation_time", DateTimeField(size=8)),
                ("last_access_time", DateTimeField(size=8)),
                ("last_write_time", DateTimeField(size=8)),
                ("change_time", DateTimeField(size=8)),
                ("end_of_file", IntField(size=8)),
                ("allocation_size", IntField(size=8)),
                (
                    "file_attributes",
                    FlagField(
                        size=4,
                        flag_type=FileAttributes,
                        flag_strict=False,
                    ),
                ),
                ("file_name_length", IntField(size=4, default=lambda s: len(s["file_name"]))),
                ("ea_size", IntField(size=4)),
                ("file_name", BytesField(size=lambda s: s["file_name_length"].get_value())),
            ]
        )
        super().__init__()


class FileFullEaInformation(Structure):
    """
    [MS-FSCC] 2.4.15 FileFullEaInformation
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/0eb94f48-6aac-41df-a878-79f4dcfd8989
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILE
    INFO_CLASS = FileInformationClass.FILE_FULL_EA_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("next_entry_offset", IntField(size=4)),
                ("flags", IntField(size=1)),
                (
                    "ea_name_length",
                    IntField(
                        size=1,
                        default=lambda s: len(s["ea_name"]),
                    ),
                ),
                (
                    "ea_value_length",
                    IntField(
                        size=2,
                        default=lambda s: len(s["ea_value"]),
                    ),
                ),
                (
                    "ea_name",
                    BytesField(
                        size=lambda s: s["ea_name_length"].get_value(),
                    ),
                ),
                # Not part of the spec byte EaName must be null padded so we add this field automatically.
                ("ea_name_padding", IntField(size=1)),
                (
                    "ea_value",
                    BytesField(
                        size=lambda s: s["ea_value_length"].get_value(),
                    ),
                ),
            ]
        )
        super().__init__()


class FileGetEaInformation(Structure):
    """
    [MS-FSCC] 2.4.15.1 FILE_GET_EA_INFORMATION
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/79dc1ea1-158c-4b24-b0e1-8c16c7e2af6b
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("next_entry_offset", IntField(size=4)),
                (
                    "ea_name_length",
                    IntField(
                        size=1,
                        default=lambda s: len(s["ea_name"]),
                    ),
                ),
                (
                    "ea_name",
                    BytesField(
                        size=lambda s: s["ea_name_length"].get_value(),
                    ),
                ),
                ("padding", IntField(size=1)),
            ]
        )
        super().__init__()


class FileIdBothDirectoryInformation(Structure):
    """
    [MS-FSCC] 2.4.17 FileIdBothDirectoryInformation
    https://msdn.microsoft.com/en-us/library/cc232070.aspx
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILE
    INFO_CLASS = FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("next_entry_offset", IntField(size=4)),
                ("file_index", IntField(size=4)),
                ("creation_time", DateTimeField(size=8)),
                ("last_access_time", DateTimeField(size=8)),
                ("last_write_time", DateTimeField(size=8)),
                ("change_time", DateTimeField(size=8)),
                ("end_of_file", IntField(size=8)),
                ("allocation_size", IntField(size=8)),
                (
                    "file_attributes",
                    FlagField(
                        size=4,
                        flag_type=FileAttributes,
                        flag_strict=False,
                    ),
                ),
                ("file_name_length", IntField(size=4, default=lambda s: len(s["file_name"]))),
                ("ea_size", IntField(size=4)),
                ("short_name_length", IntField(size=1, default=lambda s: len(s["short_name"]))),
                ("reserved1", IntField(size=1)),
                ("short_name", BytesField(size=lambda s: s["short_name_length"].get_value())),
                (
                    "short_name_padding",
                    BytesField(
                        size=lambda s: 24 - len(s["short_name"]),
                        default=lambda s: b"\x00" * (24 - len(s["short_name"])),
                    ),
                ),
                ("reserved2", IntField(size=2)),
                ("file_id", IntField(size=8)),
                ("file_name", BytesField(size=lambda s: s["file_name_length"].get_value())),
            ]
        )
        super().__init__()


class FileIdFullDirectoryInformation(Structure):
    """
    [MS-FSCC] 2.4.18 FileIdFullDirectoryInformation
    https://msdn.microsoft.com/en-us/library/cc232071.aspx
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILE
    INFO_CLASS = FileInformationClass.FILE_ID_FULL_DIRECTORY_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("next_entry_offset", IntField(size=4)),
                ("file_index", IntField(size=4)),
                ("creation_time", DateTimeField(size=8)),
                ("last_access_time", DateTimeField(size=8)),
                ("last_write_time", DateTimeField(size=8)),
                ("change_time", DateTimeField(size=8)),
                ("end_of_file", IntField(size=8)),
                ("allocation_size", IntField(size=8)),
                (
                    "file_attributes",
                    FlagField(
                        size=4,
                        flag_type=FileAttributes,
                        flag_strict=False,
                    ),
                ),
                ("file_name_length", IntField(size=4, default=lambda s: len(s["file_name"]))),
                ("ea_size", IntField(size=4)),
                ("reserved", IntField(size=4)),
                ("file_id", IntField(size=8)),
                ("file_name", BytesField(size=lambda s: s["file_name_length"].get_value())),
            ]
        )
        super().__init__()


class FileInternalInformation(Structure):
    """
    [MS-FSSC] 2.4.20 FileInternalInformation
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/7d796611-2fa5-41ac-8178-b6fea3a017b3
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILE
    INFO_CLASS = FileInformationClass.FILE_INTERNAL_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("index_number", IntField(size=8)),
            ]
        )
        super().__init__()


class FileLinkInformation(Structure):
    """
    [MS-FSSC] 2.4.21 FileLinkInformation
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/69643dd3-b518-465d-bb0e-e2e9c5b7875e
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILE
    INFO_CLASS = FileInformationClass.FILE_LINK_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("replace_if_exists", BoolField()),
                (
                    "reserved",
                    BytesField(
                        size=7,
                        default=b"\x00" * 7,
                    ),
                ),
                ("root_directory", IntField(size=8)),
                (
                    "file_name_length",
                    IntField(
                        size=4,
                        default=lambda s: len(s["file_name"]),
                    ),
                ),
                (
                    "file_name",
                    TextField(
                        size=lambda s: s["file_name_length"].get_value(),
                        encoding="utf-16-le",
                    ),
                ),
            ]
        )
        super().__init__()


class FileModeInformation(Structure):
    """
    [MS-FSCC] 2.4.24 FileModeInformation
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/52df7798-8330-474b-ac31-9afe8075640c
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILE
    INFO_CLASS = FileInformationClass.FILE_MODE_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                (
                    "mode",
                    FlagField(
                        size=4,
                        flag_type=ModeInformation,
                    ),
                ),
            ]
        )
        super().__init__()


class FileNamesInformation(Structure):
    """
    [MS-FSCC] 2.4.26 FileNamesInformation
    https://msdn.microsoft.com/en-us/library/cc232077.aspx
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILE
    INFO_CLASS = FileInformationClass.FILE_NAMES_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("next_entry_offset", IntField(size=4)),
                ("file_index", IntField(size=4)),
                ("file_name_length", IntField(size=4, default=lambda s: len(s["file_name"]))),
                ("file_name", BytesField(size=lambda s: s["file_name_length"].get_value())),
            ]
        )
        super().__init__()


class FilePositionInformation(Structure):
    """
    [MS-FSCC] 2.4.32 FilePositionInformation
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/e3ce4a39-327e-495c-99b6-6b61606b6f16
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILE
    INFO_CLASS = FileInformationClass.FILE_POSITION_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                (
                    "current_byte_offset",
                    IntField(
                        size=8,
                        unsigned=False,
                    ),
                ),
            ]
        )
        super().__init__()


class FileRenameInformation(Structure):
    """
    [MS-FSCC] 2.4.34.2 FileRenameInformation For SMB2
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/52aa0b70-8094-4971-862d-79793f41e6a8
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILE
    INFO_CLASS = FileInformationClass.FILE_RENAME_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("replace_if_exists", BoolField()),
                (
                    "reserved",
                    BytesField(
                        size=7,
                        default=b"\x00" * 7,
                    ),
                ),
                ("root_directory", IntField(size=8)),
                (
                    "file_name_length",
                    IntField(
                        size=4,
                        default=lambda s: len(s["file_name"]),
                    ),
                ),
                (
                    "file_name",
                    TextField(
                        size=lambda s: s["file_name_length"].get_value(),
                    ),
                ),
            ]
        )
        super().__init__()


class FileStandardInformation(Structure):
    """
    [MS-FSCC] 2.4.38 FileStandardInformation
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/5afa7f66-619c-48f3-955f-68c4ece704ae
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILE
    INFO_CLASS = FileInformationClass.FILE_STANDARD_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                (
                    "allocation_size",
                    IntField(
                        size=8,
                        unsigned=False,
                    ),
                ),
                (
                    "end_of_file",
                    IntField(
                        size=8,
                        unsigned=False,
                    ),
                ),
                ("number_of_links", IntField(size=4)),
                ("delete_pending", BoolField()),
                ("directory", BoolField()),
                ("reserved", IntField(size=2)),
            ]
        )
        super().__init__()


class FileStreamInformation(Structure):
    """
    [MS-FSCC] 2.4.40 FileStreamInformation
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/f8762be6-3ab9-411e-a7d6-5cc68f70c78d
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILE
    INFO_CLASS = FileInformationClass.FILE_STREAM_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("next_entry_offset", IntField(size=4)),
                (
                    "stream_name_length",
                    IntField(
                        size=4,
                        default=lambda s: len(s["stream_name"]),
                    ),
                ),
                (
                    "stream_size",
                    IntField(
                        size=8,
                        unsigned=False,
                    ),
                ),
                (
                    "stream_allocation_size",
                    IntField(
                        size=8,
                        unsigned=False,
                    ),
                ),
                (
                    "stream_name",
                    TextField(
                        encoding="utf-16-le",
                        size=lambda s: s["stream_name_length"].get_value(),
                    ),
                ),
            ]
        )
        super().__init__()


class FileFsFullSizeInformation(Structure):
    """
    [MS-FSCC] 2.5.4 FileFsFullSizeInformation
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/63768db7-9012-4209-8cca-00781e7322f5
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILESYSTEM
    INFO_CLASS = FileSystemInformationClass.FILE_FS_FULL_SIZE_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("total_allocation_units", IntField(size=8, unsigned=False)),
                ("caller_available_units", IntField(size=8, unsigned=False)),
                ("actual_available_units", IntField(size=8, unsigned=False)),
                ("sectors_per_unit", IntField(size=4)),
                ("bytes_per_sector", IntField(size=4)),
            ]
        )
        super().__init__()


class FileFsObjectIdInformation(Structure):
    """
    [MS-FSCC] 2.5.6 FileFsObjectIdInformation
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/dbf535ae-315a-4508-8bc5-84276ea106d4
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILESYSTEM
    INFO_CLASS = FileSystemInformationClass.FILE_FS_OBJECT_ID_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("object_id", UuidField()),
                (
                    "extended_info",
                    BytesField(
                        size=48,
                        default=b"\x00" * 48,
                    ),
                ),
            ]
        )
        super().__init__()


class FileFsVolumeInformation(Structure):
    """
    [MS-FSCC] 2.5.9 FileFsVolumeInformation
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/bf691378-c34e-4a13-976e-404ea1a87738
    """

    INFO_TYPE = InfoType.SMB2_0_INFO_FILESYSTEM
    INFO_CLASS = FileSystemInformationClass.FILE_FS_VOLUME_INFORMATION

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("volume_creation_time", DateTimeField()),
                ("volume_serial_number", IntField(size=4)),
                (
                    "volume_label_length",
                    IntField(
                        size=4,
                        default=lambda s: len(s["volume_label"]),
                    ),
                ),
                ("supports_objects", BoolField(default=False)),
                ("reserved", IntField(size=1)),
                (
                    "volume_label",
                    TextField(
                        size=lambda s: s["volume_label_length"].get_value(),
                        encoding="utf-16-le",
                    ),
                ),
            ]
        )
        super().__init__()
