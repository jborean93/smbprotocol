import smbprotocol.open
from smbprotocol.structure import BytesField, DateTimeField, \
    FlagField, IntField, Structure

try:
    from collections import OrderedDict
except ImportError:  # pragma: no cover
    from ordereddict import OrderedDict


class FileBothDirectoryInformation(Structure):
    """
    [MS-FSCC] 2.4.8 FileBothDirectoryInformation
    https://msdn.microsoft.com/en-us/library/cc232095.aspx
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('next_entry_offset', IntField(size=4)),
            ('file_index', IntField(size=4)),
            ('creation_time', DateTimeField(size=8)),
            ('last_access_time', DateTimeField(size=8)),
            ('last_write_time', DateTimeField(size=8)),
            ('change_time', DateTimeField(size=8)),
            ('end_of_file', IntField(size=8)),
            ('allocation_size', IntField(size=8)),
            ('file_attributes', FlagField(
                size=4,
                flag_type=smbprotocol.open.FileAttributes
            )),
            ('file_name_length', IntField(
                size=4,
                default=lambda s: len(s['file_name'])
            )),
            ('ea_size', IntField(size=4)),
            ('short_name_length', IntField(
                size=1,
                default=lambda s: len(s['short_name'])
            )),
            ('reserved', IntField(size=1)),
            ('short_name', BytesField(
                size=lambda s: s['short_name_length'].get_value()
            )),
            ('short_name_padding', BytesField(
                size=lambda s: 24 - len(s['short_name']),
                default=lambda s: b"\x00" * (24 - len(s['short_name']))
            )),
            ('file_name', BytesField(
                size=lambda s: s['file_name_length'].get_value()
            ))
        ])
        super(FileBothDirectoryInformation, self).__init__()


class FileDirectoryInformation(Structure):
    """
    [MS-FSCC] 2.4.10 FileDirectoryInformation
    https://msdn.microsoft.com/en-us/library/cc232097.aspx
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('next_entry_offset', IntField(size=4)),
            ('file_index', IntField(size=4)),
            ('creation_time', DateTimeField(size=8)),
            ('last_access_time', DateTimeField(size=8)),
            ('last_write_time', DateTimeField(size=8)),
            ('change_time', DateTimeField(size=8)),
            ('end_of_file', IntField(size=8)),
            ('allocation_size', IntField(size=8)),
            ('file_attributes', FlagField(
                size=4,
                flag_type=smbprotocol.open.FileAttributes
            )),
            ('file_name_length', IntField(
                size=4,
                default=lambda s: len(s['file_name'])
            )),
            ('file_name', BytesField(
                size=lambda s: s['file_name_length'].get_value()
            ))
        ])
        super(FileDirectoryInformation, self).__init__()


class FileFullDirectoryInformation(Structure):
    """
    [MS-FSCC] 2.4.14 FileFullDirectoryInformation
    https://msdn.microsoft.com/en-us/library/cc232068.aspx
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('next_entry_offset', IntField(size=4)),
            ('file_index', IntField(size=4)),
            ('creation_time', DateTimeField(size=8)),
            ('last_access_time', DateTimeField(size=8)),
            ('last_write_time', DateTimeField(size=8)),
            ('change_time', DateTimeField(size=8)),
            ('end_of_file', IntField(size=8)),
            ('allocation_size', IntField(size=8)),
            ('file_attributes', FlagField(
                size=4,
                flag_type=smbprotocol.open.FileAttributes
            )),
            ('file_name_length', IntField(
                size=4,
                default=lambda s: len(s['file_name'])
            )),
            ('ea_size', IntField(size=4)),
            ('file_name', BytesField(
                size=lambda s: s['file_name_length'].get_value()
            ))
        ])
        super(FileFullDirectoryInformation, self).__init__()


class FileIdBothDirectoryInformation(Structure):
    """
    [MS-FSCC] 2.4.17 FileIdBothDirectoryInformation
    https://msdn.microsoft.com/en-us/library/cc232070.aspx
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('next_entry_offset', IntField(size=4)),
            ('file_index', IntField(size=4)),
            ('creation_time', DateTimeField(size=8)),
            ('last_access_time', DateTimeField(size=8)),
            ('last_write_time', DateTimeField(size=8)),
            ('change_time', DateTimeField(size=8)),
            ('end_of_file', IntField(size=8)),
            ('allocation_size', IntField(size=8)),
            ('file_attributes', FlagField(
                size=4,
                flag_type=smbprotocol.open.FileAttributes
            )),
            ('file_name_length', IntField(
                size=4,
                default=lambda s: len(s['file_name'])
            )),
            ('ea_size', IntField(size=4)),
            ('short_name_length', IntField(
                size=1,
                default=lambda s: len(s['short_name'])
            )),
            ('reserved1', IntField(size=1)),
            ('short_name', BytesField(
                size=lambda s: s['short_name_length'].get_value()
            )),
            ('short_name_padding', BytesField(
                size=lambda s: 24 - len(s['short_name']),
                default=lambda s: b"\x00" * (24 - len(s['short_name']))
            )),
            ('reserved2', IntField(size=2)),
            ('file_id', IntField(size=8)),
            ('file_name', BytesField(
                size=lambda s: s['file_name_length'].get_value()
            ))
        ])
        super(FileIdBothDirectoryInformation, self).__init__()


class FileIdFullDirectoryInformation(Structure):
    """
    [MS-FSCC] 2.4.18 FileIdFullDirectoryInformation
    https://msdn.microsoft.com/en-us/library/cc232071.aspx
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('next_entry_offset', IntField(size=4)),
            ('file_index', IntField(size=4)),
            ('creation_time', DateTimeField(size=8)),
            ('last_access_time', DateTimeField(size=8)),
            ('last_write_time', DateTimeField(size=8)),
            ('change_time', DateTimeField(size=8)),
            ('end_of_file', IntField(size=8)),
            ('allocation_size', IntField(size=8)),
            ('file_attributes', FlagField(
                size=4,
                flag_type=smbprotocol.open.FileAttributes
            )),
            ('file_name_length', IntField(
                size=4,
                default=lambda s: len(s['file_name'])
            )),
            ('ea_size', IntField(size=4)),
            ('reserved', IntField(size=4)),
            ('file_id', IntField(size=8)),
            ('file_name', BytesField(
                size=lambda s: s['file_name_length'].get_value()
            ))
        ])
        super(FileIdFullDirectoryInformation, self).__init__()


class FileNamesInformation(Structure):
    """
    [MS-FSCC] 2.4.26 FileNamesInformation
    https://msdn.microsoft.com/en-us/library/cc232077.aspx
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('next_entry_offset', IntField(size=4)),
            ('file_index', IntField(size=4)),
            ('file_name_length', IntField(
                size=4,
                default=lambda s: len(s['file_name'])
            )),
            ('file_name', BytesField(
                size=lambda s: s['file_name_length'].get_value()
            ))

        ])
        super(FileNamesInformation, self).__init__()
