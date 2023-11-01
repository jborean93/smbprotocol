# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import re

import pytest

from smbprotocol import Dialects
from smbprotocol._text import to_bytes
from smbprotocol.connection import SMB2HeaderResponse
from smbprotocol.exceptions import (
    ErrorContextId,
    IpAddrType,
    NetworkNameDelegated,
    SMB2ErrorContextResponse,
    SMB2ErrorResponse,
    SMB2MoveDstIpAddrStructure,
    SMB2ShareRedirectErrorContext,
    SMB2SymbolicLinkErrorResponse,
    SMBAuthenticationError,
    SMBException,
    SMBLinkRedirectionError,
    SMBOSError,
    SMBResponseException,
    SMBUnsupportedFeature,
    SymbolicLinkErrorFlags,
)
from smbprotocol.header import NtStatus


class TestSMBException:
    def test_exception(self):
        with pytest.raises(SMBException) as exc:
            raise SMBException("smb error")
        assert str(exc.value) == "smb error"


class TestSMBAuthenticationError:
    def test_exception(self):
        with pytest.raises(SMBAuthenticationError) as exc:
            raise SMBAuthenticationError("auth error")
        assert str(exc.value) == "auth error"

    def test_caught_with_smbexception(self):
        with pytest.raises(SMBException) as exc:
            raise SMBAuthenticationError("auth error")
        assert str(exc.value) == "auth error"


class TestSMBOSError:
    def test_error(self):
        with pytest.raises(SMBOSError) as err:
            raise SMBOSError(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND, "filéname")
        assert str(err.value) == "[Error 2] [NtStatus 0xc0000034] No such file or directory: 'filéname'"

    def test_error_with_filename2(self):
        with pytest.raises(SMBOSError) as err:
            raise SMBOSError(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND, "filéname", "filéname2")
        assert str(err.value) == "[Error 2] [NtStatus 0xc0000034] No such file or directory: 'filéname' -> 'filéname2'"

    def test_caught_with_smbexception(self):
        with pytest.raises(SMBException) as err:
            raise SMBOSError(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND, "filéname")
        assert str(err.value) == "[Error 2] [NtStatus 0xc0000034] No such file or directory: 'filéname'"

    def test_caught_with_oserror(self):
        with pytest.raises(OSError) as err:
            raise SMBOSError(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND, "filéname")
        assert str(err.value) == "[Error 2] [NtStatus 0xc0000034] No such file or directory: 'filéname'"

    def test_error_with_unknown_error(self):
        with pytest.raises(SMBOSError) as err:
            raise SMBOSError(1, "filéname")
        assert (
            str(err.value) == "[Error 0] [NtStatus 0x00000001] Unknown NtStatus error returned 'STATUS_UNKNOWN': "
            "'filéname'"
        )

    def test_error_with_override(self):
        with pytest.raises(SMBOSError) as err:
            raise SMBOSError(NtStatus.STATUS_PRIVILEGE_NOT_HELD, "filéname")
        assert str(err.value) == "[Error 13] [NtStatus 0xc0000061] Required privilege not held: 'filéname'"


class TestSMBUnsupportedFeature:
    def test_exception_needs_newer(self):
        with pytest.raises(SMBUnsupportedFeature) as exc:
            raise SMBUnsupportedFeature(Dialects.SMB_3_0_0, Dialects.SMB_3_1_1, "feature", True)
        assert (
            str(exc.value) == "feature is not available on the "
            "negotiated dialect (768) SMB_3_0_0, "
            "requires dialect (785) SMB_3_1_1 or newer"
        )

    def test_exception_needs_older(self):
        with pytest.raises(SMBUnsupportedFeature) as exc:
            raise SMBUnsupportedFeature(Dialects.SMB_3_0_0, Dialects.SMB_3_1_1, "feature", False)
        assert (
            str(exc.value) == "feature is not available on the "
            "negotiated dialect (768) SMB_3_0_0, "
            "requires dialect (785) SMB_3_1_1 or older"
        )

    def test_exception_no_suffix(self):
        with pytest.raises(SMBUnsupportedFeature) as exc:
            raise SMBUnsupportedFeature(Dialects.SMB_3_0_0, Dialects.SMB_3_1_1, "feature")
        assert (
            str(exc.value) == "feature is not available on the "
            "negotiated dialect (768) SMB_3_0_0, "
            "requires dialect (785) SMB_3_1_1"
        )


class TestSMBResponseException:
    def test_throw_default_exception(self):
        error_resp = SMB2ErrorResponse()
        header = self._get_header(error_resp)
        try:
            raise SMBResponseException(header)
        except SMBResponseException as exc:
            assert exc.error_details == []
            exp_resp = (
                "Received unexpected status from the server: An invalid parameter was passed to a service or "
                "function. (3221225485) STATUS_INVALID_PARAMETER: 0xc000000d"
            )
            assert exc.message == exp_resp
            assert str(exc) == exp_resp
            assert exc.status == NtStatus.STATUS_INVALID_PARAMETER

    def test_throw_low_disk(self):
        error_resp = SMB2ErrorResponse()
        header = self._get_header(error_resp, NtStatus.STATUS_DISK_FULL)
        try:
            raise SMBResponseException(header)
        except SMBResponseException as exc:
            assert exc.error_details == []
            exp_resp = (
                "Received unexpected status from the server: There is not enough space on the disk. "
                "(3221225599) STATUS_DISK_FULL: 0xc000007f"
            )
            assert exc.message == exp_resp
            assert str(exc) == exp_resp
            assert exc.status == NtStatus.STATUS_DISK_FULL

    def test_throw_exception_without_header(self):
        actual = NetworkNameDelegated()
        assert isinstance(actual, NetworkNameDelegated)
        assert actual.status == NetworkNameDelegated._STATUS_CODE
        assert (
            str(actual) == "Received unexpected status from the server: The network name was deleted. "
            "(3221225673) STATUS_NETWORK_NAME_DELETED: 0xc00000c9"
        )
        assert actual.error_details == []

    def test_throw_exception_with_symlink_redir(self):
        symlnk_redir = SMB2SymbolicLinkErrorResponse()
        symlnk_redir.set_name(r"C:\temp\folder", r"\??\C:\temp\folder")

        cont_resp = SMB2ErrorContextResponse()
        cont_resp["error_context_data"] = symlnk_redir

        error_resp = SMB2ErrorResponse()
        error_resp["error_data"] = [cont_resp]
        header = self._get_header(error_resp, NtStatus.STATUS_STOPPED_ON_SYMLINK)
        try:
            raise SMBResponseException(header)
        except SMBResponseException as exc:
            assert len(exc.error_details) == 1
            err1 = exc.error_details[0]
            assert isinstance(err1, SMB2SymbolicLinkErrorResponse)
            exp_resp = (
                "Received unexpected status from the server: The create operation stopped after reaching a "
                "symbolic link. (2147483693) STATUS_STOPPED_ON_SYMLINK: 0x8000002d - Flag: (0) "
                "SYMLINK_FLAG_ABSOLUTE, Print Name: C:\\temp\\folder, Substitute Name: \\??\\C:\\temp\\folder"
            )
            assert exc.message == exp_resp
            assert str(exc) == exp_resp
            assert exc.status == NtStatus.STATUS_STOPPED_ON_SYMLINK

    def test_throw_exception_with_share_redir(self):
        ip_addr = SMB2MoveDstIpAddrStructure()
        ip_addr["type"] = IpAddrType.MOVE_DST_IPADDR_V4
        ip_addr.set_ipaddress("192.168.1.100")

        share_redir = SMB2ShareRedirectErrorContext()
        share_redir["ip_addr_move_list"] = [ip_addr]
        share_redir["resource_name"] = "resource".encode("utf-16-le")

        cont_resp = SMB2ErrorContextResponse()
        cont_resp["error_id"] = ErrorContextId.SMB2_ERROR_ID_SHARE_REDIRECT
        cont_resp["error_context_data"] = share_redir

        error_resp = SMB2ErrorResponse()
        error_resp["error_data"] = [cont_resp]
        header = self._get_header(error_resp, NtStatus.STATUS_BAD_NETWORK_NAME)
        try:
            raise SMBResponseException(header)
        except SMBResponseException as exc:
            assert len(exc.error_details) == 1
            err1 = exc.error_details[0]
            assert isinstance(err1, SMB2ShareRedirectErrorContext)
            exp_resp = (
                "Received unexpected status from the server: The specified share name cannot be found on "
                "the remote server. (3221225676) STATUS_BAD_NETWORK_NAME: 0xc00000cc - IP Addresses: "
                "'192.168.1.100', Resource Name: resource"
            )
            assert exc.message == exp_resp
            assert str(exc) == exp_resp
            assert exc.status == NtStatus.STATUS_BAD_NETWORK_NAME

    def test_throw_exception_with_raw_context(self):
        error_resp = SMB2ErrorResponse()
        cont_resp = SMB2ErrorContextResponse()
        cont_resp["error_context_data"] = b"\x01\x02\x03\x04"
        error_resp["error_data"] = [cont_resp]
        header = self._get_header(error_resp)
        try:
            raise SMBResponseException(header)
        except SMBResponseException as exc:
            assert len(exc.error_details) == 1
            assert exc.error_details[0] == b"\x01\x02\x03\x04"
            exp_resp = (
                "Received unexpected status from the server: An invalid parameter was passed to a service "
                "or function. (3221225485) STATUS_INVALID_PARAMETER: 0xc000000d - Raw: 01020304"
            )
            assert exc.message == exp_resp
            assert str(exc) == exp_resp
            assert exc.status == NtStatus.STATUS_INVALID_PARAMETER

    def test_throw_exception_with_multiple_contexts(self):
        error_resp = SMB2ErrorResponse()
        cont_resp1 = SMB2ErrorContextResponse()
        cont_resp1["error_context_data"] = b"\x01\x02\x03\x04"
        cont_resp2 = SMB2ErrorContextResponse()
        cont_resp2["error_context_data"] = b"\x05\x06\x07\x08"
        error_resp["error_data"] = [cont_resp1, cont_resp2]
        header = self._get_header(error_resp)
        try:
            raise SMBResponseException(header)
        except SMBResponseException as exc:
            assert len(exc.error_details) == 2
            assert exc.error_details[0] == b"\x01\x02\x03\x04"
            assert exc.error_details[1] == b"\x05\x06\x07\x08"
            exp_resp = (
                "Received unexpected status from the server: An invalid parameter was passed to a service "
                "or function. (3221225485) STATUS_INVALID_PARAMETER: 0xc000000d - Raw: 01020304, Raw: 05060708"
            )
            assert exc.message == exp_resp
            assert str(exc) == exp_resp

            assert exc.status == NtStatus.STATUS_INVALID_PARAMETER

    def test_exception_no_context_but_data(self):
        # Older dialects don't support the Error Context list but still return data in there. This tests those older
        # hosts.
        data = b"\x09\x00" b"\x00" b"\x00" b"\x04\x00\x00\x00" b"\x01\x02\x03\x04"
        error_resp = SMB2ErrorResponse()
        data = error_resp.unpack(data)

        assert data == b""
        assert len(error_resp["error_data"].get_value()) == 1
        error_context = error_resp["error_data"].get_value()[0]
        assert error_context["error_data_length"].get_value() == 4
        assert error_context["error_id"].get_value() == ErrorContextId.SMB2_ERROR_ID_DEFAULT
        assert error_context["error_context_data"].get_value() == b"\x01\x02\x03\x04"

    def test_inherited_exception_no_code(self):
        with pytest.raises(ValueError, match="MyError does not have the _STATUS_CODE class attribute set"):

            class MyError(SMBResponseException):
                pass

    def _get_header(self, data, status=NtStatus.STATUS_INVALID_PARAMETER):
        header = SMB2HeaderResponse()
        header["status"] = status
        header["message_id"] = 10
        header["data"] = data
        return header


class TestSMB2ErrorResponse:
    def test_create_message_plain(self):
        # This is a plain error response without the error context response
        # data appended
        message = SMB2ErrorResponse()
        expected = b"\x09\x00" b"\x00" b"\x00" b"\x00\x00\x00\x00"
        actual = message.pack()
        assert len(actual) == 8
        assert actual == expected

    def test_create_message_with_context(self):
        message = SMB2ErrorResponse()
        error_context = SMB2ErrorContextResponse()
        error_context["error_context_data"] = b"\x01\x02\x03\x04"
        message["error_data"] = [error_context]
        expected = (
            b"\x09\x00" b"\x01" b"\x00" b"\x0c\x00\x00\x00" b"\x04\x00\x00\x00" b"\x00\x00\x00\x00" b"\x01\x02\x03\x04"
        )
        actual = message.pack()
        assert len(message) == 20
        assert actual == expected

    def test_parse_message_plain(self):
        actual = SMB2ErrorResponse()
        data = b"\x09\x00" b"\x00" b"\x00" b"\x00\x00\x00\x00"
        data = actual.unpack(data)
        assert len(actual) == 8
        assert data == b""
        assert actual["structure_size"].get_value() == 9
        assert actual["error_context_count"].get_value() == 0
        assert actual["reserved"].get_value() == 0
        assert actual["byte_count"].get_value() == 0
        assert actual["error_data"].get_value() == []

    def test_parse_message_with_context(self):
        actual = SMB2ErrorResponse()
        data = (
            b"\x09\x00" b"\x01" b"\x00" b"\x0c\x00\x00\x00" b"\x04\x00\x00\x00" b"\x00\x00\x00\x00" b"\x01\x02\x03\x04"
        )  # just a fake bytes value for test
        data = actual.unpack(data)
        assert len(actual) == 20
        assert data == b""
        assert actual["structure_size"].get_value() == 9
        assert actual["error_context_count"].get_value() == 1
        assert actual["reserved"].get_value() == 0
        assert actual["byte_count"].get_value() == 12
        assert len(actual["error_data"]) == 12
        error_data = actual["error_data"].get_value()
        assert len(error_data) == 1
        assert error_data[0]["error_data_length"].get_value() == 4
        assert error_data[0]["error_id"].get_value() == SymbolicLinkErrorFlags.SYMLINK_FLAG_ABSOLUTE
        assert error_data[0]["error_context_data"].get_value() == b"\x01\x02\x03\x04"


class TestSMB2ErrorContextResponse:
    def test_create_message(self):
        message = SMB2ErrorContextResponse()
        message["error_id"] = ErrorContextId.SMB2_ERROR_ID_SHARE_REDIRECT
        message["error_context_data"] = b"\x01\x02\x03\x04"
        expected = b"\x04\x00\x00\x00" b"\x72\x64\x52\x53" b"\x01\x02\x03\x04"
        actual = message.pack()
        assert len(message) == 12
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2ErrorContextResponse()
        data = b"\x04\x00\x00\x00" b"\x72\x64\x52\x53" b"\x01\x02\x03\x04"
        data = actual.unpack(data)
        assert len(actual) == 12
        assert data == b""
        assert actual["error_data_length"].get_value() == 4
        assert actual["error_id"].get_value() == ErrorContextId.SMB2_ERROR_ID_SHARE_REDIRECT
        assert actual["error_context_data"].get_value() == b"\x01\x02\x03\x04"


class TestSMB2SymbolicLinkErrorResponse:
    def test_create_message(self):
        message = SMB2SymbolicLinkErrorResponse()
        message.set_name(r"C:\temp\folder", r"\??\C:\temp\folder")
        expected = (
            b"\x58\x00\x00\x00"
            b"\x53\x59\x4d\x4c"
            b"\x0c\x00\x00\xa0"
            b"\x4c\x00"
            b"\x00\x00"
            b"\x1c\x00"
            b"\x24\x00"
            b"\x00\x00"
            b"\x1c\x00"
            b"\x00\x00\x00\x00"
            b"\x43\x00\x3a\x00\x5c\x00\x74\x00"
            b"\x65\x00\x6d\x00\x70\x00\x5c\x00"
            b"\x66\x00\x6f\x00\x6c\x00\x64\x00"
            b"\x65\x00\x72\x00"
            b"\x5c\x00\x3f\x00\x3f\x00\x5c\x00"
            b"\x43\x00\x3a\x00\x5c\x00\x74\x00"
            b"\x65\x00\x6d\x00\x70\x00\x5c\x00"
            b"\x66\x00\x6f\x00\x6c\x00\x64\x00"
            b"\x65\x00\x72\x00"
        )
        actual = message.pack()
        assert len(actual) == 92
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2SymbolicLinkErrorResponse()
        data = (
            b"\x58\x00\x00\x00"
            b"\x53\x59\x4d\x4c"
            b"\x0c\x00\x00\xa0"
            b"\x4c\x00"
            b"\x00\x00"
            b"\x1c\x00"
            b"\x24\x00"
            b"\x00\x00"
            b"\x1c\x00"
            b"\x00\x00\x00\x00"
            b"\x43\x00\x3a\x00\x5c\x00\x74\x00"
            b"\x65\x00\x6d\x00\x70\x00\x5c\x00"
            b"\x66\x00\x6f\x00\x6c\x00\x64\x00"
            b"\x65\x00\x72\x00"
            b"\x5c\x00\x3f\x00\x3f\x00\x5c\x00"
            b"\x43\x00\x3a\x00\x5c\x00\x74\x00"
            b"\x65\x00\x6d\x00\x70\x00\x5c\x00"
            b"\x66\x00\x6f\x00\x6c\x00\x64\x00"
            b"\x65\x00\x72\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 92
        assert data == b""
        assert actual["symlink_length"].get_value() == 88
        assert actual["symlink_error_tag"].get_value() == b"\x53\x59\x4d\x4c"
        assert actual["reparse_tag"].get_value() == b"\x0c\x00\x00\xa0"
        assert actual["reparse_data_length"].get_value() == 76
        assert actual["unparsed_path_length"].get_value() == 0
        assert actual["substitute_name_offset"].get_value() == 28
        assert actual["substitute_name_length"].get_value() == 36
        assert actual["print_name_offset"].get_value() == 0
        assert actual["print_name_length"].get_value() == 28
        assert actual["flags"].get_value() == SymbolicLinkErrorFlags.SYMLINK_FLAG_ABSOLUTE
        assert (
            actual["path_buffer"].get_value() == b"\x43\x00\x3a\x00\x5c\x00\x74\x00"
            b"\x65\x00\x6d\x00\x70\x00\x5c\x00"
            b"\x66\x00\x6f\x00\x6c\x00\x64\x00"
            b"\x65\x00\x72\x00"
            b"\x5c\x00\x3f\x00\x3f\x00\x5c\x00"
            b"\x43\x00\x3a\x00\x5c\x00\x74\x00"
            b"\x65\x00\x6d\x00\x70\x00\x5c\x00"
            b"\x66\x00\x6f\x00\x6c\x00\x64\x00"
            b"\x65\x00\x72\x00"
        )
        assert actual.get_print_name() == r"C:\temp\folder"
        assert actual.get_substitute_name() == r"\??\C:\temp\folder"

    @pytest.mark.parametrize(
        "unparsed_length, sub_name, print_name, flags, link_path, expected",
        [
            # Relative link that points to a file in the same directory
            (
                0,
                "tést",
                "tést",
                SymbolicLinkErrorFlags.SYMLINK_FLAG_RELATIVE,
                "\\\\sérver\\sharé\\foldér\\subfolder\\mylink",
                "\\\\sérver\\sharé\\foldér\\subfolder\\tést",
            ),
            # Relative link that points to a file in the parent directory
            (
                0,
                "..\\tést",
                "..\\tést",
                SymbolicLinkErrorFlags.SYMLINK_FLAG_RELATIVE,
                "\\\\sérver\\sharé\\foldér\\subfolder\\mylink",
                "\\\\sérver\\sharé\\foldér\\tést",
            ),
            # Relative link with further path components
            (
                42,
                "..\\tést",
                "..\\tést",
                SymbolicLinkErrorFlags.SYMLINK_FLAG_RELATIVE,
                "\\\\sérver\\sharé\\foldér\\subfolder\\mylink\\some folder\\file.txt",
                "\\\\sérver\\sharé\\foldér\\tést\\some folder\\file.txt",
            ),
            # Absolute link
            (
                0,
                "\\??\\UNC\\sérver\\sharé\\foldér\\test",
                "\\\\sérver\\sharé\\foldér\\test",
                SymbolicLinkErrorFlags.SYMLINK_FLAG_ABSOLUTE,
                "\\\\sérver\\sharé\\foldér\\subfolder\\mylink",
                "\\\\sérver\\sharé\\foldér\\test",
            ),
            # Absolute link with further path components
            (
                42,
                "\\??\\UNC\\sérver\\sharé\\foldér\\test",
                "\\\\sérver\\sharé\\foldér\\test",
                SymbolicLinkErrorFlags.SYMLINK_FLAG_ABSOLUTE,
                "\\\\sérver\\sharé\\foldér\\subfolder\\mylink\\some folder\\file.txt",
                "\\\\sérver\\sharé\\foldér\\test\\some folder\\file.txt",
            ),
        ],
    )
    def test_resolve_path(self, unparsed_length, sub_name, print_name, flags, link_path, expected):
        b_sub_name = to_bytes(sub_name, encoding="utf-16-le")
        b_print_name = to_bytes(print_name, encoding="utf-16-le")
        resp = SMB2SymbolicLinkErrorResponse()
        resp["unparsed_path_length"] = unparsed_length
        resp["substitute_name_offset"] = 0
        resp["substitute_name_length"] = len(b_sub_name)
        resp["print_name_offset"] = len(b_sub_name)
        resp["print_name_length"] = len(b_print_name)
        resp["flags"] = flags
        resp["path_buffer"] = b_sub_name + b_print_name

        assert resp.get_print_name() == print_name
        assert resp.get_substitute_name() == sub_name

        actual = resp.resolve_path(link_path)
        assert actual == expected

    def test_resolve_path_local_fail(self):
        b_sub_name = to_bytes("\\??\\C:\\foldér", encoding="utf-16-le")
        b_print_name = to_bytes("C:\\foldér", encoding="utf-16-le")
        resp = SMB2SymbolicLinkErrorResponse()
        resp["unparsed_path_length"] = 0
        resp["substitute_name_offset"] = 0
        resp["substitute_name_length"] = len(b_sub_name)
        resp["print_name_offset"] = len(b_sub_name)
        resp["print_name_length"] = len(b_print_name)
        resp["flags"] = SymbolicLinkErrorFlags.SYMLINK_FLAG_ABSOLUTE
        resp["path_buffer"] = b_sub_name + b_print_name

        link_path = "\\\\sérver\\sharé\\foldér"
        expected = (
            "Encountered symlink at '%s' that points to 'C:\\foldér' which cannot be redirected: Cannot "
            "resolve link targets that point to a local path" % link_path
        )
        with pytest.raises(SMBLinkRedirectionError, match=re.escape(expected)):
            resp.resolve_path(link_path)

    def test_resolve_path_different_share(self):
        b_sub_name = to_bytes("\\??\\UNC\\other-sérver\\sharé\\foldér", encoding="utf-16-le")
        b_print_name = to_bytes("\\\\other-sérver\\sharé\\foldér", encoding="utf-16-le")
        resp = SMB2SymbolicLinkErrorResponse()
        resp["unparsed_path_length"] = 0
        resp["substitute_name_offset"] = 0
        resp["substitute_name_length"] = len(b_sub_name)
        resp["print_name_offset"] = len(b_sub_name)
        resp["print_name_length"] = len(b_print_name)
        resp["flags"] = SymbolicLinkErrorFlags.SYMLINK_FLAG_ABSOLUTE
        resp["path_buffer"] = b_sub_name + b_print_name

        link_path = "\\\\sérver\\sharé\\foldér"
        expected = (
            "Encountered symlink at '%s' that points to '\\\\other-sérver\\sharé\\foldér' which cannot be "
            "redirected: Cannot resolve link targets that point to a different host/share" % link_path
        )
        with pytest.raises(SMBLinkRedirectionError, match=re.escape(expected)):
            resp.resolve_path(link_path)

    def test_resolve_path_different_host(self):
        b_sub_name = to_bytes("\\??\\UNC\\sérver\\sharé2\\foldér", encoding="utf-16-le")
        b_print_name = to_bytes("\\\\sérver\\sharé2\\foldér", encoding="utf-16-le")
        resp = SMB2SymbolicLinkErrorResponse()
        resp["unparsed_path_length"] = 0
        resp["substitute_name_offset"] = 0
        resp["substitute_name_length"] = len(b_sub_name)
        resp["print_name_offset"] = len(b_sub_name)
        resp["print_name_length"] = len(b_print_name)
        resp["flags"] = SymbolicLinkErrorFlags.SYMLINK_FLAG_ABSOLUTE
        resp["path_buffer"] = b_sub_name + b_print_name

        link_path = "\\\\sérver\\sharé\\foldér"
        expected = (
            "Encountered symlink at '%s' that points to '\\\\sérver\\sharé2\\foldér' which cannot be "
            "redirected: Cannot resolve link targets that point to a different host/share" % link_path
        )
        with pytest.raises(SMBLinkRedirectionError, match=re.escape(expected)):
            resp.resolve_path(link_path)


class TestSMB2ShareRedirectErrorContext:
    def test_create_message(self):
        message = SMB2ShareRedirectErrorContext()
        ip1 = SMB2MoveDstIpAddrStructure()
        ip1["type"] = IpAddrType.MOVE_DST_IPADDR_V4
        ip1.set_ipaddress("192.168.1.100")
        ip2 = SMB2MoveDstIpAddrStructure()
        ip2["type"] = IpAddrType.MOVE_DST_IPADDR_V6
        ip2.set_ipaddress("fe80:12ab:0000:0000:0000:0001:0002:0000")
        message["ip_addr_move_list"] = [ip1, ip2]
        message["resource_name"] = b"\x01\x02\x03\x04"
        expected = (
            b"\x4c\x00\x00\x00"
            b"\x03\x00\x00\x00"
            b"\x48\x00\x00\x00"
            b"\x04\x00\x00\x00"
            b"\x00\x00"
            b"\x00\x00"
            b"\x02\x00\x00\x00"
            b"\x01\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xc0\xa8\x01\x64"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x02\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xfe\x80\x12\xab\x00\x00\x00\x00"
            b"\x00\x00\x00\x01\x00\x02\x00\x00"
            b"\x01\x02\x03\x04"
        )
        actual = message.pack()
        assert len(message) == 76
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2ShareRedirectErrorContext()
        data = (
            b"\x4c\x00\x00\x00"
            b"\x03\x00\x00\x00"
            b"\x48\x00\x00\x00"
            b"\x04\x00\x00\x00"
            b"\x00\x00"
            b"\x00\x00"
            b"\x02\x00\x00\x00"
            b"\x01\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xc0\xa8\x01\x64"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x02\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xfe\x80\x12\xab\x00\x00\x00\x00"
            b"\x00\x00\x00\x01\x00\x02\x00\x00"
            b"\x01\x02\x03\x04"
        )
        data = actual.unpack(data)
        assert len(actual) == 76
        assert data == b""
        assert actual["structure_size"].get_value() == 76
        assert actual["notification_type"].get_value() == 3
        assert actual["resource_name_offset"].get_value() == 72
        assert actual["resource_name_length"].get_value() == 4
        assert actual["flags"].get_value() == 0
        assert actual["target_type"].get_value() == 0
        assert actual["ip_addr_count"].get_value() == 2
        ip_addr = actual["ip_addr_move_list"].get_value()
        assert isinstance(ip_addr, list)
        assert len(ip_addr) == 2
        ip1 = ip_addr[0]
        assert ip1["type"].get_value() == IpAddrType.MOVE_DST_IPADDR_V4
        assert ip1["reserved"].get_value() == 0
        assert ip1["ip_address"].get_value() == b"\xc0\xa8\x01\x64"
        assert ip1["reserved2"].get_value() == b"\x00" * 12
        ip2 = ip_addr[1]
        assert ip2["type"].get_value() == IpAddrType.MOVE_DST_IPADDR_V6
        assert ip2["reserved"].get_value() == 0
        assert ip2["ip_address"].get_value() == b"\xfe\x80\x12\xab\x00\x00\x00\x00" b"\x00\x00\x00\x01\x00\x02\x00\x00"
        assert ip2["reserved2"].get_value() == b""
        assert actual["resource_name"].get_value() == b"\x01\x02\x03\x04"


class TestSMB2MoveDstIpAddrStructure:
    def test_create_message_v4(self):
        message = SMB2MoveDstIpAddrStructure()
        message["type"] = IpAddrType.MOVE_DST_IPADDR_V4
        message.set_ipaddress("192.168.1.100")
        expected = (
            b"\x01\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xc0\xa8\x01\x64"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 24
        assert actual == expected

    def test_create_message_v6(self):
        message = SMB2MoveDstIpAddrStructure()
        message["type"] = IpAddrType.MOVE_DST_IPADDR_V6
        message.set_ipaddress("fe80:12ab:0000:0000:0000:0001:0002:0000")
        expected = (
            b"\x02\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xfe\x80\x12\xab\x00\x00\x00\x00"
            b"\x00\x00\x00\x01\x00\x02\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 24
        assert actual == expected

    def test_fail_invalid_ipv6_address(self):
        message = SMB2MoveDstIpAddrStructure()
        message["type"] = IpAddrType.MOVE_DST_IPADDR_V6
        with pytest.raises(ValueError) as exc:
            message.set_ipaddress("abc")
        assert str(exc.value) == "When setting an IPv6 address, it must be in the full form without concatenation"

    def test_parse_message_v4(self):
        actual = SMB2MoveDstIpAddrStructure()
        data = (
            b"\x01\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xc0\xa8\x01\x64"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 24
        assert data == b""
        assert actual["type"].get_value() == IpAddrType.MOVE_DST_IPADDR_V4
        assert actual["reserved"].get_value() == 0
        assert actual["ip_address"].get_value() == b"\xc0\xa8\x01\x64"
        assert actual["reserved2"].get_value() == b"\x00" * 12
        assert actual.get_ipaddress() == "192.168.1.100"

    def test_parse_message_v6(self):
        actual = SMB2MoveDstIpAddrStructure()
        data = (
            b"\x02\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xfe\x80\x12\xab\x00\x00\x00\x00"
            b"\x00\x00\x00\x01\x00\x02\x00\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 24
        assert data == b""
        assert actual["type"].get_value() == IpAddrType.MOVE_DST_IPADDR_V6
        assert actual["reserved"].get_value() == 0
        assert (
            actual["ip_address"].get_value() == b"\xfe\x80\x12\xab\x00\x00\x00\x00" b"\x00\x00\x00\x01\x00\x02\x00\x00"
        )
        assert actual["reserved2"].get_value() == b""
        assert actual.get_ipaddress() == "fe80:12ab:0000:0000:0000:0001:0002:0000"
