# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import pytest

from smbprotocol._text import (
    to_bytes,
    to_native,
    to_text,
)

from smbprotocol.dfs import (
    DFSReferralEntryV1,
    DFSReferralEntryV2,
    DFSReferralEntryV3,
    DFSReferralRequest,
    DFSReferralRequestEx,
    DFSReferralRequestFlags,
    DFSReferralResponse,
)

# 'MUSICAL SYMBOL G CLEF' https://www.fileformat.info/info/unicode/char/1d11e/index.htm
UNICODE_TEXT = u'ÜseӜ' + to_text(b"\xF0\x9D\x84\x9E")


class TestDFSReferralRequest(object):

    def test_create_message(self):
        share = u'\\\\server\\shares\\%s' % UNICODE_TEXT

        message = DFSReferralRequest()
        message['max_referral_level'] = 4
        message['request_file_name'] = share
        expected = b"\x04\x00" \
                   b"\x5C\x00\x5C\x00\x73\x00\x65\x00" \
                   b"\x72\x00\x76\x00\x65\x00\x72\x00" \
                   b"\x5C\x00\x73\x00\x68\x00\x61\x00" \
                   b"\x72\x00\x65\x00\x73\x00\x5C\x00" \
                   b"\x55\x00\x08\x03\x73\x00\x65\x00" \
                   b"\xDC\x04\x34\xD8\x1E\xDD\x00\x00"
        actual = message.pack()

        assert len(message) == 50
        assert actual == expected
        assert str(message['request_file_name']) == to_native(share)

    @pytest.mark.parametrize('leftover', [b"", b"\x01\x02\x03\x04"])
    def test_parse_message(self, leftover):
        share = u'\\\\server\\shares\\%s' % UNICODE_TEXT

        actual = DFSReferralRequest()
        data = b"\x04\x00" \
               b"\x5C\x00\x5C\x00\x73\x00\x65\x00" \
               b"\x72\x00\x76\x00\x65\x00\x72\x00" \
               b"\x5C\x00\x73\x00\x68\x00\x61\x00" \
               b"\x72\x00\x65\x00\x73\x00\x5C\x00" \
               b"\x55\x00\x08\x03\x73\x00\x65\x00" \
               b"\xDC\x04\x34\xD8\x1E\xDD\x00\x00"
        data += leftover
        data = actual.unpack(data)

        assert data == leftover
        assert len(actual) == 50
        assert actual['max_referral_level'].get_value() == 4
        assert actual['request_file_name'].get_value() == share


class TestDFSReferralRequestEx(object):

    def test_create_message(self):
        share = u'\\\\server\\shares\\%s' % UNICODE_TEXT

        message = DFSReferralRequestEx()
        message['max_referral_level'] = 4
        message['request_flags'] = DFSReferralRequestFlags.SITE_NAME
        message['request_file_name'] = share
        message['site_name'] = UNICODE_TEXT

        expected = b"\x04\x00" \
                   b"\x01\x00" \
                   b"\x44\x00\x00\x00" \
                   b"\x30\x00" \
                   b"\x5C\x00\x5C\x00\x73\x00\x65\x00" \
                   b"\x72\x00\x76\x00\x65\x00\x72\x00" \
                   b"\x5C\x00\x73\x00\x68\x00\x61\x00" \
                   b"\x72\x00\x65\x00\x73\x00\x5C\x00" \
                   b"\x55\x00\x08\x03\x73\x00\x65\x00" \
                   b"\xDC\x04\x34\xD8\x1E\xDD\x00\x00" \
                   b"\x10\x00" \
                   b"\x55\x00\x08\x03\x73\x00\x65\x00" \
                   b"\xDC\x04\x34\xD8\x1E\xDD\x00\x00"
        actual = message.pack()

        assert len(message) == 76
        assert actual == expected
        assert str(message['request_file_name']) == to_native(share)
        assert str(message['site_name']) == to_native(UNICODE_TEXT)

    @pytest.mark.parametrize('leftover', [b"", b"\x01\x02\x03\x04"])
    def test_parse_message(self, leftover):
        share = u'\\\\server\\shares\\%s' % UNICODE_TEXT

        actual = DFSReferralRequestEx()
        data = b"\x04\x00" \
               b"\x01\x00" \
               b"\x44\x00\x00\x00" \
               b"\x30\x00" \
               b"\x5C\x00\x5C\x00\x73\x00\x65\x00" \
               b"\x72\x00\x76\x00\x65\x00\x72\x00" \
               b"\x5C\x00\x73\x00\x68\x00\x61\x00" \
               b"\x72\x00\x65\x00\x73\x00\x5C\x00" \
               b"\x55\x00\x08\x03\x73\x00\x65\x00" \
               b"\xDC\x04\x34\xD8\x1E\xDD\x00\x00" \
               b"\x10\x00" \
               b"\x55\x00\x08\x03\x73\x00\x65\x00" \
               b"\xDC\x04\x34\xD8\x1E\xDD\x00\x00"
        data += leftover
        data = actual.unpack(data)

        assert data == leftover
        assert len(actual) == 76
        assert actual['max_referral_level'].get_value() == 4
        assert actual['request_flags'].get_value() == DFSReferralRequestFlags.SITE_NAME
        assert actual['request_data_length'].get_value() == 68
        assert actual['request_file_name_length'].get_value() == 48
        assert actual['request_file_name'].get_value() == share
        assert actual['site_name_length'].get_value() == 16
        assert actual['site_name'].get_value() == UNICODE_TEXT


class TestDFSReferralResponse(object):

    def test_create_message(self):
        # TODO: Test this out
        return

    def test_parse_message_v1(self):
        # TODO: Test this out
        return

    def test_parse_message_v2(self):
        # TODO: Test this out
        return

    def test_parse_message_v3_name_list_referral(self):
        actual = DFSReferralResponse()
        data = b"\x00\x00" \
               b"\x02\x00" \
               b"\x00\x00\x00\x00" \
               b"\x03\x00" \
               b"\x22\x00" \
               b"\x00\x00" \
               b"\x02\x00" \
               b"\x58\x02\x00\x00" \
               b"\x34\x00" \
               b"\x00\x00" \
               b"\x00\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x03\x00" \
               b"\x12\x00" \
               b"\x00\x00" \
               b"\x02\x00" \
               b"\x58\x02\x00\x00" \
               b"\x22\x00" \
               b"\x00\x00" \
               b"\x00\x00" \
               b"\x5c\x00\x44\x00\x4f\x00\x4d\x00" \
               b"\x41\x00\x49\x00\x4e\x00\x00\x00" \
               b"\x5c\x00\x64\x00\x6f\x00\x6d\x00" \
               b"\x61\x00\x69\x00\x6e\x00\x2e\x00" \
               b"\x6c\x00\x6f\x00\x63\x00\x61\x00" \
               b"\x6c\x00\x00\x00"
        actual.unpack(data)

        assert isinstance(actual, DFSReferralResponse)
        assert actual['path_consumed'].get_value() == 0
        assert actual['number_of_referrals'].get_value() == 2
        assert actual['referral_header_flags'].get_value() == 0
        assert len(actual['referral_entries'].get_value()) == 2

        entry1 = actual['referral_entries'][0]
        assert isinstance(entry1, DFSReferralEntryV3)
        assert entry1['version_number'].get_value() == 3
        assert entry1['size'].get_value() == 34
        assert entry1['server_type'].get_value() == 0
        assert entry1['referral_entry_flags'].get_value() == 2
        assert entry1['time_to_live'].get_value() == 600
        assert entry1['dfs_path_offset'].get_value() == 52
        assert entry1['dfs_alternate_path_offset'].get_value() == 0
        assert entry1['network_address_offset'].get_value() == 0
        assert entry1['service_site_guid'].get_value() == b"\x00" * 16
        assert entry1.dfs_path == u"\\DOMAIN"
        assert entry1.dfs_alternate_path is None
        assert entry1.network_address is None

        entry2 = actual['referral_entries'][1]
        assert isinstance(entry2, DFSReferralEntryV3)
        assert entry2['version_number'].get_value() == 3
        assert entry2['size'].get_value() == 18
        assert entry2['server_type'].get_value() == 0
        assert entry2['referral_entry_flags'].get_value() == 2
        assert entry2['time_to_live'].get_value() == 600
        assert entry2['dfs_path_offset'].get_value() == 34
        assert entry2['dfs_alternate_path_offset'].get_value() == 0
        assert entry2['network_address_offset'].get_value() == 0
        assert entry2['service_site_guid'].get_value() == b""
        assert entry2.dfs_path == u"\\domain.local"
        assert entry2.dfs_alternate_path is None
        assert entry2.network_address is None

    def test_parse_message_v4(self):
        actual = DFSReferralResponse()
        data = b"\x22\x00" \
               b"\x01\x00" \
               b"\x03\x00\x00\x00" \
               b"\x04\x00" \
               b"\x22\x00" \
               b"\x01\x00" \
               b"\x04\x00" \
               b"\x2c\x01\x00\x00" \
               b"\x22\x00" \
               b"\x46\x00" \
               b"\x6a\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x5c\x00\x64\x00\x6f\x00\x6d\x00" \
               b"\x61\x00\x69\x00\x6e\x00\x2e\x00" \
               b"\x6c\x00\x6f\x00\x63\x00\x61\x00" \
               b"\x6c\x00\x5c\x00\x64\x00\x66\x00" \
               b"\x73\x00\x00\x00\x5c\x00\x64\x00" \
               b"\x6f\x00\x6d\x00\x61\x00\x69\x00" \
               b"\x6e\x00\x2e\x00\x6c\x00\x6f\x00" \
               b"\x63\x00\x61\x00\x6c\x00\x5c\x00" \
               b"\x64\x00\x66\x00\x73\x00\x00\x00" \
               b"\x5c\x00\x53\x00\x45\x00\x52\x00" \
               b"\x56\x00\x45\x00\x52\x00\x32\x00" \
               b"\x30\x00\x31\x00\x32\x00\x52\x00" \
               b"\x32\x00\x5c\x00\x64\x00\x66\x00" \
               b"\x73\x00\x00\x00"
        actual.unpack(data)

        assert isinstance(actual, DFSReferralResponse)
        assert actual['path_consumed'].get_value() == 34
        assert actual['number_of_referrals'].get_value() == 1
        assert actual['referral_header_flags'].get_value() == 3
        assert len(actual['referral_entries'].get_value()) == 1

        entry1 = actual['referral_entries'][0]
        assert isinstance(entry1, DFSReferralEntryV3)
        assert entry1['version_number'].get_value() == 4
        assert entry1['size'].get_value() == 34
        assert entry1['server_type'].get_value() == 1
        assert entry1['referral_entry_flags'].get_value() == 4
        assert entry1['time_to_live'].get_value() == 300
        assert entry1['dfs_path_offset'].get_value() == 34
        assert entry1['dfs_alternate_path_offset'].get_value() == 70
        assert entry1['network_address_offset'].get_value() == 106
        assert entry1['service_site_guid'].get_value() == b"\x00" * 16
        assert entry1.dfs_path == u"\\domain.local\\dfs"
        assert entry1.dfs_alternate_path == u"\\domain.local\\dfs"
        assert entry1.network_address == u"\\SERVER2012R2\\dfs"
