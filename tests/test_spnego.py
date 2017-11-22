from pyasn1.codec.der.decoder import decode
from pyasn1.type.univ import ObjectIdentifier

from smbprotocol.spnego import InitialContextToken, NegotiateToken, MechTypes


class TestSpnego(object):

    def test_parse_initial_context_token(self):
        data = b"\x60\x76\x06\x06\x2b\x06\x01\x05" \
               b"\x05\x02\xa0\x6c\x30\x6a\xa0\x3c" \
               b"\x30\x3a\x06\x0a\x2b\x06\x01\x04" \
               b"\x01\x82\x37\x02\x02\x1e\x06\x09" \
               b"\x2a\x86\x48\x82\xf7\x12\x01\x02" \
               b"\x02\x06\x09\x2a\x86\x48\x86\xf7" \
               b"\x12\x01\x02\x02\x06\x0a\x2a\x86" \
               b"\x48\x86\xf7\x12\x01\x02\x02\x03" \
               b"\x06\x0a\x2b\x06\x01\x04\x01\x82" \
               b"\x37\x02\x02\x0a\xa3\x2a\x30\x28" \
               b"\xa0\x26\x1b\x24\x6e\x6f\x74\x5f" \
               b"\x64\x65\x66\x69\x6e\x65\x64\x5f" \
               b"\x69\x6e\x5f\x52\x46\x43\x34\x31" \
               b"\x37\x38\x40\x70\x6c\x65\x61\x73" \
               b"\x65\x5f\x69\x67\x6e\x6f\x72\x65"
        actual, rdata = decode(data, asn1Spec=InitialContextToken())
        assert rdata == b""
        assert actual['thisMech'] == ObjectIdentifier('1.3.6.1.5.5.2')
        assert isinstance(actual['innerContextToken'], NegotiateToken)
        actual_token = actual['innerContextToken']['negTokenInit']
        assert actual_token['mechTypes'] == [
            MechTypes.NEGOEX,
            MechTypes.MS_KRB5,
            MechTypes.KRB5,
            MechTypes.KRB5_U2U,
            MechTypes.NTLMSSP

        ]
        assert actual_token['negHints']['hintName'] == \
            "not_defined_in_RFC4178@please_ignore"
