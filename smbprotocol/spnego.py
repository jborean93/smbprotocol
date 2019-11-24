# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from pyasn1.type.char import (
    GeneralString,
)

from pyasn1.type.constraint import (
    SingleValueConstraint,
)

from pyasn1.type.namedtype import (
    NamedType,
    NamedTypes,
    OptionalNamedType,
)

from pyasn1.type.namedval import (
    NamedValues,
)

from pyasn1.type.tag import (
    Tag,
    tagClassApplication,
    tagClassContext,
    tagFormatConstructed,
    tagFormatSimple,
    TagSet,
)

from pyasn1.type.univ import (
    BitString,
    Choice,
    Enumerated,
    ObjectIdentifier,
    OctetString,
    Sequence,
    SequenceOf,
)


class MechTypes(object):
    MS_KRB5 = ObjectIdentifier('1.2.840.48018.1.2.2')
    KRB5 = ObjectIdentifier('1.2.840.113554.1.2.2')
    KRB5_U2U = ObjectIdentifier('1.2.840.113554.1.2.2.3')
    NEGOEX = ObjectIdentifier('1.3.6.1.4.1.311.2.2.30')
    NTLMSSP = ObjectIdentifier('1.3.6.1.4.1.311.2.2.10')


class MechType(ObjectIdentifier):
    """
    [RFC-4178]

    4.1 Mechanism Types
    OID represents one GSS-API mechanism according to RFC-2743.

    MechType ::= OBJECT IDENTIFIER
    """
    pass


class MechTypeList(SequenceOf):
    """
    [RFC-4178]

    4.1 Mechanism Types
    List of MechTypes

    MechTypeList ::= SEQUENCE OF MechType
    """
    componentType = MechType()


class ContextFlags(BitString):
    """
    [RFC-4178]

    ContextFlags ::= BIT STRING {
        delegFlag (0),
        mutualFlag (1),
        replayFlag (2),
        sequenceFlag (3),
        anonFlag (4),
        confFlag (5),
        integFlag (6)
    }
    """
    componentType = NamedValues(
        ('delegFlag', 0),
        ('mutualFlag', 1),
        ('replayFlag', 2),
        ('sequenceFlag', 3),
        ('anonFlag', 4),
        ('confFlag', 5),
        ('integFlag', 6)
    )


class NegStat(Enumerated):
    """
    [RFC-4178]

    NegState ::= ENUMERATED {
        accept-completed (0),
        accept-incomplete (1),
        reject (2),
        request-mic (3)
    }
    """
    namedValues = NamedValues(
        ('accept-complete', 0),
        ('accept-incomplete', 1),
        ('reject', 2),
        ('request-mic', 3)
    )
    subtypeSpec = Enumerated.subtypeSpec + SingleValueConstraint(0, 1, 2, 3)


class NegHints(Sequence):
    """
    [MS-SPNG] v14.0 2017-09-15

    2.2.1 NegTokenInit2
    NegHints is an extension of NegTokenInit.

    NegHints ::= SEQUENCE {
        hintName[0] GeneralString OPTIONAL,
        hintAddress[1] OCTET STRING OPTIONAL
    }
    """
    componentType = NamedTypes(
        OptionalNamedType(
            'hintName', GeneralString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 0)
            )
        ),
        OptionalNamedType(
            'hintAddress', OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 1)
            )
        )
    )


class NegTokenInit(Sequence):
    """
    [RFC-4178]

    NegTokenInit ::= SEQUENCE {
        mechTypes [0] MechTypeList,
        regFlags [1] ContextFlags OPTIONAL,
        mechToken [2] OCTET STRING OPTIONAL,
        mechListMIC [3] OCTER STRING OPTIONAL,
        ...
    }
    """
    componentType = NamedTypes(
        NamedType(
            'mechTypes', MechTypeList().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 0)
            )
        ),
        OptionalNamedType(
            'reqFlags', ContextFlags().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 1)
            )
        ),
        OptionalNamedType(
            'mechToken', OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 2)
            )
        ),
        OptionalNamedType(
            'mechListMIC', OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 3)
            )
        )
    )


class NegTokenInit2(Sequence):
    """
    [MS-SPNG] v14.0 2017-09-15

    2.2.1 NegTokenInit2
    NegTokenInit2 is the message structure that extends NegTokenInit with a
    negotiation hints (negHints) field. On a server initiated SPNEGO process,
    it sends negTokenInit2 message instead of just the plain NegTokenInit.

    NegTokenInit2 ::= SEQUENCE {
        mechTypes [0] MechTypeList OPTIONAL,
        reqFlags [1] ContextFlags OPTIONAL,
        mechToken [2] OCTET STRING OPTIONAL,
        negHints [3] NegHints OPTIONAL,
        mechListMIC [4] OCTET STRING OPTIONAL,
        ...
    }
    """
    componentType = NamedTypes(
        OptionalNamedType(
            'mechTypes', MechTypeList().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 0)
            )
        ),
        OptionalNamedType(
            'reqFlags', ContextFlags().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 1)
            )
        ),
        OptionalNamedType(
            'mechToken', OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 2)
            )
        ),
        OptionalNamedType(
            'negHints', NegHints().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 3)
            )
        ),
        OptionalNamedType(
            'mechListMIC', OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 4)
            )
        ),
    )


class NegTokenResp(Sequence):
    """
    [RFC-4178]

    4.2.2 negTokenResp
    The response message for NegTokenInit.

    NegTokenResp ::= SEQUENCE {
        negStat [0] NegState OPTIONAL,
        supportedMech [1] MechType OPTIONAL,
        responseToken [2] OCTET STRING OPTIONAL,
        mechListMIC {3] OCTET STRING OPTIONAL,
        ...
    }
    """
    componentType = NamedTypes(
        OptionalNamedType(
            'negStat', NegStat().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 0)
            )
        ),
        OptionalNamedType(
            'supportedMech', ObjectIdentifier().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 1)
            )
        ),
        OptionalNamedType(
            'responseToken', OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 2)
            )
        ),
        OptionalNamedType(
            'mechListMIC', OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 3)
            )
        )
    )


class NegotiateToken(Choice):
    """
    [RFC-4178]

    NegotiateToken ::= CHOICE {
        negTokenInit [0] NegTokenInit,
        negTokenResp [1] NegTokenResp
    }
    """
    componentType = NamedTypes(
        NamedType(
            'negTokenInit', NegTokenInit2().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 0)
            )
        ),
        NamedType(
            'negTokenResp', NegTokenResp().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 1)
            )
        )
    )


class InitialContextToken(Sequence):
    """
    [RFC-2743]

    3.1. Mechanism-Independent Token Format
    This section specifies a mechanism-independent level of encapsulating
    representation for the initial token of a GSS-API context establishment
    sequence.

    InitialContextToken ::= [APPLICATION 0] IMPLICIT SEQUENCE {
        thisMech MechType,
        innerContextToken NegotiateToken
    }
    """
    componentType = NamedTypes(
        NamedType(
            'thisMech', ObjectIdentifier()
        ),
        NamedType(
            'innerContextToken', NegotiateToken()
        )
    )
    tagSet = TagSet(
        Sequence.tagSet,
        Tag(tagClassApplication, tagFormatConstructed, 0),
    )
