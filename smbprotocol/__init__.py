# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import logging

try:
    from logging import NullHandler
except ImportError:  # pragma: no cover
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

logger = logging.getLogger(__name__)
logger.addHandler(NullHandler())


MAX_PAYLOAD_SIZE = 65536


class Commands(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.1.2 SMB2 Packet Header - SYNC Command
    The command code of an SMB2 packet, it is used in the packet header.
    """
    SMB2_NEGOTIATE = 0x0000
    SMB2_SESSION_SETUP = 0x0001
    SMB2_LOGOFF = 0x0002
    SMB2_TREE_CONNECT = 0x0003
    SMB2_TREE_DISCONNECT = 0x0004
    SMB2_CREATE = 0x0005
    SMB2_CLOSE = 0x0006
    SMB2_FLUSH = 0x0007
    SMB2_READ = 0x0008
    SMB2_WRITE = 0x0009
    SMB2_LOCK = 0x000A
    SMB2_IOCTL = 0x000B
    SMB2_CANCEL = 0x000C
    SMB2_ECHO = 0x000D
    SMB2_QUERY_DIRECTORY = 0x000E
    SMB2_CHANGE_NOTIFY = 0x000F
    SMB2_QUERY_INFO = 0x0010
    SMB2_SET_INFO = 0x0011
    SMB2_OPLOCK_BREAK = 0x0012


class Dialects(object):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.3 SMB2 NEGOTIATE Request Dialects
    16-bit integeres specifying an SMB2 dialect that is supported. 0x02FF is
    used in the SMBv1 negotiate request to say that dialects greater than
    2.0.2 is supported.
    """
    SMB_2_0_2 = 0x0202
    SMB_2_1_0 = 0x0210
    SMB_3_0_0 = 0x0300
    SMB_3_0_2 = 0x0302
    SMB_3_1_1 = 0x0311
    SMB_2_WILDCARD = 0x02FF
