import logging

log = logging.getLogger(__name__)


class OpenFile(object):

    def __init__(self):
        """
        [MS-SMB2] v53.0 2017-09-15

        3.2.1.5 Per Open File
        For SMB 2.1+, for each opened file (distinguished by name), attributes
        for that open object
        """
        # Table of Opens to this file
        self.open_table = {}

        self.lease_key = None
        self.lease_state = None

        # SMB 3.x+
        # A squence number stored by the client to track lease state changes
        self.lease_epoch = None


class ApplicationOpenFile(object):

    def __init__(self):
        """
        ﻿[MS-SMB2] v53.0 2017-09-15

        3.2.1.6 Per Application Open of a File
        Attributes per each open of a file of an application
        """
        self.file_id = None
        self.tree_connect = None
        self.connection = None
        self.oplocal_level = None
        self.durable = None
        self.file_name = None
        self.resilient_handle = None
        self.last_disconnect_time = None
        self.resilient_timeout = None
        self.operation_buckets = None

        # SMB 3.x+
        self.durable_timeout = None

        # Table of outstanding requests, lookup by Request.cancel_id,
        # message_id
        self.outstanding_requests = {}

        self.create_guid = None
        self.is_persistent = None
        self.desired_access = None
        self.share_mode = None
        self.create_options = None
        self.file_attributes = None
        self.create_disposition = None
