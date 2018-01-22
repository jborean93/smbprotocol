import logging

from smbprotocol.constants import Commands, NtStatus, ImpersonationLevel, \
    FilePipePrinterAccessMask, FileAttributes, CreateDisposition, \
    CreateAction, ShareAccess, CreateOptions
from smbprotocol.messages import SMB2CreateRequest, SMB2CreateResponse, \
    SMB2CloseRequest, SMB2CloseResponse

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

    def open_file(self, tree_connect, path):
        create = SMB2CreateRequest()
        create['impersonation_level'] = ImpersonationLevel.Impersonation
        create['desired_access'] = FilePipePrinterAccessMask.FILE_READ_DATA
        create['file_attributes'] = FileAttributes.FILE_ATTRIBUTE_NORMAL
        create['share_access'] = ShareAccess.FILE_SHARE_DELETE | \
            ShareAccess.FILE_SHARE_READ | \
            ShareAccess.FILE_SHARE_WRITE
        create['create_disposition'] = CreateDisposition.FILE_OPEN
        create['create_options'] = CreateOptions.FILE_NON_DIRECTORY_FILE
        create['buffer_path'] = path.encode('utf-16-le')

        header = tree_connect.session.connection.send(create,
                                                      Commands.SMB2_CREATE,
                                                      tree_connect.session,
                                                      tree_connect)
        response = tree_connect.session.connection.receive()
        create_response = SMB2CreateResponse()
        create_response.unpack(response['data'].get_value())


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
