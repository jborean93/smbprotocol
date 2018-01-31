import logging

from smbprotocol.constants import Commands, Dialects, NtStatus, \
    ImpersonationLevel, \
    FilePipePrinterAccessMask, FileAttributes, CreateDisposition, \
    CreateAction, ShareAccess, CreateOptions, CloseFlags, ReadFlags, \
    ReadWriteChannel, WriteFlags
from smbprotocol.messages import SMB2CreateRequest, SMB2CreateResponse, \
    SMB2CloseRequest, SMB2CloseResponse, SMB2ReadRequest, SMB2ReadResponse, \
    SMB2WriteRequest, SMB2WriteResponse, SMB2FlushRequest, SMB2FlushResponse

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


class Open(object):

    def __init__(self):
        """
        ﻿[MS-SMB2] v53.0 2017-09-15

        3.2.1.6 Per Application Open of a File
        Attributes per each open of a file of an application
        """
        # properties available based on the file itself
        self.opened = False
        self.creation_time = None
        self.last_access_time = None
        self.last_write_time = None
        self.change_time = None
        self.allocation_size = None
        self.end_of_file = None
        self.file_attributes = None

        # properties used privately
        self.file_id = None
        self.tree_connect = None
        self.connection = None
        self.oplock_level = None
        self.durable = None
        self.file_name = None
        self.resilient_handle = None
        self.last_disconnect_time = None
        self.resilient_timeout = None

        # an array of entries used to maintain information about outstanding
        # lock and unlock operations performed on resilient Opens. Contains
        #     sequence_number - 4-bit integer modulo 16
        #     free - boolean value where False is no outstanding requests
        self.operation_buckets = []

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

    def open(self, tree_connect, file_name, impersonation_level,
             desired_access, file_attributes, share_access, create_disposition,
             create_options):
        create = SMB2CreateRequest()
        create['impersonation_level'] = impersonation_level
        create['desired_access'] = desired_access
        create['file_attributes'] = file_attributes
        create['share_access'] = share_access
        create['create_disposition'] = create_disposition
        create['create_options'] = create_options
        create['buffer_path'] = file_name.encode('utf-16-le')

        tree_connect.session.connection.send(create,
                                             Commands.SMB2_CREATE,
                                             tree_connect.session,
                                             tree_connect)
        response = tree_connect.session.connection.receive()
        create_response = SMB2CreateResponse()
        create_response.unpack(response['data'].get_value())

        self.file_id = create_response['file_id'].get_value()
        self.tree_connect = tree_connect
        self.connection = tree_connect.session.connection
        self.oplock_level = create_response['oplock_level'].get_value()
        self.durable = False
        self.resilient_handle = False
        self.last_disconnect_time = 0
        self.file_name = file_name

        if self.connection.dialect >= Dialects.SMB_3_0_0:
            self.desired_access = desired_access
            self.share_mode = share_access
            self.create_options = create_options
            self.file_attributes = file_attributes
            self.create_disposition = create_disposition

        self.creation_time = create_response['creation_time'].get_value()
        self.last_access_time = create_response['last_access_time'].get_value()
        self.last_write_time = create_response['last_write_time'].get_value()
        self.change_time = create_response['change_time'].get_value()
        self.allocation_size = create_response['allocation_size'].get_value()
        self.end_of_file = create_response['end_of_file'].get_value()
        self.file_attributes = create_response['file_attributes'].get_value()
        self.opened = True

    def read(self, offset, length, min_length=0, unbuffered=False):
        read = SMB2ReadRequest()

        if unbuffered:
            if self.connection.dialect < Dialects.SMB_3_0_2:
                raise Exception("Unbuffered read is not available on the "
                                "negotiated dialect, requires SMB 3.0.2 or "
                                "newer")
            read['flags'].set_flag(ReadFlags.SMB2_READFLAG_READ_UNBUFFERED)

        read['length'] = length
        read['offset'] = offset
        read['minimum_count'] = min_length
        read['file_id'] = self.file_id
        read['padding'] = b"\x50"

        # deal with length greater than connection max size
        self.connection.send(read, Commands.SMB2_READ,
                             self.tree_connect.session, self.tree_connect)
        response = self.connection.receive()
        read_response = SMB2ReadResponse()
        read_response.unpack(response['data'].get_value())

        return read_response['buffer'].get_value()

    def write(self, data, offset=0, write_through=False, unbuffered=False):
        # handle data over max write size
        write = SMB2WriteRequest()
        write['length'] = len(data)
        write['offset'] = offset
        write['file_id'] = self.file_id
        write['data_offset'] = 0x70
        write['buffer'] = data
        if write_through:
            if self.connection.dialect < Dialects.SMB_2_1_0:
                raise Exception("Write through is not available on the "
                                "negotiated dialect, required SMB 2.1.0 or "
                                "newer")
            write['flags'].set_flag(WriteFlags.SMB2_WRITEFLAG_WRITE_THROUGH)

        if unbuffered:
            if self.connection.dialect < Dialects.SMB_3_0_2:
                raise Exception("Unbuffered write is not available on the "
                                "negotiated dialect, requires SMB 3.0.2 or "
                                "newer")
            write['flags'].set_flag(WriteFlags.SMB2_WRITEFLAG_WRITE_UNBUFFERED)

        self.connection.send(write, Commands.SMB2_WRITE,
                             self.tree_connect.session, self.tree_connect)
        response = self.connection.receive()
        write_response = SMB2WriteResponse()
        write_response.unpack(response['data'].get_value())
        return write_response['count'].get_value()

    def flush(self):
        flush = SMB2FlushRequest()
        flush['file_id'] = self.file_id

        self.connection.send(flush, Commands.SMB2_FLUSH,
                             self.tree_connect.session, self.tree_connect)
        response = self.connection.receive()
        flush_response = SMB2FlushResponse()
        flush_response.unpack(response['data'].get_value())

    def close(self, get_attributes):
        # if connection is NULL and durable is True, the client SHOULD attempt
        # to reconnect this open and the close retried
        # if connection is NULL and durable is False the client MUST fail the
        # close operation
        close = SMB2CloseRequest()
        close['file_id'] = self.file_id
        if get_attributes:
            close['flags'] = CloseFlags.SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB

        self.connection.send(close, Commands.SMB2_CLOSE,
                             self.tree_connect.session, self.tree_connect)
        response = self.connection.receive()
        c_resp = SMB2CloseResponse()
        c_resp.unpack(response['data'].get_value())

        # update the attributes if requested
        if get_attributes:
            self.creation_time = c_resp['creation_time'].get_value()
            self.last_access_time = c_resp['last_access_time'].get_value()
            self.last_write_time = c_resp['last_write_time'].get_value()
            self.change_time = c_resp['change_time'].get_value()
            self.allocation_size = c_resp['allocation_size'].get_value()
            self.end_of_file = c_resp['end_of_file'].get_value()
            self.file_attributes = c_resp['file_attributes'].get_value()
        self.opened = False
