from smbprotocol.structure import BytesField, IntField, ListField, Structure

try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict


class SMBResponseException(Exception):

    @property
    def header(self):
        return self.args[0]

    @property
    def status(self):
        return self.args[1]

    @property
    def message_id(self):
        return self.args[2]

    @property
    def message(self):
        error_message = "%s: %s"\
                        % (str(self.header['status']), hex(self.status))

        # error = SMB2ErrorResponse()
        # error.unpack(self.header['data'].get_value())
        # byte_count = error['byte_count'].get_value()
        # if byte_count != 0:
        #    # TODO: add code to parse this error
        #    error_data = ""

        return "Received unexpected status from the server: %s" % error_message

    def __str__(self):
        return self.message


class SMB2ErrorResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.2 SMB2 Error Response
    The SMB2 Error Response packet is sent by the server to respond to a
    request that has failed or encountered an error. This is only used in the
    SMB 3.1.1 dialect and this code won't decode values based on older versions
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('structure_size', IntField(
                size=2,
                default=9,
            )),
            ('error_context_count', IntField(
                size=1,
                default=lambda s: len(s['error_data'].get_value()),
            )),
            ('reserved', IntField(size=1)),
            ('byte_count', IntField(
                size=4,
                default=lambda s: len(s['error_data']),
            )),
            ('error_data', ListField(
                size=lambda s: s['byte_count'].get_value(),
                list_count=lambda s: s['error_context_count'].get_value(),
                unpack_func=lambda s, d: self._error_data_value(s, d)
            )),
        ])
        super(SMB2ErrorResponse, self).__init__()

    def _error_data_value(self, structure, data):
        # parse raw bytes into a list we can iterate through
        # TODO: add code to parse data into a list
        return []


class SMB2ErrorContextResponse(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.2.2.1 SMB2 ERROR Context Response
    For the SMB dialect 3.1.1, the server formats the error data as an array of
    SMB2 Error Context structures in the SMB2ErrorResponse message.

    """

    def __init__(self):
        self.fields = OrderedDict([
            ('error_data_length', IntField(
                size=4,
                default=lambda s: len(s['error_context_data']),
            )),
            ('error_id', IntField(size=4)),
            ('error_context_data', BytesField(
                size=lambda s: s['error_data_length'].get_value(),
            )),
        ])
        super(SMB2ErrorContextResponse, self).__init__()
