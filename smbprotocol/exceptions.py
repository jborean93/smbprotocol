class InvalidFieldDefinition(Exception):
    pass


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
