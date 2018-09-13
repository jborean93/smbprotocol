# Changelog

## 0.1.1 - 2018-09-14

* Fix initial negotiate message not setting connection timeout value
* Fix endless loop when running a compound message that failed


## 0.1.0 - 2018-03-07

Initial release of smbprotocol, it contains the following features

* Support for Dialect 2.0.2 to 3.1.1
* Supports message encryption and signing
* Works with both NTLM and Kerberos auth (latter requiring a non-windows
  library)
* Open files, directories and pipes
* Open command with create_contexts to set extra attributes on an open
* Read/Write the files
* Send IOCTL commands
* Sending of multiple messages in one packet (compounding)
