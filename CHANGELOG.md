# Changelog

## 1.2.0 - TBD

* Added experimental support for DFS shares when using `smbclient` function
* Added `smbclient.ClientConfig()` to set global default options on new connections
* Moved the SMB Header structures to `smbprotocol.header`
* Added `null_terminated` option for a `TextField` value
* Fix broken pipe errors that occur on long running connections by sending a echo request for each connection session every 10 minutes

## 1.1.0 - 2020-08-14

* Speed up logging statements for large messages like a read and write message
* Changed authentication dep to [pyspnego](https://github.com/jborean93/pyspnego) that handles all the authentication work
* Fixed up authentication against hosts that don't present the initial GSSAPI token like Azure File Storage
* Added specific exception types for every `NtStatus` value to make it easier to catch only specific exceptions
* Added the following exceptions  to the list of known exception codes
    * `STATUS_NETWORK_NAME_DELETED`
    * `STATUS_NOT_FOUND`
    * `STATUS_PATH_NOT_COVERED`
    * `STATUS_DFS_UNAVAILABLE`
    * `STATUS_SERVER_UNAVAILABLE`
* Fix session key generation when creating a new session from an existing connection object


## 1.0.1 - 2019-12-12

* Fix issue when reading a large file that exceeds 65KB and raises `STATUS_END_OF_FILE`.
* Fix issue where `listdir`, `scandir`, `walk` would only enumerate a subset of entries in a directories with lots of sub files/folders


## 1.0.0 - 2019-11-30

* Dropped support for Python 2.6 and Python 3.4
* Added the `smbclient` package that provides a higher level API for interactive with SMB servers
* Deprecated `smbprotocol.query_info` in favour of `smbprotocol.file_info`, `query_info` will be removed in the next major release
* Add automatic symlink resolver when a symlink is in the path being opened
* Fix issue when trying to connect to host with IPv6 address
* Fix response parsing for SMB2 Create Response Lease V1 and V2
* Added the ability to set the Oplock level when opening a file
* Revamped the socket listener and message processor to run in a separate thread for faster message resolving
* Added the `FileSystemWatcher` in `change_notify.py` to provider a way to watch for changes on the SMB filesystem
* Added the `.cancel()` method onto a Request to cancel an SMB request on the server


## 0.2.0 - 2019-09-19

* Fix issue where timeout was not being applied to the new connection
* Fix various deprecated regex escape patterns
* Added support for Windows Kerberos and implicit credential support through the optional extra library [pywin32](https://github.com/mhammond/pywin32)
* Simplified the fallback NTLM context object


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
