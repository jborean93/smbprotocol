# Changelog

## 1.14.0 - 2024-08-26

* Dropped support for Python 3.7
* `SMBDirEntryInformation.last_write_time` is now annotated as `datetime.datetime`. Previously, it was `datetime.date`.  https://github.com/jborean93/smbprotocol/issues/279

## 1.13.0 - 2024-03-21

* Added the property `smb_info` on `SMBDirEntry` which returns a named tuple `SMBDirEntryInformation` containing metadata already retrieved in the `scandir` operation.
  * This avoid having to call `stat()` to retrieve data like the file attributes or datetime fields that is already available
* Ensure `DateTimeField` values are set to `UTC` timezones as FILETIME values are in UTC
* Stop using `datetime.datetime.utcfromtimestamp()` as it has been deprecated
* Added default timeout for disconnect operations for 60 seconds to ensure the process doesn't hang forever when closing a broken connection
* `smbprotocol.connection.Connection.disconnect()` now waits (with a timeout) for the message processing threads to be stopped before returning.
* Do not set the SMB SessionId and TreeId in the headers to `0xFFFFFFFF` for related compound requests
+ Ensures the source file for `shutil.copyfile` is opened with `share_access="r"` for better compatibility with files already opened by something else
+ Remove endless authentication loop when the context is complete and no more input messages are needed

## 1.12.0 - 2023-11-09

* Added the `DiskFull` error and message for the NTSTATUS code `0xC000007F` - https://github.com/jborean93/smbprotocol/pull/245

## 1.11.0 - 2023-09-06

* Fix up pre authenticated session id lookups that were failing with Linux ksmbd
* Removes `logging.NullHandler()` being set in the root `smbprotocol` namespace
* Adds basic support for remote to local and vice versa file operations with `smbclient.shutil.copytree`
* Fixes DFS infinite recursion error when dealing with a file that does not exist on a DFS namespace

## 1.10.1 - 2022-11-14

* Raise the original `BadNetworkName` error if the server doesn't indicate it supports DFS or `FSDriverRequired` was raised trying to lookup the DFS information - https://github.com/jborean93/smbprotocol/issues/196
* Fix pre auth session id tracking if the intermediate token messages return 0 as the session id

## 1.10.0 - 2022-11-07

* Require Python 3.7 or newer (dropped 3.6)
* Created PEP 517 compliant package
* Moved all setuptools configuration, except extension information, to `pyproject.toml`
* Migrated project layout to a `src` based structure rather than including it in the project root
* Allow `smbclient.copyfile` to copy files on the same server and not just the same share
* Improve DFS opens by setting the DFS operation header flag when opening a file on a share marked as a DFS share
* Fix negotiate request padding when using a hostname with a length of 8 characters

## 1.9.0 - 2022-02-01

* Fix connection cache reuse for some DFS referral requests
* Add `smbclient.path` to the `smbclient` import allowing `import smbclient; smbclient.path.func()`


## 1.8.3 - 2021-11-19

* Set `additional_information` field in `SMB2SetInfoRequest` to a flags field rather than a single enum as per protocol docs


## 1.8.2 - 2021-11-03

* Add missing `FileAttributes` enum values
* Set messages with `FileAttributes` to be non-strict allowing unknown values in the future to be parsed without an error


## 1.8.1 - 2021-10-27

* Raises `ObjectPathNotFound` if a DFS referral is required but not referrals are available (https://github.com/jborean93/smbprotocol/pull/149)


## 1.8.0 - 2021-10-21

* Added support for 256bit keyed encryption ciphers
* Added support for signing with AES GCM
* Now sends the `SMB2_NETNAME_NEGOTIATE_CONTEXT_ID` with the negotiate request
* Adds the Python requirement of [pykrb5](https://github.com/jborean93/pykrb5) for Kerberos support on non-Windows
* Fix unpacking security descriptor ACEs with extra data on the end - https://github.com/jborean93/smbprotocol/pull/143
* Set `index_number` in `FileInternalInformation` to be an unsigned integer to match the other structures
* Clear out expired DFS referrals to avoid memory leaks and stale DFS information - https://github.com/jborean93/smbprotocol/issues/136


## 1.7.0 - 2021-09-22

* Improve connection health checks to reduce the occurances of an infinite deadlock
* Added more exception error classes
* Added `create_action` to the `Open` object that describes how the file was opened
* Added `follow_symlinks` option to `SMBDirEntry.from_path` to control whether the entry is based on the path or the link target (if there is one)


## 1.6.2 - 2021-08-16

* Fix up cached credential logic when setting `domain_controller` in the initial config singleton


## 1.6.1 - 2021-07-29

* Remove `print()` statement that was used during testing


## 1.6.0 - 2021-07-28

* Dropped support for Python 2.7 and 3.5
* Add performance improvement on reads with large files
* Added the `require_signing` kwarg to `smbclient.register_session()` to allow the caller to control whether signing is required on the connection or not
* Fix `OverflowError` when handling FILETIME values beyond the year 9999 - caps the value to `9999-12-31` due to a Python limitation
* Fix up credit charge calculation which causes a `STATUS_INVALID_PARAMETER` response for certain read/write lengths
* Ensure responses with a failure are cleaned up from the outstanding request table to avoid memory leaks


## 1.5.1 - 2021-05-08

* Unified DFS path handling when using any API that uses a transaction to open the file
  * This includes `smbclient.rename` and `smbclient.replace`
* Fixed up `smbclient.rename` to work with directories
* `smbclient.scandir` will continue to use the connection cache when getting stat information of a dir entry
* `smbclient.shutil.rmtree` will continue to use the connection cache when removing child entries


## 1.5.0 - 2021-03-25

* Added `smbprotocol.exceptions.SMBConnectionClosed` that is raised when trying to send or receive data on a connection that has been closed
* Added `smbprotocol.exceptions.WrongPassword` that is raised when some servers indicate the password is not correct or the account is locked out
* Do not attempt to reuse any cached connections that have been closed in `smbclient`
* Added a lock when writing to the socket, only 1 thread can write a message at a single point in time
* Revamped the SMB receiver code to simplify the logic and make it more durable
    * Removed the TCP recv thread for each connection, now each connection uses just 1 thread instead of 2
    * Be more defensive when reading data from a socket to ensure we get all the data we require
    * Handled server side FIN packets that close the connection unexpectedly, any requests waiting for a response will raise `SMBConnectionClosed`


## 1.4.0 - 2021-02-02

* Fixed up secure negotiation logic when connecting to older SMB dialects
* Will attempt to perform secure negotiation even on older dialects that may not implement it properly
* Added `ClientConfig` option `require_secure_negotiate` to globally turn off secure negotiation if the client wishes
* Fix explicit `ntlm` or `kerberos` authentication when the server response with the initial SPNEGO mech list token


## 1.3.0 - 2021-01-23

* Changed initial credit request from `256` to `64` when creating the SMB session
    * This is done to avoid overloading the SMB server
    * If `smbclient` requires more credits to perform an operation it will request it automatically
* Improve credit handling when reading and writing large amounts of data to reduce the number of requests being made
* Fixed up `write()` in `smbclient.open_file()` to be able to write bytes greater than the `max_write_size`
* Fixed issue when receiving an unknown NtStatus error code from the server
* Added `PipeBusy` exception for `STATUS_PIPE_NOT_AVAILABLE 0xC00000AD` error responses
* Fix credit granting calculation when receiving a compound response
    * Original logic granted `len(responses) - 1` credits than what the server actually given causing errors when the client ran out of credits without it knowing
* Added `auth_protocol` to `Session`, `ClientConfig`, and `register_session()` to control what authentication protocol is used
    * This can be `negotiate` (default), `kerberos`, or `ntlm` where `negotiate` selects `kerberos` or `ntlm` depending on what's available


## 1.2.0 - 2020-09-22

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
