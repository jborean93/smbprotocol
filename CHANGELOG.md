# Changelog

## 0.0.1 (Unreleased)

Initial release of smbprotocol, it contains the following features

* Support for Dialect 2.0.2 to 3.1.1
* Supports message encryption and signing
* Works with both NTLM and Kerberos auth (latter requiring a non-builtin
  library)
* Open files, directories and pipes
* Open command with create_contexts to set extra attributes on an open
* Read/Write the files
* Send IOCTL commands
