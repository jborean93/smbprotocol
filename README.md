# smbprotocol
SMBv2 and v3 Client for both Python 2 and 3.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jborean93/smbprotocol/blob/master/LICENSE)
[![Travis Build](https://travis-ci.org/jborean93/smbprotocol.svg)](https://travis-ci.org/jborean93/smbprotocol)
[![AppVeyor Build](https://ci.appveyor.com/api/projects/status/github/jborean93/smbprotocol?svg=true)](https://ci.appveyor.com/project/jborean93/smbprotocol)
[![Coverage](https://coveralls.io/repos/jborean93/smbprotocol/badge.svg)](https://coveralls.io/r/jborean93/smbprotocol)

SMB is a network file sharing protocol and has numerous iterations over the
years. This library implements the SMBv2 and SMBv3 protocol based on the
[MS-SMB2](https://msdn.microsoft.com/en-us/library/cc246482.aspx) document.


## Features

* Negotiation of the SMB 2.0.2 protocol to SMB 3.1.1 (Windows 10/Server 2016)
* Authentication with both NTLM and Kerberos
* Message signing
* Message encryption (SMB 3.x.x+)
* Connect to a Tree/Share
* Opening of files, pipes and directories
* Set create contexts when opening files
* Read and writing of files and pipes
* Sending IOCTL commands
* Sending of multiple messages in one packet (compounding)

This is definitely not feature complete as SMB is quite a complex protocol, see
backlog for features that would be nice to have in this library.


## Requirements

* Python 2.6, 2.7, 3.4+
* For Kerberos auth [python-gssapi](https://github.com/pythongssapi/python-gssapi)

To use Kerberos authentication, further dependencies are required, to install
these dependencies run

```
# for Debian/Ubuntu/etc:
sudo apt-get install gcc python-dev libkrb5-dev
pip install smbprotocol[kerberos]

# for RHEL/CentOS/etc:
sudo yum install gcc python-devel krb5-devel krb5-workstation python-devel
pip install smbprotocol[kerberos]
```

Currently Kerberos authentication is not supported on Windows. As part of this
optional extra, the python-gssapi library is installed and smbprotocol requires
a particular GSSAPI extension to be available to work. This extension should
be installed on the majority of MIT or Heimdall Kerberos installs but it isn't
guaranteed. To verify that Kerberos is available you can run the following
check in a Python console

```
try:
    from gssapi.raw import inquire_sec_context_by_oid
    print("python-gssapi extension is available")
except ImportError as exc:
    print("python-gssapi extension is not available: %s" % str(exc))
```

If it isn't available, then either a newer version of the system's gssapi
implementation needs to be setup and python-gssapi compiled against that newer
version.


## Installation

To install smbprotocol, simply run

```
pip install smbprotocol

# on a non Windows host, to install with Kerberos support
pip install smbprotocol[kerberos]
```

This will download the required packages that are used in this package and get
your Python environment ready to go.


## Additional Info

One of the first steps as part of the SMB protocol is to negotiate the dialect
used and other features that are available. Currently smbprotocol supports
the following dialects;

* `2.0.0`: Added with Server 2008/Windows Vista
* `2.1.0`: Added with Server 2008 R2/Windows 7
* `3.0.0`: Added with Server 2012/Windows 8
* `3.0.2`: Added with Server 2012 R2/Windows 8.1
* `3.1.1`: Added with Server 2016/Windows10

Each dialect adds in more features to the protocol where some are minor but
some are major. One major changes is in Dialect 3.x where it added message
encryption. Message encryption is set to True by default and needs to be
overridden when creating a Session object for the older dialects.

By default, the negotiation process will use the latest dialect that is
supported by the server but this can be overridden if required. When this is
done by the following code

```
import uuid

from smbprotocol.connection import Connection, Dialects

connection = Connection(uuid.uuid4(), "server", 445)
connection.connect(Dialects.SMB_3_0_2)
```

While you shouldn't want to downgrade to an earlier version, this does allow
you to set a minimum dialect version if required.


## Examples

Currently the existing classes expose a very low level interface to the SMB
protocol which can make things quite complex for people starting to use this
package. I do plan on making a high-level interface to make things easier for
users but that's in the backlog.

For now, the `examples` folder contains some examples of how this package can
be used.


## Logging

This library makes use of the builtin Python logging facilities. Log messages
are logged to the `smbprotocol` named logger as well as `smbprotocol.*` where
`*` is each python script in the `smbprotocol` directory.

These logs are really useful when debugging issues as they give you a more
step by step snapshot of what it is doing and what may be going wrong. The
debug side will also print out a human readable string of each SMB packet that
is sent out from the client so it can get very verbose.


## Testing

To this module, you need to install some pre-requisites first. This can be done
by running;

```
pip install -r requirements-test.txt

# you can also run tox by installing tox
pip install tox
```

From there to run the basic tests run;

```
py.test -v --pep8 --cov smbprotocol --cov-report term-missing

# or with tox 2.7, 2.7, 3.4, 3.5, and 3.6
tox
```

There are extra tests that only run when certain environment variables are set.
To run these tests set the following variables;

* `SMB_USER`: The username to authenticate with
* `SMB_PASSWORD`: The password to authenticate with
* `SMB_SERVER`: The IP or hostname of the server to authenticate with
* `SMB_PORT`: The port the SMB server is listening on, default is `445`
* `SMB_SHARE`: The name of the share to connect to, a share with this name must exist as well as a share with the name`$SMB_SHARE-encrypted` must also exist that forces encryption

From here running `tox` or `py.test` with these environment variables set will
activate the integration tests.

To set up a Windows host that will work with these tests run the following in
PowerShell;

```powershell
New-Item -Path C:\share -ItemType Directory > $null
New-Item -Path C:\share-encrypted -ItemType Directory > $null
New-SmbShare -Name $env:SMB_SHARE -Path C:\share -EncryptData $false -FullAccess Everyone > $null
New-SmbShare -Name "$($env:SMB_SHARE)-encrypted" -Path C:\share-encrypted -EncryptData $true -FullAccess Everyone > $null
```

This requires either Windows 10 or Server 2016 as they support Dialect 3.1.1
which is required by the tests.

If you don't have access to a Windows host, you can use Docker to setup a
Samba container and use that as part of the tests. To do so run the following
bash commands;

```bash
export SMB_USER=smbuser
export SMB_PASSWORD=smbpassword
export SMB_PORT=445
export SMB_SERVER=127.0.0.1
export SMB_SHARE=share

docker run -d -p $SMB_PORT:445 -v $(pwd)/build-scripts:/app -w /app -e SMB_USER=$SMB_USER -e SMB_PASSWORD=$SMB_PASSWORD -e SMB_SHARE=$SMB_SHARE centos:7 /bin/bash /app/setup_samba.sh;
```


## Backlog

Here is a list of features that I would like to incorporate, PRs are welcome
if you want to implement them yourself;

* SSPI integration for Windows and Kerberos authentication
* Test and support DFS mounts and not just server shares
* Multiple channel support to speed up large data transfers
* Create an easier API on top of the `raw` SMB calls that currently exist
* Lots and lots more...
