# smbprotocol
SMBv2 and v3 Client for both Python 2 and 3.


[![Build Status](https://dev.azure.com/jborean93/jborean93/_apis/build/status/jborean93.smbprotocol?branchName=master)](https://dev.azure.com/jborean93/jborean93/_build/latest?definitionId=4&branchName=master)
[![codecov](https://codecov.io/gh/jborean93/smbprotocol/branch/master/graph/badge.svg)](https://codecov.io/gh/jborean93/smbprotocol)
[![PyPI version](https://badge.fury.io/py/smbprotocol.svg)](https://badge.fury.io/py/smbprotocol)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jborean93/smbprotocol/blob/master/LICENSE)

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
* Experimental support for both standalone and DFS server shares

This is definitely not feature complete as SMB is quite a complex protocol, see
backlog for features that would be nice to have in this library.


## Requirements

* Python 2.7, 3.5+
* For Kerberos auth on Linux
    * [python-gssapi](https://github.com/pythongssapi/python-gssapi)

To use Kerberos authentication on Linux, further dependencies are required, to install these dependencies run

```bash
# for Debian/Ubuntu/etc:
sudo apt-get install gcc python-dev libkrb5-dev
pip install smbprotocol[kerberos]

# for RHEL/CentOS/etc:
sudo yum install gcc python-devel krb5-devel krb5-workstation python-devel
pip install smbprotocol[kerberos]
```

Kerberos auth with Windows should just work out of the box with the `pyspnego` library but on Linux, the
`python-gssapi` library must be installed and `smbprotocol` requires a particular GSSAPI extension to be available to
work. This extension should be installed on the majority of MIT or Heimdal Kerberos installs but that is not a
guarantee. To verify that Kerberos is available on Linux you can run the following check in a Python console:

```python
try:
    from gssapi.raw import inquire_sec_context_by_oid
    print("python-gssapi extension is available")
except ImportError as exc:
    print("python-gssapi extension is not available: %s" % str(exc))
```

If it isn't available, then either a newer version of the system's gssapi implementation needs to be setup and
python-gssapi compiled against that newer version. In the absence of this extension, only NTLM auth is used.


## Installation

To install smbprotocol, simply run

```bash
pip install smbprotocol

# To install with Kerberos support
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

```python
import uuid

from smbprotocol.connection import Connection, Dialects

connection = Connection(uuid.uuid4(), "server", 445)
connection.connect(Dialects.SMB_3_0_2)
```

While you shouldn't want to downgrade to an earlier version, this does allow
you to set a minimum dialect version if required.


## Examples

There are 2 different APIs you can use with this library.0

* `smbprotocol`: Low level interface that can do whatever you want but quite verbose
* `smbclient`: Higher level interface that implements the builtin `os` and `os.path` file system functions but for SMB support

The `examples` folder contains some examples of both the high and low level
interface but for everyday user's it is recommended to use `smbclient` as it
is a lot simpler.

### smbclient Interface

The higher level interface `smbclient` is designed to make this library easier
for people to use for simple and common use cases. It is designed to replicate
the builtin `os` and `os.path` filesystem functions like `os.open()`,
`os.stat()`, and `os.path.exists()`. It is also designed to handle connections
to a DFS target unlike `smbprotocol`.

A connection made by `smbclient` is kept in a pool and re-used for future
requests to the same server until the Python process exists. This makes
authentication simple and only required for the first call to the server. Any
DFS referrals are also cached in that Python process. This optimises any
future requests to that same DFS namespace.

The functions in `smbclient` have a global config object that can be used to
set any connection defaults to use for any future connections. It can also be
used to specify any domain based DFS settings for more advanced setups. It is
recommended to use `ClientConfig()` to set any global credentials like so:

```python
import smbclient

smbclient.ClientConfig(username='user', password='password')
```

The `ClientConfig` is a singleton and any future instanciations of that
object will just update the keys being set. You can set the following keys on
the `ClientConfig`:

* `client_guid`: The client GUID to identify the client to the server on a new connection
* `username`: The default username to use when creating a new SMB session if explicit credentials weren't set
* `password`: The default password to use for authentication
* `domain_controller`: The domain controller hostname. This is useful for environments with DFS servers as it is used to identify the DFS domain information automatically
* `skip_dfs`: Whether to skip doing any DFS resolution, useful if there is a bug or you don't want to waste any roundtrip requesting referrals
* `auth_protocol`: The authentication protocol to use; `negotiate` (default), `kerberos`, or `ntlm`

As well as setting the default credentials on the `ClientConfig` you can also
specify the credentials and other connection parameters on each `smbclient`
function or when registering a new server. These functions accept the
following kwargs:

* `username`: The username used to connect to the share
* `password`: The password used to connect to the share
* `port`: Override the default port (`445`) to connect to
* `encrypt`: Whether to force encryption on the connection, requires SMBv3 or newer on the remote server (default: `False`)
* `connection_timeout`: Override the connection timeout in seconds (default: `60`)

If using Kerberos authentication and a Kerberos ticket has already set by
`kinit` then `smbclient` will automatically use those credentials without
having to be explicitly set. If no ticket has been retrieved or you wish to use
different credentials then set the default credentials on the `ClientConfig`
or specify `username` and `password` on the first request to the server.

For example I only need to set the credentials on the first request to create
the directory and not for the subsequent file creation in that dir.

```python
import smbclient

# Optional - specify the default credentials to use on the global config object
smbclient.ClientConfig(username='user', password='pass')

# Optional - register the credentials with a server (overrides ClientConfig for that server)
smbclient.register_session("server", username="user", password="pass")

smbclient.mkdir(r"\\server\share\directory", username="user", password="pass")

with smbclient.open_file(r"\\server\share\directory\file.txt", mode="w") as fd:
    fd.write(u"file contents")
```

If you wish to reset the cache you can either start a new Python process or
call `smbclient.reset_connection_cache()` to close all the connections that
have been cached by the client.


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

```bash
pip install -r requirements-test.txt

# you can also run tox by installing tox
pip install tox
```

From there to run the basic tests run;

```bash
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

This requires either Windows 10 or Server 2016 as they support Dialect 3.1.1
which is required by the tests.

If you don't have access to a Windows host, you can use Docker to setup a
Samba container and use that as part of the tests. To do so run the following
bash commands;

```bash
export SMB_USER=smbuser
export SMB_PASSWORD=smbpassword
export SMB_PORT=445
export SMB_SERVER=localhost
export SMB_SHARE=share

docker run \
    --detach \
    --rm \
    --privileged=true \
    -p $SMB_PORT:445 \
    -v $(pwd)/build-scripts:/app \
    -w /app \
    -e SMB_USER=$SMB_USER \
    -e SMB_PASSWORD=$SMB_PASSWORD \
    -e SMB_SHARE=$SMB_SHARE \
    centos:7 \
    /bin/bash /app/setup_samba.sh
```


## Backlog

Here is a list of features that I would like to incorporate, PRs are welcome
if you want to implement them yourself;

* Multiple channel support to speed up large data transfers
* Lots and lots more...
