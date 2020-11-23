# Smbprotocol Integration Tests

This directory contains files that cna be used for more complex integration tests that aren't easily covered in CI.

It current achieves this by creating a bunch of virtual machines using Vagrant, configuring those hosts using Ansible
then running the tests on the various hosts using Ansible.

### Environment

The environment consists of:

##### Servers

- `CENTOS8` - Linux test host
- `DC01` - Domain Controller, Windows Server 2019
- `SERVER2012R2` - Windows test host, Windows Server 2012 R2
- `SERVER2019` - Server with DFS share, Windows Server 2019

All Windows boxes are joined to the `smb.test` (`SMB`) domain.

##### Users

- `vagrant`:`vagrant` - local administrator user on all hosts
- `SMB\smb`:`Password01` - domain user

#### Running tests

To run these tests run the following:

```bash
# Setup the virtual machine in either Libvirt or VirtualBox
vagrant up

# Configure the virtual machines and get them ready for the tests
ansible-playbook -i inventory.yml main.yml -vv

# Run the tests
ansible-playbook -i inventory.yml tests.yml -vv
```

When running `main.yml` it will prompt for the Azure Pipelines artifacts URL to use as the compiled source of smbprotocol.
This URL can be gotten by clicking on the published artifacts of a CI run and getting the URL for the `wheels
artifact.

The following tags are set for `main.yml`

* `template`: Re-template the test files to the test hosts

The following tags are set for `tests.yaml`

* `linux`: Run the tests on the Linux hosts only
* `windows`: Run the tests on the Windows hosts only
