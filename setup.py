#!/usr/bin/env python
# coding: utf-8

from setuptools import setup

# PyPi supports only reStructuredText, so pandoc should be installed
# before uploading package
try:
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
except ImportError:
    long_description = ''


setup(
    name='smbprotocol',
    version='0.1.0',
    packages=['smbprotocol'],
    install_requires=[
        'cryptography>=2.0',
        'ntlm-auth',
        'pyasn1',
        'six',
    ],
    extras_require={
        ':python_version<"2.7"': [
            'ordereddict'
        ],
        'kerberos:sys_platform=="win32"': [],
        'kerberos:sys_platform!="win32"': [
            'gssapi>=1.4.1'
        ]
    },
    author='Jordan Borean',
    author_email='jborean93@gmail.com',
    url='https://github.com/jborean93/smbprotocol',
    description='Interact with a server using the SMB 2/3 Protocol',
    long_description=long_description,
    keywords='smb smb2 smb3 cifs python',
    license='MIT',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
)
