#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os

from setuptools import setup


def abs_path(rel_path):
    return os.path.join(os.path.dirname(__file__), rel_path)


with open(abs_path('README.md'), mode='rb') as fd:
    long_description = fd.read().decode('utf-8')


setup(
    name='smbprotocol',
    version='1.7.0',
    packages=['smbclient', 'smbprotocol'],
    install_requires=[
        'cryptography>=2.0',
        'pyspnego',
    ],
    extras_require={
        'kerberos:sys_platform=="win32"': [],
        'kerberos:sys_platform!="win32"': [
            'gssapi>=1.4.1',
        ],
    },
    python_requires='>=3.6',
    author='Jordan Borean',
    author_email='jborean93@gmail.com',
    url='https://github.com/jborean93/smbprotocol',
    description='Interact with a server using the SMB 2/3 Protocol',
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords='smb smb2 smb3 cifs python',
    license='MIT',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
)
