#!/bin/bash -ex

source ./build_helpers/lib.sh

lib::setup::smb_server
lib::setup::python_requirements
lib::sanity::run
lib::tests::run
