#!/bin/bash -ex

# Set by GHA setup-python
if [[ -n "${pythonLocation}" ]]; then
    PATH="${pythonLocation}/bin:${PATH}"
fi

source ./build_helpers/lib.sh

if [[ "$#" == 0 ]]; then
    set "$@" requirements lint tests coverage
fi

while [[ "$#" > 0 ]]; do
    case "$1" in
    "requirements")
        lib::requirements::install
        ;;
    "lint")
        lib::sanity::run
        ;;
    "tests")
        lib::coverage::erase
        lib::server::start
        lib::tests::run
        lib::server::stop
        ;;
    "coverage")
        lib::coverage::combine
        ;;
    esac
    shift
done
