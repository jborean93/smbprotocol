#!/bin/bash -ex

# Set by GHA setup-python
if [[ -n "${pythonLocation}" ]]; then
  PATH="${pythonLocation}/bin:${PATH}"
fi

source ./build_helpers/lib.sh

if [[ "$#" == 0 ]]; then
  set "$@" requirements lint coverage-erase start-server tests stop-server coverage-combine
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
    lib::tests::run
    ;;
  "start-server")
    lib::server::start
    ;;
  "stop-server")
    lib::server::stop
    ;;
  "erase-coverage")
    lib::coverage::erase
    ;;
  "combine-coverage")
    lib::coverage::combine
    ;;
  esac
  shift
done
