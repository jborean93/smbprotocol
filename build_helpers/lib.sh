#!/bin/bash


lib::setup::smb_server() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Setting up SMB Server"
    fi

    if [ "$(expr substr $(uname -s) 1 5)" == "MINGW" ]; then
        echo "Running on Windows, configuring server"
        export SMB_SERVER=localhost
        export SMB_PORT=445
        export SMB_SHARE=share

        # Runs as a 32-bit process so we use sysnative to invoke the 64-bit PowerShell
        powershell.exe -NoLogo -NoProfile \
            -File ./build_helpers/win-setup.ps1 \
            -Name ${SMB_SHARE} \
            -Verbose

    elif [ "$(uname)" == "Darwin" ]; then
        echo "Running on macOS, no Docker available in CI, skipping integration tests"

    else
        echo "Running on Linux, configuring Samba in a Docker container"
        export SMB_SERVER=localhost
        export SMB_PORT=445
        export SMB_SHARE=share
        export SMB_USER=smbuser
        export SMB_PASSWORD=smbpass

        docker run \
            --detach \
            --rm \
            --publish ${SMB_PORT}:445 \
            --volume $( pwd )/build_helpers:/app:z \
            --workdir /app \
            fedora:36 \
            /bin/bash \
            /app/samba-setup.sh \
            ${SMB_SHARE} \
            ${SMB_USER} \
            ${SMB_PASSWORD}

    fi

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::setup::python_requirements() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Installing Python Requirements"
    fi

    python -m pip install --upgrade pip setuptools wheel

    echo "Installing smbprotocol"
    python -m pip install .

    echo "Installing dev dependencies"
    python -m pip install -r requirements-test.txt

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::sanity::run() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Running Sanity Checks"
    fi

    python -m pycodestyle \
        . \
        --verbose \
        --show-source \
        --statistics

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::tests::run() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Running Tests"
    fi

    # Make sure the SMB server is up and available before running the tests
    if [ -n "${SMB_SERVER+set}" ]; then
        python ./build_helpers/check-smb.py
    fi

    python -m pytest \
        --verbose \
        --junitxml junit/test-results.xml \
        --cov smbclient \
        --cov smbprotocol \
        --cov-report xml \
        --cov-report term-missing

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}
