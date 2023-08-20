import logging
import os
import time
import uuid

from smbprotocol.connection import Connection

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def test_connection(server, port):
    conn = Connection(uuid.uuid4(), server, port=port)
    log.info("Opening connection to %s:%d", server, port)
    conn.connect(timeout=5)
    conn.disconnect(True)


if __name__ == "__main__":
    server = os.environ.get("SMB_SERVER", "127.0.0.1")
    port = int(os.environ.get("SMB_PORT", 445))
    log.info("Waiting for SMB server to be online")

    attempt = 1
    total_attempts = 20
    while attempt < total_attempts:
        log.info("Starting attempt %d", attempt)
        try:
            test_connection(server, port)
            break
        except Exception as e:
            log.info("Connection attempt %d failed: %s", attempt, e)
            attempt += 1
            if attempt == total_attempts:
                raise Exception("Timeout while waiting for SMB server to come online") from e

            log.info("Sleeping for 5 seconds before next attempt")
            time.sleep(5)

    log.info("Connection successful")
