import os
import time
import uuid

from smbprotocol.connection import Connection


def test_connection(server, port):
    """
    Test if a simple connection

    Args:
        server: (str): write your description
        port: (int): write your description
    """
    conn = Connection(uuid.uuid4(), server, port=port)
    print("Opening connection to %s:%d" % (server, port))
    conn.connect(timeout=5)
    try:
        print("Connection successful, sending ECHO request")
        conn.echo()
    finally:
        conn.disconnect(True)


if __name__ == '__main__':
    server = os.environ.get("SMB_SERVER", "127.0.0.1")
    port = int(os.environ.get("SMB_PORT", 445))
    print("Waiting for Docker container SMB server to be online")

    attempt = 1
    total_attempts = 20
    while attempt < total_attempts:
        print("Starting attempt %d" % attempt)
        try:
            test_connection(server, port)
            break
        except Exception as e:
            print("Connection attempt %d failed: %s" % (attempt, str(e)))
            attempt += 1
            if attempt == total_attempts:
                raise Exception("Timeout while waiting for SMB server to come "
                                "online")

            print("Sleeping for 5 seconds before next attempt")
            time.sleep(5)

    print("Connection successful")
