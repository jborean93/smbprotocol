import time
import uuid

import smbclient

print("session 1")
ses = smbclient.register_session("server2022.domain.test")
print("sleep")
time.sleep(1200)
print("session 2")
ses = smbclient.register_session("server2022.domain.test")

# print("reset")
# smbclient.reset_connection_cache()

print("done")
