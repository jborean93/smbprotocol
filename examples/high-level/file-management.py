from smbclient import (
    link,
    open_file,
    remove,
    register_session,
    stat,
    symlink,
)

# Optional - register the server with explicit credentials
register_session("server", username="admin", password="pass")

# Read an existing file as text (credentials only needed for the first request to the server if not registered.)
with open_file(r"\\server\share\file.txt", username="admin", password="pass") as fd:
    file_contents = fd.read()

# Read an existing file as bytes
with open_file(r"\\server\share\file.txt", mode="rb") as fd:
    file_bytes = fd.read()

# Create a file and write to it
with open_file(r"\\server\share\file.txt", mode="w") as fd:
    fd.write(u"content")

# Write data to the end of an existing file
with open_file(r"\\server\share\file.txt", mode="a") as fd:
    fd.write(u"\ndata at the end")

# Delete a file
remove(r"\\server\share\file.txt")

# Get info about a file
stat(r"\\server\share\file.txt")

# Create a symbolic link
symlink(r"\\server\share\directory", r"\\server\share\link")

# Create a hard link
link(r"\\server\share\file.txt", r"\\server\share\hard-link.txt")
