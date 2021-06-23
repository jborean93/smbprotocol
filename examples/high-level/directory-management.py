from smbclient import (
    listdir,
    mkdir,
    register_session,
    rmdir,
    scandir,
    isdir,
)

# Optional - register the server with explicit credentials
register_session("server", username="admin", password="pass")

# Create a directory (only the first request needs credentials)
mkdir(r"\\server\share\directory", username="user", password="pass")

# Remove a directory
rmdir(r"\\server\share\directory")

# Checking whether a file is a directory
d_filename = r"\\server\share\directory"
print("Is file {} dir?: {}".format(d_filename, isdir(d_filename))

# List the files/directories inside a dir
for filename in listdir(r"\\server\share\directory"):
    print(filename)

# Use scandir as a more efficient directory listing as it already contains info like stat and attributes.
for file_info in scandir(r"\\server\share\directory"):
    file_inode = file_info.inode()
    if file_info.is_file():
        print("File: %s %d" % (file_info.name, file_inode))
    elif file_info.is_dir():
        print("Dir: %s %d" % (file_info.name, file_inode))
    else:
        print("Symlink: %s %d" % (file_info.name, file_inode))
