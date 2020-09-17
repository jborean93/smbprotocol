# install samba on a Centos server
yum install samba vim -y

# set basic SMB configuration
cat > /etc/samba/smb.conf << EOL
[global]
host msdfs = yes
workgroup = WORKGROUP
valid users = @smbgroup
server signing = mandatory
ea support = yes
store dos attributes = yes
vfs objects = xattr_tdb streams_xattr

[dfs]
comment = Test Samba DFS Root
path = /srv/samba/dfsroot
browsable = yes
guest ok = no
read only = no
create mask = 0755
msdfs root = yes

[$SMB_SHARE]
comment = Test Samba Share
path = /srv/samba/$SMB_SHARE
browsable = yes
guest ok = no
read only = no
create mask = 0755

[${SMB_SHARE}-encrypted]
comment = Test Encrypted Samba Share
path = /srv/samba/${SMB_SHARE}-encrypted
browsable = yes
guest ok = no
read only = no
create mask = 0755
smb encrypt = required
EOL

# create smb user
groupadd smbgroup
useradd $SMB_USER -G smbgroup
(echo $SMB_PASSWORD; echo $SMB_PASSWORD) | smbpasswd -s -a $SMB_USER

# create smb share and configure permissions
mkdir -p /srv/samba/dfsroot
chmod -R 0755 /srv/samba/dfsroot
chown -R $SMB_USER:smbgroup /srv/samba/dfsroot
ln -s msdfs:localhost\\$SMB_SHARE /srv/samba/dfsroot/$SMB_SHARE
ln -s msdfs:localhost\\missing,localhost\\$SMB_SHARE-encrypted /srv/samba/dfsroot/$SMB_SHARE-encrypted
ln -s msdfs:localhost\\missing /srv/samba/dfsroot/broken

mkdir -p /srv/samba/$SMB_SHARE
chmod -R 0755 /srv/samba/$SMB_SHARE
chown -R $SMB_USER:smbgroup /srv/samba/$SMB_SHARE

mkdir -p /srv/samba/${SMB_SHARE}-encrypted
chmod -R 0755 /srv/samba/${SMB_SHARE}-encrypted
chown -R $SMB_USER:smbgroup /srv/samba/${SMB_SHARE}-encrypted

# run smb service
/usr/sbin/smbd -F -S < /dev/null
