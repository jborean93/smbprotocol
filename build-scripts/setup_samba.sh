# install samba on a Centos server
yum install samba -y

# set basic SMB configuration
cat > /etc/samba/smb.conf << EOL
[global]
workgroup = WORKGROUP
valid users = @smbgroup

[$SMB_SHARE]
comment = Test Samba Share
path = /srv/samba/$SMB_SHARE
browsable = yes
guest ok = no
read only = no
create mask = 0755

[$SMB_ENCRYPTED_SHARE]
command = Test Encrypted Samba Share
path = /srv/samba/$SMB_ENCRYPTED_SHARE
browsable = no
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
mkdir -p /srv/samba/$SMB_SHARE
chmod -R 0755 /srv/samba/$SMB_SHARE
chown -R $SMB_USER:smbgroup /srv/samba/$SMB_SHARE

mkdir -p /srv/samba/$SMB_ENCRYPTED_SHARE
chmod -R 0755 /srv/samba/$SMB_ENCRYPTED_SHARE
chown -R $SMB_USER:smbgroup /srv/samba/$SMB_ENCRYPTED_SHARE

# run smb service
/usr/sbin/smbd -F -S < /dev/null
