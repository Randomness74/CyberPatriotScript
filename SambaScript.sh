#!/bin/bash
# finish forensics questions before running this. REMEMBER WHAT HAPPENED IN ROUND 2 of CP XII.

echo "Starting ..."

echo "Updating Samba..."
sudo apt-get install samba

echo "Backing up files..."
sudo cp /etc/samba/smb.conf /etc/samba/smb.conf.bak

echo 'Rememeber to set the following:
    /etc/samba/smb.conf
    Fix Workgroup
    security = user
    path = /tmp
    guest ok = no
    read only = no
    browseable = yes
    min_protocol >= lanman1

'
sudo sudo cat smb.conf > /etc/samba/smb.conf
sudo chmod 644 /etc/samba/smb.conf

echo "Restarting samba..."
sudo systemctl restart samba

echo "... done!"