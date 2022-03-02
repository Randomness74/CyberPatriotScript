#!/bin/bash
# finish forensics questions before running this. REMEMBER WHAT HAPPENED IN ROUND 2 of CP XII.

echo "Starting ..."

echo "Updating FTP..."
sudo apt-get install vsftpd

echo "Replacing CONFIG file..."
sudo cp /etc/vsftpd.conf /etc/vsftpd.conf.bak
sudo cat vsftpd.conf > /etc/vsftpd.conf

echo "Generating more secure keys..."
sudo openssl req -x509 -days 365 -newkey rsa:4096 -nodes -keyout /etc/vsftpd_fixed.pem -out /etc/vsftpd_fixed.pem

echo "Adding firewall exceptions..."
sudo ufw allow 20
sudo ufw allow 21
sudo ufw allow 64000:65535

echo "Fixing file permissions..."
sudo chmod 644 /etc/vsftpd.conf
sudo chmod 600 /etc/vsftpd_fixed.pem
sudo chmod 600 /etc/vsftpd.pem
sudo chmod 600 /etc/ssl/certs/ssl-cert-snakeoil.pem
sudo chmod 600 /etc/ssl/private/ssl-cert-snakeoil.key

echo "Restarting FTP..."
sudo systemctl restart vsftpd

echo "... done!"