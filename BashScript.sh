#!/bin/bash
# remember to chmod 755 BashScript from directory.
# To enable line numbers in Emacs, press Alt-X, then type and enter linum-mode
# finish forensics questions before running this. REMEMBER WHAT HAPPENED IN ROUND 2 of CP XII.
# add crontab
# CHECK THE FUCKING CRONJOBS
# hidden users, check users list
# /etc/security/pwquality.conf 
# service config matters

echo "Starting..."



echo "$(tput setaf 10)------------------------------------"

echo "Creating log files..."
touch log.txt

echo "Securing network settings..."
echo "Enabling firewall..."
sudo apt-get install ufw
sudo apt-get remove iptables-persistent
echo "Configuring UFW..."
# loopback denial
sudo ufw allow in on lo
sudo ufw allow out on lo
sudo ufw deny in from 127.0.0.0/8
sudo ufw deny in from ::1
sudo ufw allow ssh
sudo ufw allow http
sudo ufw deny 23
sudo ufw default deny
sudo ufw --force enable
echo "Editing sysctl.conf..."
sudo cp /etc/sysctl.conf /etc/sysctl.conf.bak
# echo "net.ipv6.conf.all.disable_ipv6=1" | sudo tee -a /etc/sysctl.conf
# echo "net.ipv4.icmp_echo_ignore_all=1" | sudo tee -a /etc/sysctl.conf
# sudo sed -i '19,20 s/#//; 25 s/#//; 28 s/#//; 44,45 s/#//; 52 s/#//; 55,56 s/#//; 59 s/#//' /etc/sysctl.conf
sudo cat sysctl.conf > /etc/sysctl.conf
echo "Editing host.conf..."
sudo cp /etc/host.conf /etc/host.conf.bak
echo "order bind,hosts" | sudo tee -a /etc/host.conf
sudo ip link set dev promisc off 
echo "Done editing network settings."
echo "------------------------------------$(tput sgr0)"


function DelUser() {
    VAR1=""
    INP1=""
    echo "Which user do you want to delete? "
    read VAR1
    echo "Are you sure that you want to delete user $VAR1? "
    read INP1
    if [ "$INP1" == "Yes" ] || [ "$INP1" == "yes" ]; then
        sudo userdel $VAR1
    fi
}

function DelGroup() {
    VAR2=""
    INP2=""
    echo "Which group do you want to delete? "
    read VAR2
    echo "Are you sure that you want to delete group $VAR2? "
    read INP2
    if [ "$INP2" == "Yes" ] || [ "$INP2" == "yes" ]; then
        sudo groupdel $VAR2
    fi
}

function AddUser() {
    VAR3=""
    INP3=""
    echo "What is the name of the user you want to add? "
    read VAR3
    echo "Are you sure that you want to add user $VAR3? "
    read INP3
    if [ "$INP3" == "Yes" ] || [ "$INP3" == "yes" ]; then
        sudo adduser $VAR3
    fi
}

function PassChange() {
    VAR4=""
    INP4=""
    echo "Which user's password do you want to change? "
    read VAR4
    echo "Are you sure that you want to change user $VAR4's password? "
    read INP4
    if [ "$INP4" == "Yes" ] || [ "$INP4" == "yes" ]; then
        sudo passwd $VAR4
    fi
}
function PrivChange() {
    VAR5=""
    INP5=""
    echo "Which user's privileges do you want to change? "
    read VAR5
    echo "Are you sure that you want to change user $VAR5's privileges? "
    read INP5
    if [ "$INP5" == "Yes" ] || [ "$INP5" == "yes" ]; then
        usermod -aG sudo $VAR5
    fi
}

echo "$(tput setaf 9)------------------------------------"
echo "Fixing users..."
echo "Starting user account functions..."
echo "User account list for reference: "
sudo getent passwd
echo "$(tput setaf 7)------------------------------------"
echo "Also a list of sudoers: "
sudo getent group sudo | cut -d: -f4
echo "$(tput setaf 4)------------------------------------"
echo "Also a list of groups: "
sudo getent group

while true
do
    VAR5=""
    AddUser
    echo "Do you want to add another user?"
    read VAR5
    if [ "$VAR5" != "Yes" ] && [ "$VAR5" != "yes" ]; then
        break
    fi
done

while true
do
    VAR5=""
    DelUser
    echo "Do you want to remove another user?"
    read VAR5
    if [ "$VAR5" != "Yes" ] && [ "$VAR5" != "yes" ]; then
        break
    fi
done

while true
do
    VAR5=""
    PassChange
    echo "Do you want to change another password?"
    read VAR5
    if [ "$VAR5" != "Yes" ] && [ "$VAR5" != "yes" ]; then
        break
    fi
done

while true
do
    VAR5=""
    PrivChange
    echo "Do you want to change another user's privileges?"
    read VAR5
    if [ "$VAR5" != "Yes" ] && [ "$VAR5" != "yes" ]; then
        break
    fi
done

while true
do
    VAR5=""
    DelGroup
    echo "Do you want to delete another group?"
    read VAR5
    if [ "$VAR5" != "Yes" ] && [ "$VAR5" != "yes" ]; then
        break
    fi
done

echo "------------------------------------$(tput sgr0)"


while (true)
do
    VAR26=""
    echo "Do you want to remove SSH? (yes or no)"
    read VAR26
    if [ "$VAR26" == "Yes" ] || [ "$VAR26" == "yes" ]; then
        sudo apt-get remove openssh-server
        sudo apt-get remove oepnssh-client
        break
    elif [ "$VAR26" == "No" ] || [ "$VAR26" == "no" ]; then
        echo "Editing sshd_config..."
        # SSH SETTINGS
          #  PermitRootLogin no
          #  PermitUserEnvironment no
          #  PermitEmptyPasswords no
          #  Protocol 2
          #  PrintLastLog no
          #  PubkeyAuthentication yes
          #  RSAAuthentication yes
          #  LoginGraceTime 30
          #  ClientAliveInterval 600
          #  ClientAliveCountMax 1
          #  UsePAM yes
          #  UsePrivilegeSeparation yes
          #  StrictModes yes
          #  IgnoreUserKnownHosts yes
          #  IgnoreRhosts yes
          #  RhostsAuthentication no
          #  RhostsRSAAuthentication no
          #  HostBasedAuthentication no
          #  AllowTcpForwarding no
          #  X11Forwarding no
          #  LogLevel VERBOSE
          #  Port 2453
          #  If you mistype any of these and sshd won't start, just type sshd --t to find the line.

        sudo python3 smartreplace.py SSH_KEY.csv /etc/ssh/sshd_config
        break
    fi
done

while (true)
do
    VAR6=""
    echo "Do you want to remove Apache2? (yes or no)"
    read VAR6
    if [ "$VAR6" == "Yes" ] || [ "$VAR6" == "yes" ]; then
        sudo apt-get remove apache2
        break
    elif [ "$VAR6" == "No" ] || [ "$VAR6" == "no" ]; then
        sudo chmod 755 ./ApacheScript.sh
        sudo bash ApacheScript.sh
        break
    fi
done

while (true)
do
    VAR7=""
    echo "Do you want to remove nginx? (yes or no)"
    read VAR7
    if [ "$VAR7" == "Yes" ] || [ "$VAR7" == "yes" ]; then
        sudo apt-get remove nginx
        break
    elif [ "$VAR7" == "No" ] || [ "$VAR7" == "no" ]; then
        sudo chmod 755 ./NginxScript.sh
        sudo bash NginxScript.sh
        break
    fi
done

while (true)
do
    VAR11=""
    echo "Do you want to remove samba? (yes or no)"
    read VAR11
    if [ "$VAR11" == "Yes" ] || [ "$VAR11" == "yes" ]; then
        sudo apt-get remove samba
        break
    elif [ "$VAR11" == "No" ] || [ "$VAR11" == "no" ]; then
        sudo chmod 755 ./SambaScript.sh
        sudo bash SambaScript.sh
        break
    fi
done

while (true)
do
    VAR12=""
    echo "Do you want to remove postgresql? (yes or no)"
    read VAR12
    if [ "$VAR12" == "Yes" ] || [ "$VAR12" == "yes" ]; then
        sudo apt-get remove postgresql
        break
    elif [ "$VAR12" == "No" ] || [ "$VAR12" == "no" ]; then
        sudo chmod 755 ./PostGreScript.sh # doesnt exist yet
        sudo bash PostGreScript.sh
        break
    fi
done

while (true)
do
    VAR8=""
    echo "Do you want to remove FTP? (yes or no)"
    read VAR8
    if [ "$VAR8" == "Yes" ] || [ "$VAR8" == "yes" ]; then
        echo "Removing all versions of FTP..."
        sudo apt-get purge ftp
        sudo apt-get purge pure-ftpd
        sudo apt-get purge lftp
        sudo apt-get purge tftp
        sudo apt-get purge gftp
        sudo apt-get purge jftp
        sudo apt-get purge proftpd
        sudo apt-get purge vsftpd
        sudo apt-get purge tnftp
        sudo apt-get purge bareftp
        break
    elif [ "$VAR8" == "No" ] || [ "$VAR8" == "no" ]; then
        array=(1 2 3 4 5 6 7 8 9 10)
        echo "Which version(s) of FTP do you want to keep?"
        echo "1. FTP"
        echo "2. Pure-FTPD"
        echo "3. LFTP"
        echo "4. TFTP"
        echo "5. GFTP"
        echo "6. JFTP"
        echo "7. Pro-FTPD"
        echo "8. VSFTPD"
        echo "9. TNFTP"
        echo "10. BareFTP"
        while (true)
        do
            VAR9=""
            echo "Enter a number (enter anything else to escape)."
            read VAR9
            echo VAR9
            if [ "$VAR9" != 1 ] && [ "$VAR9" != 2 ] && [ "$VAR9" != 3 ] && [ "$VAR9" != 4 ] && [ "$VAR9" != 5 ] && [ "$VAR9" != 6 ] && [ "$VAR9" != 7 ] && [ "$VAR9" != 8 ] && [ "$VAR9" != 9 ] && [ "$VAR9" != 10 ]; then
                break
            fi
            array=( "${array[@]/$VAR9}" )
        done
        for i in "${array[@]}";
        do
            if [ "$i" == 1 ]; then
                echo "Removing FTP..."
                sudo apt-get remove ftp
            elif [ "$i" == 2 ]; then
                echo "Removing Pure-FTPD..."
                sudo apt-get remove pure-ftpd
            elif [ "$i" == 3 ]; then
                echo "Removing LFTP..."
                sudo apt-get remove lftp
            elif [ "$i" == 4 ]; then
                echo "Removing TFTP..."
                sudo apt-get remove tftp
            elif [ "$i" == 5 ]; then
                echo "Removing GFTP..."
                sudo apt-get remove gftp
            elif [ "$i" == 6 ]; then
                echo "Removing JFTP..."
                sudo apt-get remove jftp
            elif [ "$i" == 7 ]; then
                echo "Removing Pro-FTPD..."
                sudo apt-get remove proftpd
            elif [ "$i" == 8 ]; then
                echo "Removing VSFTPD..."
                sudo apt-get remove vsftpd
            elif [ "$i" == 9 ]; then
                echo "Removing TNFTP..."
                sudo apt-get remove tnftp
            elif [ "$i" == 10 ]; then
                echo "Removing BareFTP..."
                sudo apt-get remove bareftp
        fi
        sudo chmod 755 FTPScript.sh
        sudo bash FTPScript.sh
    done
        break
    fi
done

echo "installing antiviruses..."
sudo apt-get install clamav
sudo apt-get install logwatch libdate-manip-perl
sudo apt-get autoremove
sudo apt-get install apparmor
sudo systemctl enable apparmor.service 
sudo systemctl start apparmor.service 
sudo apt-get install mfetp 
echo "------------------------------------ $(tput sgr0)"


echo "$(tput setaf 2)------------------------------------"
# Command to find all non-root files: sudo find / ! -user root -not -path "/proc/*" -not -path "*/.cache/*" -not -path "/usr/src/*" -not -path "/var/*" -not -path "/tmp/*" -not -path "/run/*" -not -path "*/.local/*"

function DelFiles() {
    echo "Deleting unauthorized files..."
    touch suspiciousFiles.txt
    sudo find / -type f -name '*.mp3' >> suspiciousFiles.txt
    sudo find / -type f -name '*.avi' >> suspiciousFiles.txt
    sudo find / -type f -name '*.mov' >> suspiciousFiles.txt
    sudo find / -type f -name '*.pdf' >> suspiciousFiles.txt
    sudo find / -type f -name '*.ps1' >> suspiciousFiles.txt
    sudo find / -type f -name '*.bat' >> suspiciousFiles.txt
    sudo find / -type f -name '*.flac' >> suspiciousFiles.txt
    sudo find / -type f -name '*.aac' >> suspiciousFiles.txt
    sudo find / -type f -name '*.tiff' >> suspiciousFiles.txt
    sudo find / -type f -name '*.mp4' >> suspiciousFiles.txt
    sudo find / -type f -name '*.RAW' >> suspiciousFiles.txt
    sudo find / -type f -name '*.flv' >> suspiciousFiles.txt
    sudo find / -type f -name '*.exe' >> suspiciousFiles.txt
    sudo find / -type f -name '*.vbs' >> suspiciousFiles.txt
    sudo find / -type f -name '*.shosts' >> suspiciousFiles.txt
    sudo find / -type f -name '*.3gp' >> suspiciousFiles.txt
    sudo find / -type f -name '*.msi' >> suspiciousFiles.txt
    sudo find / -type f -name '*.dll' >> suspiciousFiles.txt
    sudo find / -type f -name '*.pl' -not -path "/usr/*" -not -path "/snap/*" >> suspiciousFiles.txt
    sudo find / -type f -name '*.sh' -not -path "/usr/*" -not -path "/snap/*" >> suspiciousFiles.txt
    sudo find / -type f -name '*.php' -not -path "/usr/*" -not -path "/snap/*" >> suspiciousFiles.txt
    sudo find / -type f -name '*.py' -not -path "/usr/*" -not -path "/snap/*" -not -path "/etc/*">> suspiciousFiles.txt
    sudo find / -type f -name '*.c' -not -path "/usr/*" -not -path "/snap/*" >> suspiciousFiles.txt
    sudo find / -type f -name '*.cpp' -not -path "/usr/*" -not -path "/snap/*" >> suspiciousFiles.txt
}


VAR14=""
echo "Do you want to remove all unauthorized files now? (yes or no)"
read VAR14
if [ "$VAR14" == "Yes" ] || [ "$VAR14" == "yes" ]; then
    DelFiles
fi
echo "------------------------------------ $(tput sgr0)"


echo "------------------------------------"
echo "Fixing config files..."
echo "Editing login.defs..."
#    max age: 90, 
#    min age: 7, 
#    warn age: 14
#    login retries: 3
#    login timeout: 30
sudo apt-get install python3
sudo python3 smartreplace.py LOGIN_KEY.csv /etc/login.defs
sudo python3 shadowchecker.py
echo "Remember the following password settings: 
    deny=10
    difok=3
    minlen=8
    remember=5
    unlock_time=1800
    ucredit=-1
    lcredit=-1
    dcredit=-1
    ocredit=-1
    maxrepeat=2
    dictcheck=1
"
sleep 5
echo "opening common auth. create a new line called tally2.so and add 'deny=10 unlock_time=1800'" 
sleep 5
sudo nano /etc/pam.d/common-auth
echo "auth    required                        pam_tally2.so   deny=10 unlock_time=1800" | sudo tee -a /etc/pam.d/common-auth

echo "opening common password. add minlen=8 and remember=5 to pam_unix.so line. add 'ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-' to pam_cracklib.so."
sleep 5
sudo apt-get install libpam-cracklib
sudo nano /etc/pam.d/common-password
suod rm /etc/gdm3/greeter.dconf-defaults
sudo touch /etc/gdm3/greeter.dconf-defaults
echo "[org/gnome/login-screen]" | sudo tee -a /etc/gdm3/greeter.dconf-defaults
echo "banner-message-enable=true" | sudo tee -a /etc/gdm3/greeter.dconf-defaults
echo "banner-message-text='Welcome to CyberPatriot Ubuntu'"  | sudo tee -a /etc/gdm3/greeter.dconf-defaults
echo "disable-user-list=true"  | sudo tee -a /etc/gdm3/greeter.dconf-defaults
#
#    Note: If lightdm bricks itself again:
#       * Press Ctrl-alt-F1 through F7 on loading screen.
#       * When in terminal, login to sudoer account and reinstall lightdm.
#           * If LightDM won't install, check /etc/apt-get/sources.list. Full version here: https://gist.github.com/rohitrawat/60a04e6ebe4a9ec1203eac3a11d4afc1
#       * After that, reboot the PC and it should work
#
echo "Disabling root password... add 'Defaults     rootpw' to defaults section... also check for !authenticate and NOPASSWD"
echo "Remember to set the su password to something else before doing this."
sudo visudo
#
#    Note: If you lock yourself out by not setting a root password:
#       * First, reboot your computer and enter the boot menu by pressing F2 upon boot.
#       * Second, go into advanced settings and enter the root settings page.
#       * Demount and remount the root disk.
#       * Then, you can set a root password and continue with the boot process.
#       * For further information: https://phoenixnap.com/kb/how-to-change-root-password-linux
#
# sudo passwd -l root 
echo "------------------------------------"


echo "------------------------------------"
echo "Fixing permissions..."
sudo chmod 000 /etc/shadow
sudo chmod 644 /etc/passwd
sudo chmod 600 /etc/ssh/ssh_host*key
sudo chmod 600 /etc/ssh/*key.pub
sudo chmod 640 /var/log 
sudo chmod 640 /var/log/syslog
sudo chmod 640 /var/cache
sudo chown syslog /var/log/syslog
sudo chown root /var/log
sudo chgrp adm /var/log/syslog
sudo chgrp syslog /var/log 
sudo find /lib /usr/lib /lib64 ! -user root -type f -exec chown root '{}' \; # changes all system files to be owned by root
sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec chmod 755 '{}' \; 

sudo chmod 755 /bin
sudo chmod 755 /sbin
sudo chmod 755 /usr/bin
sudo chmod 755 /usr/sbin
sudo chmod 755 /usr/local/bin
sudo chmod 755 /usr/local/sbin
sudo find /lib /lib64 /usr/lib -perm /022 -type d -exec chmod 755 '{}' \;
sudo chmod 600 /var/cache/dictionaries-common
sudo chmod 600 /var/cache/cracklib
sudo chmod 600 /var/cache/apparmor
sudo chmod 640 /var/backups
sudo chmod 644 /var/spool
echo "------------------------------------"

echo "------------------------------------"
echo "Enabling auditing policy..."
sudo apt-get install rsyslog
sudo systemctl enable rsyslog
sudo apt-get install auditd
sudo cat audit.rules > /etc/audit/rules.d/audit.rules
sudo augenrules --load
sudo systemctl restart rsyslog
echo "------------------------------------"

echo "More perms fixing..."
sudo chmod 0600 /var/log/audit/* 
sudo chmod 0600 /var/log/audit/* 

# auditing tools
sudo chown root /sbin/auditctl
sudo chown root /sbin/aureport
sudo chown root /sbin/ausearch
sudo chown root /sbin/autrace
sudo chown root /sbin/auditd
sudo chown root /sbin/audispd
sudo chown root /sbin/augenrules

sudo chmod 755 /sbin/auditctl
sudo chmod 755 /sbin/aureport
sudo chmod 755 /sbin/ausearch
sudo chmod 755 /sbin/autrace
sudo chmod 755 /sbin/auditd
sudo chmod 755 /sbin/audispd
sudo chmod 755 /sbin/augenrules


echo "$(tput setaf 3)------------------------------------"
echo "Fixing firefox settings..."
cd ~
cd ./.mozilla/firefox/*.default
touch user.js
function FirefoxPref() {
    echo "user_pref($1, $2);" | sudo tee -a user.js
}
FirefoxPref '"browser.safebrowsing.downloads.enabled"' "true"
FirefoxPref '"browser.safebrowsing.downloads.remote.enabled"' "true"
FirefoxPref '"browser.safebrowsing.downloads.remote.block_dangerous"' "true"
FirefoxPref '"browser.safebrowsing.downloads.remote.block_dangerous"' "true"
FirefoxPref '"browser.safebrowsing.downloads.remote.block_dangerous_host"' "true"
FirefoxPref '"browser.safebrowsing.downloads.remote.block_potentially_unwanted"' "true"
FirefoxPref '"browser.safebrowsing.downloads.remote.block_uncommon"' "true"
FirefoxPref '"browser.safebrowsing.malware.enabled"' "true"
FirefoxPref '"browser.safebrowsing.phishing.enabled"' "true"
FirefoxPref '"dom.disable_open_during_load"' "true"
FirefoxPref '"dom.block_multiple_popups"' "true"
FirefoxPref '"dom.block_download_insecure"' "true"
FirefoxPref '"dom.enable_performance"' "true"
FirefoxPref '"dom.allow_scripts_to_close_windows"' "false"
FirefoxPref '"media.autoplay.block-webaudio"' "true"
FirefoxPref '"media.block-autoplay-until-in-foreground"' "true"
FirefoxPref '"plugins.flashBlock.enabled"' "true"
FirefoxPref '"privacy.socialtracking.block_cookies.enabled"' "true"
FirefoxPref '"toolkit.telemetry.reportingpolicy.firstRun"' "false"
cd ~
cd Desktop
cd Script
echo "------------------------------------ $(tput sgr0)"


echo "$(tput setaf 14)------------------------------------"
echo "Experimental stuff..."
sudo systemctl mask ctrl-alt-del.target
sudo systemctl disable kdump.service

#echo "Testing for shellshock vulnerabilities..."
#echo "If the system is vulnerable to CVE-2014-6271, it should print 'vulnerable this is a test'"
#env x='() { :;}; echo vulnerable' bash -c "echo this is a test" 
#echo "If the system is vulnerable to CVE-2014-7169, it should throw a syntax error"
#env X='() { (a)=>\' sh -c "echo date"; cat echo; rm ./echo
#echo "If the system is vulnerable to CVE-2014-6277 or 6278, it should print 'not patched'"
#foo='() { echo not patched; }' bash -c foo
#echo "If the system is vulnerable to CVE-2014-7186, it should throw a syntax error"
#bash -c "export f=1 g='() {'; f() { echo 2;}; export -f f; bash -c 'echo \$f \$g; f; env | grep ^f='" 
#echo "If the system is vulnerable CVE-2014-7187, it should print 'CVE2014-7187 vulnerable, word_lineno'"
#(for x in {1..200} ; do echo "for x$x in ; do :"; done; for x in {1..200} ; do echo done ; done) | bash || echo "CVE-2014-7187 vulnerable, word_lineno" 

echo "Disabling unessecary services..."
sudo apt-get install bum
sudo bum

#echo "Setting process ID limits..."
#sudo nano /etc/security/limits.conf

echo "Checking for open ports..."
sudo netstat -tulpna
while (true)
do
    VAR10=0
    VAR11=""
    echo "What port do you want to close?"
    read VAR10
    sudo ufw deny VAR10
    echo "Do you want to close another port?"
    read VAR11
    if [ "$VAR11" != "Yes" ] || [ "$VAR11" != "yes" ]; then
        break
    fi
done

echo "Scanning for suspicious cron jobs..."
echo "Logging all user cronjobs..."
if [ "$(sudo ls -A /var/spool/cron/crontabs)" ] ; then
    echo "WARNING! User crontabs have been found!" >> log.txt
    sudo ls -A /var/spool/cron/crontabs >> log.txt
fi
echo "Printing out all root cron jobs..."
sudo cat /etc/crontab

echo "Fixing sources.list"
VAR111=$(cat /etc/issue.net)
VAR112=$(echo $VAR111 | cut -c7-9)
VAR113=$(echo $VAR111 | cut -c1-6)
if [ $VAR113 -eq "Ubuntu" ]; then 
    if [ $VAR112 -eq "16" ]; then
        sudo cat ubu16.txt > /etc/apt/sources.list
    fi
    elif [ $VAR112 -eq "18" ]; then 
        sudo cat ubu18.txt > /etc/apt/sources.list
    fi
    elif [ $VAR112 -eq "20" ]; then
        sudo cat ubu20.txt > /etc/apt/sources.list
    fi
fi
elif [ $VAR113 -eq "Debian" ]; then
    sudo cat deb.txt > /etc/apt/sources.list
fi

echo "Clearing bash history..."
history -c
set +o history

# remove file systems?
sudo rmmod cramfs
sudo rmmod freevxfs
sudo rmmod jffs2
sudo rmmod hfs
sudo rmmod hfsplus
sudo rmmod udf

echo "Printing out all tasks..."
sudo systemctl list-units --type=service

echo "... it's finally fucking done!"
echo "------------------------------------ $(tput sgr0)"

# NOTES

# if rm is not working
# chattr -a -i
# then chmod -ug+w
# then delete

# /etc/fstab

#postgresql check /etc/postgresql
# turn ssl on and check for mapping

# samba change protocol to not lanman1

# space force server
# hide version names
# check .sh files
# check user access and group perms
# check /etc/apt/sources.list
# time.conf?
# rest of /etc/security
# configure apparmor?
# ufw sysctl.conf
# pam.d service passwd policies
## especially su and sudo password config
# rsyslog config (if desperate)


# TO ADD
# https://stigviewer.com/stig/canonical_ubuntu_20.04_lts/2021-03-23/finding/V-238207
# https://stigviewer.com/stig/canonical_ubuntu_20.04_lts/2021-03-23/finding/V-238236
# https://stigviewer.com/stig/canonical_ubuntu_20.04_lts/2021-03-23/finding/V-238324
# https://stigviewer.com/stig/canonical_ubuntu_20.04_lts/2021-03-23/finding/V-238244
# https://stigviewer.com/stig/canonical_ubuntu_20.04_lts/2021-03-23/finding/V-238370
# https://stigviewer.com/stig/canonical_ubuntu_20.04_lts/2021-03-23/finding/V-238375
# https://stigviewer.com/stig/canonical_ubuntu_20.04_lts/2021-03-23/finding/V-238362 (IMPORTANT)
# https://stigviewer.com/stig/canonical_ubuntu_20.04_lts/2021-03-23/finding/V-238373

# Apache shit: https://stigviewer.com/stig/apache_2.2_serverunix/
# POSTGRESQL: https://stigviewer.com/stig/postgresql_9.x/

# SOURCES
#    Point sheets, Training Modules, Personal Experience
#    https://www.thefanclub.co.za/how-to/how-secure-ubuntu-1604-lts-server-part-1-basics
#    https://github.com/Forty-Bot/linux-checklist
#    https://pastebin.com/NS4ng79h
#    https://www.stigviewer.com/stig/canonical_ubuntu_16.04_lts/
#    https://stigviewer.com/stig/canonical_ubuntu_18.04_lts/
#    https://www.stigviewer.com/stig/canonical_ubuntu_20.04_lts/
#    https://sites.google.com/site/cyberpatriotkhs/hardening-check-list-1
#    http://bookofzeus.com/harden-ubuntu/
#    Logs and their meaning: http://bookofzeus.com/harden-ubuntu/monitoring-tools/watch-logs/
#    https://www.cisecurity.org/cis-benchmarks/
#    https://drive.google.com/file/d/1tcSyEDYHZp_Qi9FkVif5KJWUR8KafykJ/view