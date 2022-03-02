# reads file
with open('/etc/shadow', 'r') as file1:
	content = file1.read().splitlines()

no_passwd_list = ["daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats", "nobody", "systemd-network", "systemd-resolve", "systemd-timesync", "messagebus", "syslog", "_apt", "tss", "uuidd", "tcpdump", "avahi-autoipd", "usbmux", "rtkit", "dnsmasq", "cups-pk-helper", "speech-dispatcher", "avahi", "kernoops", "saned", "nm-openvpn", "hplip", "whoopsie", "colord", "geoclue", "pulse", "gnome-initial-setup", "sssd", "systemd-coredump"]

# opens log
with open('log.txt', 'a') as file2:
	content2 = []
	# splits file into segments
	for item in content:
		content2.append(item.split(':'))
	# checks for security issues
	for i in content2:
		for j in range(0, len(i)):
			if j == 1:	# password policy
				# hashing algorithms
				if i[j][0:3] == "$1$":
					file2.write("WARNING! The password for user account " + i[0] + " is encrypted using the insecure MD5 hashing algorithm.\n")
				# usable accounts
				if i[j][0] != "$" and i[0] not in no_passwd_list:
					file2.write("WARNING! User account " + i[0] + " does not have a password.\n")