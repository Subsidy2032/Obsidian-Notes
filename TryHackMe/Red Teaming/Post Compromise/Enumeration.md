## Linux Enumeration

##### System

`ls /etc/*-release` - Find information about the Linux distribution and release version.

`ls -lh /var/mail/` - Find mail directories.

`ls -lh /usr/bin/` or `ls -lh /sbin/` - Find the installed applications.
`dpkg -l` - Find the installed packages.
`rpm -qa` - Find the installed packages in RPM-based Linux system.

##### Users

`who` - Show who is logged in.
`w` - Show who is logged in and what they are doing.
`last` - List the last logged in users.

##### Networking

The DNS servers can be found in the `/etc/resolve.conf`.

`netstat` is a useful command to learn about network connections, routing tables and interface statistics.

`lsof` stands for list open files, `lsof -i` Will display only internet and network connections, you can also filter connections by port number you can use `lsof -i :<port>`.

## Windows enumeration

##### System

`systeminfo` shows detailed information about the system.
`wmic qfe get Caption,Descriptio` - Check the installed updates.
`net start` - Check the installed and started Windows services.
`wmic product get name,version,vendor` - Check the installed apps.

##### Users

`net user` - View users.
`net group` - Discover available groups if the system is Windows DC.
`net localgroup` - Discover available groups in a not AD environment.
`net localgroup <group name>` - Check the members of a group.
`net accounts /domain` - Learn about local policies.

##### Networking

`arp -a` - Find other systems in the same LAN that recently communicated with your system.

## DNS, SMB and SNMP

##### DNS

`dig -t AXFR DOMAIN_NAME @<dns server>` - Attempt zone transfer.

##### SMB

`net share` - Check for shared folders.

##### SNMP

SNMP lets you know about various events, like a server with a faulty disk or a printer that is out of ink.

`snmpcheck` is a tool to enumerate servers related to SNMP.