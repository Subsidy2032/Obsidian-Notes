## Network Infrastructure

When gaining access to a machine we need to enumerate what target system we are dealing with, what service the machine provides and what kind of network are we in.

Network segmentation is an extra layer of security divided into multiple subnets, for example VLAN is a technique used in network segmentation.

##### Internal Networks

Internal Networks are subnetworks that are segmented and separated based on the importance of the internal device or the importance of the accessibility of its data.

![[f86b9cce1276f4c317bcb4bae7686891.png]]

##### A Demilitarized Zone (DMZ)

A DMZ is an edge network that provides extra protection, commonly sits between the public internet and the internal networks, for example this way a company can isolate services they provide to the public internet.

##### Network Enumeration

`netstat -na` - Check for open TCP and UDP ports.
`arp -a` - Show the ARP table, can help with scanning other machines for open ports and vulnerabilities.

##### Internal Network Services

It provides private and internal network communication for internal network devices, for example internal DNS and web servers.

## Active Directory (AD) Environment

##### What is the Active Directory (AD) Environment

It provides data objects to the internal network environment, it allows for the central management of authentication and authorization.

**AD Objects:** Contains users, groups, computers and GPOs.
**AD Forest:** A collection of domains that trust each other.

`systeminfo | findstr Domain` - Check if the windows machine is part of a domain environment.

## Users and Groups Management

Accounts in Windows:

- The built-in local users' accounts are used to manage the system locally, which is not part of the AD environment.
- Domain user accounts with access to an active directory environment can use the AD services (managed by AD).
- AD managed service accounts are limited domain user account with higher privileges to manage AD services.
- Domain Administrators are user accounts that can manage information in an Active Directory environment, including AD configurations, users, groups, permissions, roles, services, etc. One of the red team goals in engagement is to hunt for information that leads to a domain administrator having complete control over the AD environment.

AD Administrators accounts:

|Acount|Description|
|---|---|
|BUILTIN\Administrator|Local admin access on a domain controller|
|Domain Admins|Administrative access to all resources in the domain|
|Enterprise Admins|Available only in the forest root|
|Schema Admins|Capable of modifying domain/forest; useful for red teamers|
|Server Operators|Can manage domain servers|
|Account Operators|Can manage users that are not in privileged groups|

##### Active Directory (AD) Enum

`Get-ADUser  -Filter *` - List all AD user accounts.

We can also use the [LDAP hierarchical tree structure](http://www.ietf.org/rfc/rfc2253.txt) to find a user in the AD, the distinguished name (DN) is a collection of key and value pairs separated by a comma used to identify unique records within the directory. The DN consists of Domain Component (DC), OrganizationalUnitName (OU), Common Name (CN) and others.

`Get-ADUser -Filter * -SearchBase "CN=Users,DC=THMREDTEAM,DC=COM"` - An example of searching for a specific CN in the AD.

## Host Security Solution #1

##### Antivirus Software (AV)

The main job of antivirus is to prevent malware from executing, you can make a full scan, scan in the background and make virus definitions.

Detection techniques:

**Signature-based detection:** The antivirus vendors adds signature of malicious files to the signatures database, it than consider a threat any file that matches a signature.

**Heuristic-based detection:** Uses machine learning it scans and analyzes in real time for malicious properties in application's code and checks whether it uses common Windows or system APIs.

**Behavior-based detection:** Searches for abnormal behaviors and activities in an application, like changing a registry values or killing creating processes.

`wmic /namespace:\\root\securitycenter2 path antivirusproduct` - Check for antivirus in Windows.

##### Microsoft Windows Defender

Microsoft Windows Defender is pre-installed and uses various algorithms like machine learning, big data analysis, in depth threat resistance research and Microsoft cloud infrastructure.

Modes:

**Active:** The MS defender runs as the primary antivirus software.

**Passive:** Runs while there is a third party antivirus on the machine, does not provide remediation only detection.

**Disable:** The MS defender is disabled or uninstalled.

`Get-Service WinDefend` or `Get-MpComputerStatus | select RealTimeProtectionEnabled` - Check the service state of Windows defender.

##### Host-based Firewall

`Get-NetFirewallProfile | Format-Table Name, Enabled` - Check the firewall state.
`Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False` - Disable the firewall.
`Get-NetFirewallRule | select DisplayName, Enabled, Description` - Check the firewall rules.
`Test-NetConnection -ComputerName 127.0.0.1 -Port 80` or `(New-Object System.Net.Sockets.TcpClient("127.0.0.1", "80")).Connected` - Test inbound connection.

## Host Security Solution #2

##### Security Event Logging and Monitoring

`Get-EventLog -List` - Get a list of available event logs on the local machine.

With this list you can get insight of applications and services installed in the machine.

##### System Monitor (Sysmon)

Sysmon is a service and device driver that is part of the Sysinternals tools, once installed it starts gathering and logging events.

Some rules and configuration to monitor:

- Process creation and termination.
- Network connections.
- Modification on file.
- Remote threats.
- Process and memory access.
- And many others.

As a red teamer you should be aware of and avoid those tools.

`Get-Process | Where-Object { $_.ProcessName -eq "Sysmon" }` - Look for a process named Sysmon.

Or look for services as follows:

``` powershell
PS C:\Users\thm> Get-CimInstance win32_service -Filter "Description = 'System Monitor service'"
# or
Get-Service | where-object {$_.DisplayName -like "*sysm*"}```

`reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational` - Check the Windows registry for the service.

`findstr /si '<ProcessCreate onmatch="exclude">' C:\tools\*` - Find the Sysmon configuration file.

##### Host-based Intrusion Detection/Prevention System (HIDS/HIPS)

HIDS used to detect abnormal activity on the host, in 2 ways:

- **Signature-based IDS:** It looks at checksum and message authentication.
- **Anomaly-based IDS:** Looks for unexpected activity.

HIPS is a detecting and preventing solution against well known attacks and abnormal behavior, it's a mixture of antivirus, behavior analysis, network, application firewall, etc.

##### Endpoint Detection and Response (EDR)

EDR can look for malicious files, monitor endpoint, system and network events and record them in a database, this is the next generation of antivirus and detect malicious activities in real time.

Some common EDR software:

- Cylance
- Crowdstrike
- Symantec
- SentinelOne
- Many others

Even if an attacker bypassed EDR and got a reverse shell, EDR continues to monitor and might block us from doing something else.

We can use tools such as [Invoke-EDRChecker](https://github.com/PwnDexter/Invoke-EDRChecker) and [SharpEDRChecker](https://github.com/PwnDexter/SharpEDRChecker) to check for host security solutions.

## Network Security Solutions

##### Network Firewall

Firewalls are the first checkpoint for packets entering and exiting the network.

##### Security Information and Event Management (SIEM)

SIEM is used to monitor and analyze events in real time, to prevent threats and vulnerabilities before causing demage.

SIEM aggregates log data and performs action on the data to detect security threats and attacks.

SIEM can also detect advanced and unknown threats using integrated threat intelligence and AI technologies.

##### Intrusion Detection System and Intrusion Prevention System (NIDS/NIPS)

Network NIDS and NIPS is based on sensors and agents distributed across the network to collect data.

## Applications and Services

##### Installed applications

As red teamers we should enumerate the system for applications names and versions, this way we can find vulnerabilities or credentials.

`wmic product get name,version` - List all installed applications and their version.

We can also look for particular text strings, hidden directories and backup files.

##### Services and Process

Services may have misconfigured permission which will allow us to escalate privileges.

Process discovery is an enumeration step used to get details about services and processes on a system, for example a client custom application that is found is the most common vector for privilege escalation.

##### Sharing Files and Printers

System Administrators may misconfigure access permissions for shared resources, and they may have useful information about other accounts and systems.

##### Internal Services: DNS Local Web Applications, etc

With network services we can expand are knowledge about other systems and the entire environment.

Internal services that are commonly used and we are interested in:

- DNS services
- Email services
- Network file share
- Web application
- Database service



`net start` - Check for running services.
`wmic service where "name like '<service name>'" get Name,PathName` - Find a file name and a path for the service.
`Get-Process -Name t<service name>` - Find more information about the service.
`netstat -noa |findstr "LISTENING" |findstr "<service ID>"` - Check if providing a network service.