### enumeration

[PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)/[SharpView](https://github.com/dmchell/SharpView): A PowerShell tool and a .NET port of the same used to gain situational awareness in AD, can be used to replace various Windows net* commands, can gather much of the data BloodHound does but requires more work.

[BloodHound](https://github.com/BloodHoundAD/BloodHound): Used to visually map out AD relationships and help plan attack paths that may otherwise go unnoticed

[SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors): Gathers data from active directory into a JSON file, to later be ingested into the BloodHound tool

[BloodHound.py](https://github.com/fox-it/BloodHound.py): A Python-based BloodHound ingestor based on the [Impacket toolkit](https://github.com/CoreSecurity/impacket/)

[Kerbrute](https://github.com/ropnop/kerbrute): A tool written in Go that uses Kerberos Pre-Authentication to enumerate Active Directory accounts, perform password spraying, and brute-forcing

[Impacket toolkit](https://github.com/SecureAuthCorp/impacket): A collection of tools written in Python for interacting with network protocols

[Responder](https://github.com/lgandx/Responder): A purpose-built tool to poison LLMNR, NBT-NS, and MDNS

[Inveigh.ps1](https://github.com/Kevin-Robertson/Inveigh/blob/master/Inveigh.ps1): Similar to Responder

[C# Inveigh (InveighZero)](https://github.com/Kevin-Robertson/Inveigh/tree/master/Inveigh): The C# version of Inveigh with a semi-interactive console for interacting with captured data such as username and password hashes

[rpcinfo](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rpcinfo): used to query the status of an RPC program or enumerate the list of available RPC services on a remote host

[rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html): A part of the Samba suite on Linux distributions that can be used to perform a variety of Active Directory enumeration tasks via the remote RPC service

[CrackMapExec (CME)](https://github.com/byt3bl33d3r/CrackMapExec): CME is an enumeration, attack, and post-exploitation toolkit, it attempts to "live off the land"

[GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py): Another Impacket module geared towards finding Service Principal names tied to normal users

[enum4linux](https://github.com/CiscoCXSecurity/enum4linux): A tool for enumerating information from Windows and Samba systems

[enum4linux-ng](https://github.com/cddmp/enum4linux-ng): A rework of the original Enum4linux tool that works a bit differently

[ldapsearch](https://linux.die.net/man/1/ldapsearch): Built-in interface for interacting with the LDAP protocol

[windapsearch](https://github.com/ropnop/windapsearch): A Python script used to enumerate AD users, groups, and computers using LDAP queries

[Snaffler](https://github.com/SnaffCon/Snaffler): Useful for finding information (such as credentials) in Active Directory on computers with accessible file shares

[rpcdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py): Part of the Impacket toolset, RPC endpoint mapper

[adidnsdump](https://github.com/dirkjanm/adidnsdump): A tool for enumerating and dumping DNS records from a domain. Similar to performing a DNS Zone transfer

[Active Directory Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer): Active Directory Explorer (AD Explorer) is an AD viewer and editor. It can be used to navigate an AD database or save a snapshot. It can also be used to compare two AD database snapshots

### Attacks

[CrackMapExec (CME)](https://github.com/byt3bl33d3r/CrackMapExec): CME is an enumeration, attack, and post-exploitation toolkit, it attempts to "live off the land"

[Rubeus](https://github.com/GhostPack/Rubeus): Rubeus is a C# tool built for Kerberos Abuse

[DomainPasswordSpray.ps1](https://github.com/dafthack/DomainPasswordSpray): DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit): The toolkit includes functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsoft's Local Administrator Password Solution (LAPS)

[smbmap](https://github.com/ShawnDEvans/smbmap): SMB share enumeration across a domain

[psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py): Part of the Impacket toolkit, it provides us with Psexec-like functionality in the form of a semi-interactive shell

[wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py): Part of the Impacket toolkit, it provides the capability of command execution over WMI

[setspn.exe](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11)): Adds, reads, modifies and deletes the Service Principal Names (SPN) directory property for an Active Directory service account

[Mimikatz](https://github.com/ParrotSec/mimikatz): Performs many functions. Notably, pass-the-hash attacks, extracting plaintext passwords, and Kerberos ticket extraction from memory on a host

[mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py): Part of the Impacket toolkit, it provides the ability to interact with MSSQL databases

[noPac.py](https://github.com/Ridter/noPac): Exploit combo using CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user

[CVE-2021-1675.py](https://github.com/cube0x0/CVE-2021-1675/blob/main/CVE-2021-1675.py): Printnightmare PoC in python

[ntlmrelayx.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py): Part of the Impacket toolset, it performs SMB relay attacks

[PetitPotam.py](https://github.com/topotam/PetitPotam): PoC tool for CVE-2021-36942 to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions

[gettgtpkinit.py](https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py): Tool for manipulating certificates and TGTs

[getnthash.py](https://github.com/dirkjanm/PKINITtools/blob/master/getnthash.py): This tool will use an existing TGT to request a PAC for the current user using U2U

[gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt): Extracts usernames and passwords from Group Policy preferences files

[GetNPUsers.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py): Part of the Impacket toolkit. Used to perform the ASREPRoasting attack to list and obtain AS-REP hashes for users with the 'Do not require Kerberos preauthentication' set

[lookupsid.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/lookupsid.py): SID bruteforcing tool

[ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py): A tool for creation and customization of TGT/TGS tickets

[raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py): Part of the Impacket toolkit, It is a tool for automated child to parent domain privilege escalation



### Post-Exploitation

[CrackMapExec (CME)](https://github.com/byt3bl33d3r/CrackMapExec): CME is an enumeration, attack, and post-exploitation toolkit, it attempts to "live off the land"

### Auditing

[PingCastle](https://www.pingcastle.com/documentation/): [PingCastle](https://www.pingcastle.com/documentation/)

[Group3r](https://github.com/Group3r/Group3r): Group3r is useful for auditing and finding security misconfigurations in AD Group Policy Objects (GPO)

[ADRecon](https://github.com/adrecon/ADRecon): A tool used to extract various data from a target AD environment, which can be output in Excel format