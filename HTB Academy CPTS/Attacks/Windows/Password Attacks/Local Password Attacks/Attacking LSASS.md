In logon LSASS will:

- Cache credentials locally in memory
- Create [access tokens](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- Enforce security policies
- Write to Windows [security log](https://docs.microsoft.com/en-us/windows/win32/eventlog/event-logging-security)

## Dumping LSASS Process Memory

### Task Manager Method
![[taskmanagerdump.webp]]

The `lsass.DMP` file will be saved in:
```cmd-session
C:\Users\loggedonusersdirectory\AppData\Local\Temp
```

A way to transfer the file is discussed in [[Attacking SAM]]

### Finding LSASS PID in CMD
```cmd-session
C:\Windows\system32> tasklist /svc
```

### Finding LSASS PID in PowerShell
```powershell-session
PS C:\Windows\system32> Get-Process lsass
```

#### Creating lsass.dmp using PowerShell
```powershell-session
PS C:\Windows\system32> rundll32 C:\windows\system32\comsvcs.dll, MiniDump 652 C:\lsass.dmp full
```

## Using Pypykatz to Extract Credentials

We can use [pypykatz](https://github.com/skelsec/pypykatz) for extracting credentials from the dmp file, Pypykatz is an implementation of Mimikatz written entirely in Python, which gives us the ability to run it on Linux.

LSASS only stores credentials with active logon sessions.

### Running Pypykatz
```shell-session
$ pypykatz lsa minidump <lsass.dmp file path>
```

### MSV
[MSV](https://docs.microsoft.com/en-us/windows/win32/secauthn/msv1-0-authentication-package) is an authentication package in Windows that LSA calls on to validate logon attempts against the SAM database.

### WDIGEST
WDIGEST is an old authentication protocol used with old Windows machines, LSASS stores credentials used by WDIGEST in clear text, Microsoft released a security update for this issue.

### Kerberos
LSASS `caches passwords`, `ekeys`, `tickets`, and `pins` associated with Kerberos. It is possible to extract these from LSASS process memory and use them to access other systems joined to the same domain.

### DPAPI
The Data Protection Application Programming Interface or [DPAPI](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection) is a set of APIs in Windows operating systems used to encrypt and decrypt DPAPI data blobs on a per-user basis for Windows OS features and various third-party applications.

With Mimikatz and Pypykatz we can extract the DPAPI master key for the data of logged in users, this master key can be used to decrypt the secrets associated with the applications that use DPAPI.

#### Examples of applications that use DPAPI
|Applications|Use of DPAPI|
|---|---|
|`Internet Explorer`|Password form auto-completion data (username and password for saved sites).|
|`Google Chrome`|Password form auto-completion data (username and password for saved sites).|
|`Outlook`|Passwords for email accounts.|
|`Remote Desktop Connection`|Saved credentials for connections to remote machines.|
|`Credential Manager`|Saved credentials for accessing shared resources, joining Wireless networks, VPNs and more.|

### Cracking the NT Hash With Hashcat
```shell-session
$ sudo hashcat -m 1000 <hash> /usr/share/wordlists/rockyou.txt
```