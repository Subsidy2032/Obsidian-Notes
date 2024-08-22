## Nmap Scans

### Initial

```
# nmap -sV -sC -T4 10.129.202.41 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-17 11:51 EST
Nmap scan report for 10.129.202.41
Host is up (0.10s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
111/tcp  open  rpcbind?
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
2049/tcp open  mountd        1-3 (RPC #100005)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-02-17T16:53:07+00:00; +1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: WINMEDIUM
|   NetBIOS_Domain_Name: WINMEDIUM
|   NetBIOS_Computer_Name: WINMEDIUM
|   DNS_Domain_Name: WINMEDIUM
|   DNS_Computer_Name: WINMEDIUM
|   Product_Version: 10.0.17763
|_  System_Time: 2024-02-17T16:52:56+00:00
| ssl-cert: Subject: commonName=WINMEDIUM
| Not valid before: 2024-02-16T16:51:32
|_Not valid after:  2024-08-17T16:51:32
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-02-17T16:53:07
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 88.34 seconds
```

### Full Port Scan

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-17 12:27 EST
Warning: 10.129.202.41 giving up on port because retransmission cap hit (6).
Stats: 0:13:41 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 88.66% done; ETC: 12:42 (0:01:45 remaining)
Nmap scan report for 10.129.202.41
Host is up (0.080s latency).
Not shown: 63539 closed tcp ports (reset), 1980 filtered tcp ports (no-response)
PORT      STATE SERVICE
111/tcp   open  rpcbind
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
2049/tcp  open  nfs
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49679/tcp open  unknown
49680/tcp open  unknown
49681/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 960.65 seconds
```

### NFS

```
# nmap -sV -p 111,2049 10.129.202.41 --script nfs*
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-17 11:57 EST
Nmap scan report for 10.129.202.41
Host is up (0.080s latency).

PORT     STATE SERVICE  VERSION
111/tcp  open  rpcbind?
| rpcinfo: 
|   program version    port/proto  service
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|_  100003  2,3,4       2049/tcp6  nfs
2049/tcp open  nfs      2-4 (RPC #100003)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.68 seconds
```

## NFS

### Mounting NFS Shares

![[Pasted image 20240217190337.png]]

### Interesting Text File

```
Conversation with InlaneFreight Ltd

Started on November 10, 2021 at 01:27 PM London time GMT (GMT+0200)
---
01:27 PM | Operator: Hello,. 
 
So what brings you here today?
01:27 PM | alex: hello
01:27 PM | Operator: Hey alex!
01:27 PM | Operator: What do you need help with?
01:36 PM | alex: I run into an issue with the web config file on the system for the smtp server. do you mind to take a look at the config?
01:38 PM | Operator: Of course
01:42 PM | alex: here it is:

 1smtp {
 2    host=smtp.web.dev.inlanefreight.htb
 3    #port=25
 4    ssl=true
 5    user="alex"
 6    password="lol123!mD"
 7    from="alex.g@web.dev.inlanefreight.htb"
 8}
 9
10securesocial {
11    
12    onLoginGoTo=/
13    onLogoutGoTo=/login
14    ssl=false
15    
16    userpass {      
17      withUserNameSupport=false
18      sendWelcomeEmail=true
19      enableGravatarSupport=true
20      signupSkipLogin=true
21      tokenDuration=60
22      tokenDeleteInterval=5
23      minimumPasswordLength=8
24      enableTokenJob=true
25      hasher=bcrypt
26      }
27
28     cookie {
29     #       name=id
30     #       path=/login
31     #       domain="10.129.2.59:9500"
32            httpOnly=true
33            makeTransient=false
34            absoluteTimeoutInMinutes=1440
35            idleTimeoutInMinutes=1440
36    }
```

## SMB

### Found Shares

```
# smbmap -u alex -p "lol123!mD" -H 10.129.202.41
[+] IP: 10.129.202.41:445       Name: 10.129.202.41                                     
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote 
        C$                                                      NO ACCESS       Default 
        devshare                                                READ, WRITE
        IPC$                                                    READ ONLY       Remote 
        Users
```

#### devshare

![[Pasted image 20240217204447.png]]

#### important.txt File contents

`sa:87N1ns@slls83`

## Connecting With RDP

![[Pasted image 20240217210350.png]]

### Opened SQL Server as Administrator With the Found Credentials

#### Found the Password

![[Pasted image 20240217214101.png]]