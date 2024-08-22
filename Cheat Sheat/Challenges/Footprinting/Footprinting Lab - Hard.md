## Nmap Scans

### All Ports

```
# nmap -p- -T4 10.129.202.20                                              
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-17 14:42 EST
Stats: 0:00:35 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 18.01% done; ETC: 14:45 (0:02:39 remaining)
Warning: 10.129.202.20 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.129.202.20
Host is up (0.072s latency).
Not shown: 64081 closed tcp ports (reset), 1449 filtered tcp ports (no-response)
PORT    STATE SERVICE
22/tcp  open  ssh
110/tcp open  pop3
143/tcp open  imap
993/tcp open  imaps
995/tcp open  pop3s

Nmap done: 1 IP address (1 host up) scanned in 876.68 seconds
```

### Open Ports

```
# nmap -sV -sC -p22,110,143,993,995 10.129.202.20
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-17 14:58 EST
Nmap scan report for 10.129.202.20
Host is up (0.073s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3f:4c:8f:10:f1:ae:be:cd:31:24:7c:a1:4e:ab:84:6d (RSA)
|   256 7b:30:37:67:50:b9:ad:91:c0:8f:f7:02:78:3b:7c:02 (ECDSA)
|_  256 88:9e:0e:07:fe:ca:d0:5c:60:ab:cf:10:99:cd:6c:a7 (ED25519)
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: AUTH-RESP-CODE STLS USER SASL(PLAIN) PIPELINING RESP-CODES UIDL CAPA TOP
143/tcp open  imap     Dovecot imapd (Ubuntu)
|_imap-capabilities: LITERAL+ IMAP4rev1 more IDLE STARTTLS OK post-login ENABLE LOGIN-REFERRALS have listed capabilities Pre-login ID AUTH=PLAINA0001 SASL-IR
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25
993/tcp open  ssl/imap Dovecot imapd (Ubuntu)
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25
|_imap-capabilities: LITERAL+ IMAP4rev1 IDLE AUTH=PLAINA0001 OK post-login ENABLE LOGIN-REFERRALS have more listed capabilities ID Pre-login SASL-IR
|_ssl-date: TLS randomness does not represent time
995/tcp open  ssl/pop3 Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25
|_pop3-capabilities: USER SASL(PLAIN) UIDL AUTH-RESP-CODE PIPELINING TOP CAPA RESP-CODES
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.07 seconds
```

### SNMP Scan

```
nmap -sU 10.129.202.20 -p161 -sV -sC 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-18 03:50 EST
Nmap scan report for 10.129.202.20
Host is up (0.76s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    net-snmp; net-snmp SNMPv3 server
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: 5b99e75a10288b6100000000
|   snmpEngineBoots: 10
|_  snmpEngineTime: 45m06s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.41 seconds
```

## SNMP

### Community String

![[Pasted image 20240218105246.png]]

### braa

```
braa backup@10.129.202.20:.1.3.6.*                   
10.129.202.20:102ms:.0:Linux NIXHARD 5.4.0-90-generic #101-Ubuntu SMP Fri Oct 15 20:00:55 UTC 2021 x86_64
10.129.202.20:102ms:.0:.10
10.129.202.20:103ms:.0:293148
10.129.202.20:104ms:.0:Admin <tech@inlanefreight.htb>
10.129.202.20:105ms:.0:NIXHARD
10.129.202.20:104ms:.0:Inlanefreight
10.129.202.20:104ms:.0:72
10.129.202.20:104ms:.0:18
10.129.202.20:108ms:.1:.1
10.129.202.20:104ms:.2:.1
10.129.202.20:103ms:.3:.1
10.129.202.20:105ms:.4:.1
10.129.202.20:105ms:.5:.1
10.129.202.20:107ms:.6:.49
10.129.202.20:103ms:.7:.4
10.129.202.20:103ms:.8:.50
10.129.202.20:104ms:.9:.3
10.129.202.20:103ms:.10:.92
10.129.202.20:103ms:.1:The SNMP Management Architecture MIB.
10.129.202.20:102ms:.2:The MIB for Message Processing and Dispatching.
10.129.202.20:103ms:.3:The management information definitions for the SNMP User-based Security Model.
10.129.202.20:102ms:.4:The MIB module for SNMPv2 entities
10.129.202.20:102ms:.5:View-based Access Control Model for SNMP.
10.129.202.20:103ms:.6:The MIB module for managing TCP implementations
10.129.202.20:103ms:.7:The MIB module for managing IP and ICMP implementations
10.129.202.20:103ms:.8:The MIB module for managing UDP implementations
10.129.202.20:101ms:.9:The MIB modules for managing SNMP Notification, plus filtering.
10.129.202.20:102ms:.10:The MIB module for logging SNMP Notifications.
10.129.202.20:104ms:.1:18
10.129.202.20:104ms:.2:18
10.129.202.20:102ms:.3:18
10.129.202.20:103ms:.4:18
10.129.202.20:102ms:.5:18
10.129.202.20:102ms:.6:18
10.129.202.20:102ms:.7:18
10.129.202.20:102ms:.8:18
10.129.202.20:104ms:.9:18
10.129.202.20:103ms:.10:18
10.129.202.20:104ms:.0:294398
10.129.202.20:102ms:.0:6
10.129.202.20:102ms:.0:393216
10.129.202.20:110ms:.0:BOOT_IMAGE=/vmlinuz-5.4.0-90-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro ipv6.disable=1 maybe-ubiquity

10.129.202.20:102ms:.0:0
10.129.202.20:103ms:.0:163
10.129.202.20:102ms:.0:0
10.129.202.20:103ms:.0:1
10.129.202.20:106ms:.80:/opt/tom-recovery.sh
10.129.202.20:102ms:.80:tom NMds732Js2761
10.129.202.20: Message cannot be decoded!
10.129.202.20: Message cannot be decoded!
10.129.202.20: Message cannot be decoded!
```

## IMAP

### Connecting to IMAP

![[Pasted image 20240218220512.png]]

Used `1 LOGIN tom NMds732Js2761` to login.

Used `1 STATUS INBOX (MESSAGES)` and found out there is 1 message in inbox.

Selected INBOX with `1 SELECT INBOX`.

Fetched all messages with `1 FETCH 1 all`.

Used `1 FETCH 1 body[text]` To get the SSH key.

### Output

```
"Wed, 10 Nov 2010 14:21:26 +0200" "KEY" ((NIL NIL "MISSING_MAILBOX" "MISSING_DOMAIN")) ((NIL NIL "MISSING_MAILBOX" "MISSING_DOMAIN")) ((NIL NIL "MISSING_MAILBOX" "MISSING_DOMAIN")) ((NIL NIL "tom" "inlanefreight.htb")) NIL NIL NIL NIL))
1 OK Fetch completed (0.001 + 0.000 secs).
```

### SSH Key

```
HELO dev.inlanefreight.htb
MAIL FROM:<tech@dev.inlanefreight.htb>
RCPT TO:<bob@inlanefreight.htb>
DATA
From: [Admin] <tech@inlanefreight.htb>
To: <tom@inlanefreight.htb>
Date: Wed, 10 Nov 2010 14:21:26 +0200
Subject: KEY

-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

Found another user: cry0l1t3

## MySQL

Connecting to MySQL with `mysql -u tom -pNMds732Js2761`

Found password: `cr3n4o7rzse7rzhnckhssncif7ds`