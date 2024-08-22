## Nmap Scans

### Initial

```
# nmap -sV -sC -T4 10.129.181.162                         
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-17 11:26 EST
Nmap scan report for 10.129.181.162
Host is up (0.080s latency).
Not shown: 944 closed tcp ports (reset), 52 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp?
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (ftp.int.inlanefreight.htb) [10.129.181.162]
|     Invalid command: try being more creative
|     Invalid command: try being more creative
|   NULL: 
|_    220 ProFTPD Server (ftp.int.inlanefreight.htb) [10.129.181.162]
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3f:4c:8f:10:f1:ae:be:cd:31:24:7c:a1:4e:ab:84:6d (RSA)
|   256 7b:30:37:67:50:b9:ad:91:c0:8f:f7:02:78:3b:7c:02 (ECDSA)
|_  256 88:9e:0e:07:fe:ca:d0:5c:60:ab:cf:10:99:cd:6c:a7 (ED25519)
53/tcp   open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
2121/tcp open  ftp?
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (Ceil's FTP) [10.129.181.162]
|     Invalid command: try being more creative
|     Invalid command: try being more creative
|   NULL: 
|_    220 ProFTPD Server (Ceil's FTP) [10.129.181.162]
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port21-TCP:V=7.94SVN%I=7%D=2/17%Time=65D0DE39%P=x86_64-pc-linux-gnu%r(N
SF:ULL,41,"220\x20ProFTPD\x20Server\x20\(ftp\.int\.inlanefreight\.htb\)\x2
SF:0\[10\.129\.181\.162\]\r\n")%r(GenericLines,9D,"220\x20ProFTPD\x20Serve
SF:r\x20\(ftp\.int\.inlanefreight\.htb\)\x20\[10\.129\.181\.162\]\r\n500\x
SF:20Invalid\x20command:\x20try\x20being\x20more\x20creative\r\n500\x20Inv
SF:alid\x20command:\x20try\x20being\x20more\x20creative\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port2121-TCP:V=7.94SVN%I=7%D=2/17%Time=65D0DE39%P=x86_64-pc-linux-gnu%r
SF:(NULL,32,"220\x20ProFTPD\x20Server\x20\(Ceil's\x20FTP\)\x20\[10\.129\.1
SF:81\.162\]\r\n")%r(GenericLines,8E,"220\x20ProFTPD\x20Server\x20\(Ceil's
SF:\x20FTP\)\x20\[10\.129\.181\.162\]\r\n500\x20Invalid\x20command:\x20try
SF:\x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x20try\x20b
SF:eing\x20more\x20creative\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 128.36 seconds
```

## Getting all the FTP Files

![[Pasted image 20240217184852.png]]

## SSH

### Logging in With the SSH Key

![[Pasted image 20240217184636.png]]

### Getting the Flag

![[Pasted image 20240217184741.png]]
