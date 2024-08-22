The tester started with an Nmap scan to identify open ports.
```shell-session
# nmap -T4 -p- 10.129.186.118 -oN Scans/nmap_all_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-30 10:20 IDT
Nmap scan report for trilocor.local (10.129.186.118)
Host is up (0.095s latency).
Not shown: 65524 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
25/tcp   open  smtp
53/tcp   open  domain
80/tcp   open  http
110/tcp  open  pop3
111/tcp  open  rpcbind
143/tcp  open  imap
993/tcp  open  imaps
995/tcp  open  pop3s
7777/tcp open  cbt

Nmap done: 1 IP address (1 host up) scanned in 42.29 seconds
```

The tester then proceeded to perform a more detailed scan on the open ports.
```shell-session
# nmap -sV -sC -p 21,22,25,53,80,110,111,143,993,995,7777 10.129.186.118 -oN Scans/nmap_open_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-30 10:23 IDT
Nmap scan report for trilocor.local (10.129.186.118)
Host is up (0.067s latency).

PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0               0 Sep 14  2022 Uninstaller.lnk
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.14
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 71:08:b0:c4:f3:ca:97:57:64:97:70:f9:fe:c5:0c:7b (RSA)
|   256 45:c3:b5:14:63:99:3d:9e:b3:22:51:e5:97:76:e1:50 (ECDSA)
|_  256 2e:c2:41:66:46:ef:b6:81:95:d5:aa:35:23:94:55:38 (ED25519)
25/tcp   open  smtp     Postfix smtpd
|_smtp-commands: WEB-NIX01, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp   open  domain   (unknown banner: ISC BIND 9 (Ubuntu Linux))
| dns-nsid: 
|_  bind.version: ISC BIND 9 (Ubuntu Linux)
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|     bind
|_    BIND 9 (Ubuntu Linux)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Trilocor &#8211; A cutting edge robotics company!
|_http-generator: WordPress 5.8.3
110/tcp  open  pop3     Dovecot pop3d
|_pop3-capabilities: SASL STLS AUTH-RESP-CODE PIPELINING CAPA UIDL TOP RESP-CODES
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-08-03T08:24:29
|_Not valid after:  2032-07-31T08:24:29
111/tcp  open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
143/tcp  open  imap     Dovecot imapd (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-08-03T08:24:29
|_Not valid after:  2032-07-31T08:24:29
|_imap-capabilities: Pre-login STARTTLS IMAP4rev1 LOGINDISABLEDA0001 more listed capabilities IDLE ENABLE ID post-login LOGIN-REFERRALS OK have LITERAL+ SASL-IR
993/tcp  open  ssl/imap Dovecot imapd (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-08-03T08:24:29
|_Not valid after:  2032-07-31T08:24:29
|_imap-capabilities: Pre-login IMAP4rev1 more AUTH=PLAINA0001 listed post-login IDLE ENABLE ID capabilities LOGIN-REFERRALS OK have LITERAL+ SASL-IR
995/tcp  open  ssl/pop3 Dovecot pop3d
|_pop3-capabilities: USER SASL(PLAIN) AUTH-RESP-CODE PIPELINING CAPA UIDL TOP RESP-CODES
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-08-03T08:24:29
|_Not valid after:  2032-07-31T08:24:29
|_ssl-date: TLS randomness does not represent time
7777/tcp open  http     Werkzeug httpd 2.2.1 (Python 3.8.10)
|_http-server-header: Werkzeug/2.2.1 Python/3.8.10
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.94SVN%I=7%D=7/30%Time=66A89519%P=x86_64-pc-linux-gnu%r(D
SF:NSVersionBindReqTCP,46,"\0D\0\x06\x85\0\0\x01\0\x01\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03\xc0\x0c\0\x10\0\x03\0\0\0\0\0\x1a\x19ISC\x20BIND\
SF:x209\x20\(Ubuntu\x20Linux\)");
Service Info: Host:  WEB-NIX01; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.32 seconds
```

While the above scan is running, the tester attempted to discover subdomains of the target website, using DNS zone transfer.
```shell-session
# dig axfr @10.129.186.118 trilocor.local                   

; <<>> DiG 9.19.19-1-Debian <<>> axfr @10.129.186.118 trilocor.local
; (1 server found)
;; global options: +cmd
trilocor.local.         86400   IN      SOA     ns1.trilocor.local. dnsadmin.trilocor.local. 21 604800 86400 2419200 86400
trilocor.local.         86400   IN      NS      trilocor.local.
trilocor.local.         86400   IN      A       127.0.0.1
blog.trilocor.local.    86400   IN      A       127.0.0.1
careers.trilocor.local. 86400   IN      A       127.0.0.1
dev.trilocor.local.     86400   IN      A       127.0.0.1
portal.trilocor.local.  86400   IN      A       127.0.0.1
pr.trilocor.local.      86400   IN      A       127.0.0.1
remote.trilocor.local.  86400   IN      A       127.0.0.1
store.trilocor.local.   86400   IN      A       127.0.0.1
trilocor.local.         86400   IN      SOA     ns1.trilocor.local. dnsadmin.trilocor.local. 21 604800 86400 2419200 86400
;; Query time: 68 msec
;; SERVER: 10.129.186.118#53(10.129.186.118) (TCP)
;; WHEN: Tue Jul 30 10:24:29 IDT 2024
;; XFR size: 11 records (messages 1, bytes 338)
```
