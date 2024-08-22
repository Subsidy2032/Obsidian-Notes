#bufferoverflow #notfinished
### Nmap

```nmap
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 12:57:3f:cc:86:39:04:3b:f0:e6:46:bf:72:51:64:0b (RSA)
|   256 81:05:75:ad:78:83:62:b2:06:41:5b:e5:a5:a9:82:4d (ECDSA)
|_  256 0f:8d:0e:19:e9:c7:cc:14:39:e9:34:60:5c:f7:aa:fe (ED25519)
80/tcp   open  http          Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  EtherNetIP-1?
| fingerprint-strings: 
|   DNSStatusRequestTCP, GenericLines, NULL, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     Welcome to the NoNameCTF!
|     Choose an action:
|     regiser: 1
|     login: 2
|     get_secret_directory: 3
|     store_your_buffer: 4
|   GetRequest, HTTPOptions, Help, RTSPRequest: 
|     Welcome to the NoNameCTF!
|     Choose an action:
|     regiser: 1
|     login: 2
|     get_secret_directory: 3
|     store_your_buffer: 4
|     Wrong option
|_    Good bye
9090/tcp open  http          Tornado httpd 6.0.3
|_http-title: Site doesn't have a title (text/plain).
|_http-server-header: TornadoServer/6.0.3
```

### Port 2222

Was able to connect with Netcat:

![[Pasted image 20231122211828.png]]

