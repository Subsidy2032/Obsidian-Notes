## SSH

SSH is implemented natively on Linux and macOS distributions, and can be installed on Windows systems. The well-known [OpenBSD SSH](https://www.openssh.com/) (`OpenSSH`) server on Linux distributions is an open-source fork of the original and commercial `SSH` server from SSH Communication Security. Accordingly, there are two competing protocols: `SSH-1` and `SSH-2`.

`SSH-2`, also known as SSH version 2, is a more advanced protocol than SSH version 1 in encryption, speed, stability, and security. For example, `SSH-1` is vulnerable to `MITM` attacks, whereas SSH-2 is not.

OpenSSH authentication methods:

1. Password authentication
2. Public-key authentication
3. Host-based authentication
4. Keyboard authentication
5. Challenge-response authentication
6. GSSAPI authentication

### Public Key Authentication

First the server proves its identity using a certificate, the server than sends a challenge with the public be which the client decrypts with the private key and sends it back to the server, the passphrase should only be used once during each session until the user logs out.

## Default Configuration

The [sshd_config](https://www.ssh.com/academy/ssh/sshd_config) file, responsible for the OpenSSH server, has only a few of the settings configured by default. However, the default configuration includes X11 forwarding, which contained a command injection vulnerability in version 7.2p1 of OpenSSH in 2016. Nevertheless, we do not need a GUI to manage our servers.

### Default Configuration
```shell-session
$ cat /etc/ssh/sshd_config  | grep -v "#" | sed -r '/^\s*$/d'
```

## Dangerous Settings
|**Setting**|**Description**|
|---|---|
|`PasswordAuthentication yes`|Allows password-based authentication.|
|`PermitEmptyPasswords yes`|Allows the use of empty passwords.|
|`PermitRootLogin yes`|Allows to log in as the root user.|
|`Protocol 1`|Uses an outdated version of encryption.|
|`X11Forwarding yes`|Allows X11 forwarding for GUI applications.|
|`AllowTcpForwarding yes`|Allows forwarding of TCP ports.|
|`PermitTunnel`|Allows tunneling.|
|`DebianBanner yes`|Displays a specific banner when logging in.|

## Footprinting the Service

[ssh-audit](https://github.com/jtesta/ssh-audit) checks the server-side and client-side configuration, and shows some general information and which end which encryption algorithms are still used by the client and server.

```shell-session
$ git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
$ ./ssh-audit.py <ip address>
```

### Change Authentication Method
```shell-session
$ ssh -v <username>@<ip address> -o PreferredAuthentications=password
```

By default the banners start with the version of the protocol that can be applied and than the version of the server itself, SSH-1.99 means we can use both protocol versions SSH-1 and SSH-2.

## Rsync

[Rsync](https://linux.die.net/man/1/rsync) is a fast and efficient tool to copy files locally and remotely, It is highly versatile and well-known for its delta-transfer algorithm. This algorithm only sends the difference between the source files and the version of the files on the destination server, which reduces the amount of data transmitted. It is often used for backup and mirroring it finds file that should be transmitted based on the size and last modified time. By default it uses port 873 and can be configured to use SSH by piggybacking on top of an established SSH server connection.

This [guide](https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync) covers some of the ways Rsync can be abused, sometimes we'll need credentials to list the contents of a shared folder and retrieve files and sometimes we won't. It's always good to check for password re-use when finding credentials.

### Scanning for Rsync
```shell-session
$ sudo nmap -sV -p 873 127.0.0.1
```

### Probing for Accessible Shares
```shell-session
$ nc -nv 127.0.0.1 873

(UNKNOWN) [127.0.0.1] 873 (rsync) open
@RSYNCD: 31.0
@RSYNCD: 31.0
#list
dev            	Dev Tools
@RSYNCD: EXIT
```

### Enumerating an Open Share
```shell-session
$ rsync -av --list-only rsync://127.0.0.1/dev
```

To sync all files to our machine we can use the command `rsync -av rsync://127.0.0.1/dev`, if Rsync is using SSH we can add `-e ssh` or `-e ssh -p2222` for non standard port in our command.

## R-Services

R-Services is a suit of services hosted to enable remote access or issue command between Unix hosts over TCP/IP, initially developed by the Computer Systems Research Group (`CSRG`), it was the de facto standard for remote access until it was replaced by SSH. It was insecure due to transmission of data unencrypted.

R-Services span across the ports `512`, `513`, and `514` and are only accessible through a suit of programs known as r-commands, they are most commonly used by commercial operating systems such as Solaris, HP-UX, and AIX. While less common now days, we still can run into them from time to time.

The [R-commands](https://en.wikipedia.org/wiki/Berkeley_r-commands) suite consists of the following programs:

- rcp (`remote copy`)
- rexec (`remote execution`)
- rlogin (`remote login`)
- rsh (`remote shell`)
- rstat
- ruptime
- rwho (`remote who`)

### Most Frequently Abused Commands
|**Command**|**Service Daemon**|**Port**|**Transport Protocol**|**Description**|
|---|---|---|---|---|
|`rcp`|`rshd`|514|TCP|Copy a file or directory bidirectionally from the local system to the remote system (or vice versa) or from one remote system to another. It works like the `cp` command on Linux but provides `no warning to the user for overwriting existing files on a system`.|
|`rsh`|`rshd`|514|TCP|Opens a shell on a remote machine without a login procedure. Relies upon the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files for validation.|
|`rexec`|`rexecd`|512|TCP|Enables a user to run shell commands on a remote machine. Requires authentication through the use of a `username` and `password` through an unencrypted network socket. Authentication is overridden by the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files.|
|`rlogin`|`rlogind`|513|TCP|Enables a user to log in to a remote host over the network. It works similarly to `telnet` but can only connect to Unix-like hosts. Authentication is overridden by the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files.|

The `/etc/hosts.equiv` contains a list of trusted hosts, users on this list do not need authentication.

### /etc/hosts.equiv
```shell-session
$ cat /etc/hosts.equiv

# <hostname> <local username>
pwnbox cry0l1t3
```

### Scanning for R-Services
```shell-session
$ sudo nmap -sV -p 512,513,514 <ip address>
```

### Access Control & Trusted Relationships

R-Services relay on the information sent from the remote client to the host machine, By default, these services utilize [Pluggable Authentication Modules (PAM)](https://debathena.mit.edu/trac/wiki/PAM) for user authentication onto a remote system, however it's also bypassed by the `/etc/hosts.equiv` and `.rhosts` files, those files contain a list of hosts (IPs or Hostnames) and users that are trusted by the local host when a connection attempt is made using r-commands.

**Note:** The `hosts.equiv` file is recognized as the global configuration regarding all users on a system, whereas `.rhosts` provides a per-user configuration.

### Sample .rhosts File
```shell-session
$ cat .rhosts

htb-student     10.0.17.5
+               10.0.17.10
+               +
```

The `+` modifier can be used as a wildcard to specify anything, in the above example the `+` modifier allows access to r-commands from the htb-student account with IP address `10.0.17.10`.

Misconfigurations can allow us to authenticate as another user without credentials.

### logging in Using Rlogin
```shell-session
$ rlogin <ip address> -l <username>
```

The `rwho` command will list all interactive sessions on the local network, by sending request to the UDP port 513.

### Listing Authenticated Users Using Rwho
```shell-session
$ rwho
```

It might be beneficial to watch the network traffic since `rwho` periodically broadcast information about logged in users.

### Listing Authenticated Users Using Rusers

This will give us more detailed account of all logged in users over the network, including information such as username, hostname of the accessed machine, TTY that the user is logged in to, the date and time the user logged in, the amount of time since the user typed on the keyboard, and the remote host they logged in from (if applicable).

```shell-session
$ rusers -al 10.0.17.5

htb-student     10.0.17.5:console          Dec 2 19:57     2:25
```

