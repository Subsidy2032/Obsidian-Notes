## TFTP

Trivial File Transfer Protocol (TFTP) is simpler than FTP, it doesn't provide authentication and other features of FTP, and it uses UDP with UDP-assisted application layer recovery.

TFTP sets limits on access solely based on read and write permissions of a file in the operating system, practically this leads to TFTP operating exclusively in directories and with files that have been shared with all users and can be read and written globally.

### TFTP Commands
|**Commands**|**Description**|
|---|---|
|`connect`|Sets the remote host, and optionally the port, for file transfers.|
|`get`|Transfers a file or set of files from the remote host to the local host.|
|`put`|Transfers a file or set of files from the local host onto the remote host.|
|`quit`|Exits tftp.|
|`status`|Shows the current status of tftp, including the current transfer mode (ascii or binary), connection status, time-out value, and so on.|
|`verbose`|Turns verbose mode, which displays additional information during file transfer, on or off.|

Unlike FTP it doesn't have directory listing capability.

## Default Configuration

[vsFTPd](https://security.appspot.com/vsftpd.html) is the most used FTP server in Linux distributions, the default configuration can be found in `/etc/vsftpd.conf`.

### vsFTPd Config File
| **Setting** | **Description** |
| ---- | ---- |
| `listen=NO` | Run from inetd or as a standalone daemon? |
| `listen_ipv6=YES` | Listen on IPv6 ? |
| `anonymous_enable=NO` | Enable Anonymous access? |
| `local_enable=YES` | Allow local users to login? |
| `dirmessage_enable=YES` | Display active directory messages when users go into certain directories? |
| `use_localtime=YES` | Use local time? |
| `xferlog_enable=YES` | Activate logging of uploads/downloads? |
| `connect_from_port_20=YES` | Connect from port 20? |
| `secure_chroot_dir=/var/run/vsftpd/empty` | Name of an empty directory |
| `pam_service_name=vsftpd` | This string is the name of the PAM service vsftpd will use. |
| `rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem` | The last three options specify the location of the RSA certificate to use for SSL encrypted connections. |
| `rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key` |  |
| `ssl_enable=NO` |  |

There is also the `/etc/ftpusers` file, which is used to deny access to the FTP service for certain users.

## Dangerous Settings

### Anonymous Login Settings
|   |   |
|---|---|
|`anonymous_enable=YES`|Allowing anonymous login?|
|`anon_upload_enable=YES`|Allowing anonymous to upload files?|
|`anon_mkdir_write_enable=YES`|Allowing anonymous to create new directories?|
|`no_anon_password=YES`|Do not ask anonymous for password?|
|`anon_root=/home/username/ftp`|Directory for anonymous.|
|`write_enable=YES`|Allow the usage of FTP commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE?|

As soon as we connect to the vsFTPd server, the response code 220 is displayed with the banner of FTP server, it contains the description and version of the service, and the type of system it runs on. With anonymous login settings enabled, we can get some information from just reading the files even if we do not have access to them.

### vsFTPd status

We can use the `status` command to check the status.

### vsFTPd Detailed Output

The `debug` and `trace` commands can make the server show us more information.

| **Setting** | **Description** |
| ---- | ---- |
| `dirmessage_enable=YES` | Show a message when they first enter a new directory? |
| `chown_uploads=YES` | Change ownership of anonymously uploaded files? |
| `chown_username=username` | User who is given ownership of anonymously uploaded files. |
| `local_enable=YES` | Enable local users to login? |
| `chroot_local_user=YES` | Place local users into their home directory? |
| `chroot_list_enable=YES` | Use a list of local users that will be placed in their home directory? |
| `hide_ids=YES` | All user and group information in directory listings will be displayed as "ftp". |
| `ls_recurse_enable=YES` | Allows the use of recurse listings. |

### Download All Files and Folders We have Access to at Once
```shell-session
$ wget -m --no-passive ftp://anonymous:anonymous@<ip address>
```

All the downloaded files will be stored in a directory with the name of the IP address of the target.

### Uploading Files

If we have permissions we can upload files with the `put` command which can even lead to a reverse shell.

## Footprinting the Service

### Update Nmap Database of NSE Scripts
```shell-session
$ sudo nmap --script-updatedb
```

### Find All FTP Scripts
```shell-session
$ find / -type f -name ftp* 2>/dev/null | grep scripts
```

### Nmap Script Trace
```shell-session
$ sudo nmap -sV -p21 -sC -A <ip address> --script-trace
```

### Service Interaction
```shell-session
$ nc -nv <ip address> 21
```
```shell-session
$ telnet <ip address> 21
```

### In Case of the Service Running With TLS/SSL
```shell-session
$ openssl s_client -connect <ip address>:21 -starttls ftp
```

We can get the SSL certificate from this command, which allows us to recognize the hostname and in most cases an email address for the company, and also a specific location in case the company has several.