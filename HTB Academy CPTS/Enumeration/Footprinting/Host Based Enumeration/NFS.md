The purpose of Network File System (NFS) is like SMB, accessing a file system over a network, this is used between Linux and Unix systems which cannot directly communicate with the SMB servers. NFS is an internet standard that governs the procedures in distributed file system. NFSv3 authenticates the client computer, while with NFSv4 the user must authenticate like with the Windows SMB protocol.

|**Version**|**Features**|
|---|---|
|`NFSv2`|It is older but is supported by many systems and was initially operated entirely over UDP.|
|`NFSv3`|It has more features, including variable file size and better error reporting, but is not fully compatible with NFSv2 clients.|
|`NFSv4`|It includes Kerberos, works through firewalls and on the Internet, no longer requires portmappers, supports ACLs, applies state-based operations, and provides performance improvements and high security. It is also the first version to have a stateful protocol.|

NFS version 4.1 aims to provide protocol support to leverage cluster server deployments, with the ability of parallel access to files in multiple servers (pNFS extension), it also includes a session trunking mechanism also known as NFS multipathing. One advantage of NFSv4 is that it only runs on single UDP or TCP port 2049 simplifies the use with firewalls.

NFS is based on the [Open Network Computing Remote Procedure Call](https://en.wikipedia.org/wiki/Sun_RPC) (`ONC-RPC`/`SUN-RPC`) protocol exposed on TCP and UDP ports 111, which uses [External Data Representation](https://en.wikipedia.org/wiki/External_Data_Representation) (`XDR`) for the system independent exchange of data. The authentication is completely shifted to the RPC protocol's options, the authorization is derived from the available file system information, and the server is responsible for translation.

The most common form of authentication is via UNIX UID/GID and group membership, one problem is the the server and client might not have the same mapping of UID/GID.

## Default Configuration

The `/etc/exports` contains a table of physical file systems accessible. The [NFS Exports Table](http://manpages.ubuntu.com/manpages/trusty/man5/exports.5.html) shows which options it accepts and thus indicates which options are available to us.

|**Option**|**Description**|
|---|---|
|`rw`|Read and write permissions.|
|`ro`|Read only permissions.|
|`sync`|Synchronous data transfer. (A bit slower)|
|`async`|Asynchronous data transfer. (A bit faster)|
|`secure`|Ports above 1024 will not be used.|
|`insecure`|Ports above 1024 will be used.|
|`no_subtree_check`|This option disables the checking of subdirectory trees.|
|`root_squash`|Assigns all permissions to files of root UID/GID 0 to the UID/GID of anonymous, which prevents `root` from accessing files on an NFS mount.|

### Example of adding a folder
```shell-session
root@nfs:~# echo '/mnt/nfs  <ip address>/24(sync,no_subtree_check)' >> /etc/exports
root@nfs:~# systemctl restart nfs-kernel-server 
root@nfs:~# exportfs
```

## Dangerous Settings
|**Option**|**Description**|
|---|---|
|`rw`|Read and write permissions.|
|`insecure`|Ports above 1024 will be used (the first 1024 ports can only be used by root). |
|`nohide`|If another file system was mounted below an exported directory, this directory is exported by its own exports entry.|
|`no_root_squash`|All files created by root are kept with the UID/GID 0.|

## Footprinting the Service

### Nmap
```shell-session
$ sudo nmap <ip address> -p111,2049 -sV -sC
```

The rpcinfo NSE script retrieves the names and descriptions of running RPC services, and the ports they use, other scripts can show us things like the contents of the share and its stats.

```shell-session
$ sudo nmap --script nfs* <ip address> -sV -p111,2049
```

### Show Available NFS Shares
```shell-session
$ showmount -e <ip address>
```

### Mounting NFS Share
```shell-session
$ mkdir <directory to mount to>
$ sudo mount -t nfs <ip address>:/ ./<directory to mount to>/ -o nolock
$ cd target-NFS
$ tree .
```

### List Contents with Usernames & Group Names
```shell-session
$ ls -l mnt/nfs/
```

### List Contents with UIDs & GUIDs
```shell-session
$ ls -n mnt/nfs/
```

If the root_squash option is set we cannot edit the backup.sh file even as root.

We can create users, groups and UIDs/GUIDs based on the information discovered to view and modify files.

### Unmounting
```shell-session
$ cd ..
$ sudo umount ./target-NFS
```

