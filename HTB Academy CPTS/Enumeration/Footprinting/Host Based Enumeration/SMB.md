Server Message Block (SMB) is a client-server protocol that regulates access to network resources such as files and directories, printers, routers, or interfaces released for the network. his main application is for the Windows operating system and it is downgrade compatible.

Tow computers, one with the SMB server application and a client can communicate with each other to access files or services shared in the network, after establishing a connection, for which they exchange corresponding messages.

An SMB server can provide arbitrary parts of its local file system as shares, access rights are defined by an ACL, they can be controlled in a fined-grand manner based on attributes like read, write and full access.

## Samba

Samba is an alternative for the SMB server developed for UNIX-based systems, it implements the Common Internet File System (CIFS) which is a very specific implementation of SMB (an extension of it), created by Microsoft which allows it to communicate with newer Windows systems, when we pass SMB commands over samba to an older NetBIOS service it usually connects over ports 137, 138, 139 while CIFS uses port 445 only.

### SMB Versions
|**SMB Version**|**Supported**|**Features**|
|---|---|---|
|CIFS|Windows NT 4.0|Communication via NetBIOS interface|
|SMB 1.0|Windows 2000|Direct connection via TCP|
|SMB 2.0|Windows Vista, Windows Server 2008|Performance upgrades, improved message signing, caching feature|
|SMB 2.1|Windows 7, Windows Server 2008 R2|Locking mechanisms|
|SMB 3.0|Windows 8, Windows Server 2012|Multichannel connections, end-to-end encryption, remote storage access|
|SMB 3.0.2|Windows 8.1, Windows Server 2012 R2||
|SMB 3.1.1|Windows 10, Windows Server 2016|Integrity checking, AES-128 encryption|

With version 3 Samba gained the ability to be a full member of an Active Directory domain, and with version 4 it even provides a domain controller. It contains daemons (Unix background programs) for this purpose, the SMB server daemon (smbd) provides the first two functionalities, while the NetBIOS message block daemon (nmbd) provides the last two, the SMB service controls the daemons.

Samba is suitable for both Linux and Windows, each host participates in the same workgroup, which is a group name that identifies an arbitrary collection of computer and resources on the SMB network, there can be multiple in a given time. IBM developed an API for networking computers called Network Basic Input/Output System (NetBIOS) which provides a blueprint for an application to connect and share data with other computers. In NetBIOS environment when a machine becomes online it need a name, which is done through the name registration procedure. Either each host reserves its hostname in the network or the NetBIOS name server (NBNS) is used for this purpose. It also been enhanced to Windows Internet Name Service (WINS).

## Default Configuration

`/etc/samba/smb.conf` is the default location for the configuration file.

The global settings are the configuration of the available SMB server that is used for all shares, in the individual shares these settings can be overwritten.

### Some of the Settings
|**Setting**|**Description**|
|---|---|
|`[sharename]`|The name of the network share.|
|`workgroup = WORKGROUP/DOMAIN`|Workgroup that will appear when clients query.|
|`path = /path/here/`|The directory to which user is to be given access.|
|`server string = STRING`|The string that will show up when a connection is initiated.|
|`unix password sync = yes`|Synchronize the UNIX password with the SMB password?|
|`usershare allow guests = yes`|Allow non-authenticated users to access defined share?|
|`map to guest = bad user`|What to do when a user login request doesn't match a valid UNIX user?|
|`browseable = yes`|Should this share be shown in the list of available shares?|
|`guest ok = yes`|Allow connecting to the service without using a password?|
|`read only = yes`|Allow users to read files only?|
|`create mask = 0700`|What permissions need to be set for newly created files?|

### Dangerous Settings
|**Setting**|**Description**|
|---|---|
|`browseable = yes`|Allow listing available shares in the current share?|
|`read only = no`|Forbid the creation and modification of files?|
|`writable = yes`|Allow users to create and modify files?|
|`guest ok = yes`|Allow connecting to the service without using a password?|
|`enable privileges = yes`|Honor privileges assigned to specific SID?|
|`create mask = 0777`|What permissions must be assigned to the newly created files?|
|`directory mask = 0777`|What permissions must be assigned to the newly created directories?|
|`logon script = script.sh`|What script needs to be executed on the user's login?|
|`magic script = script.sh`|Which script should be executed when the script gets closed?|
|`magic output = script.out`|Where the output of the magic script needs to be stored?|

### Restart Samba to Reset Configuratons
```shell-session
# sudo systemctl restart smbd
```

### SMBclient - Connecting to the Shares
```shell-session
$ smbclient -N -L //<ip address>
```

print$ and IPC$ are included by default.

### Connecting to a share
```shell-session
$ smbclient //<ip address>/<share>
```

We can use the `get` command to download files, and `!<command>` to execute commands on the local system without interrupting the connection.

### Samba Status

With the `smbstatus` command we can see the version, and from who, which host and which shares the client is connected.

With domain-level security the samba server acts as a member of a windows domain, with at list one domain controller, usually a Windows NT server providing password authentication. This domain controller provides the workgroup with a definitive password server. The domain controller keep track of users and passwords in their own Security Authentication Module (SAM) and authenticate each user when they first log in and wish to access another machine's share.

## Footprinting the Service

We can use Nmap to get information from the SMB service, but this scans takes a lot of time, so it's better to do manual testing.

The Remote Procedure Call (RPC) is a concept and therefore, also a central tool to realize operational and work sharing structures in networks and client-server architectures. The communication process via RPC includes passing parameters and the returns of a function value.

### RPCclient
```shell-session
$ rpcclient -U "" <ip address>
```

A complete list of all the functions we can execute on the SMB server can be found on the [man page](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) of the rpcclient.

### Some of the functions
|**Query**|**Description**|
|---|---|
|`srvinfo`|Server information.|
|`enumdomains`|Enumerate all domains that are deployed in the network.|
|`querydominfo` |Provides domain, server, and user information of deployed domains.|
|`netshareenumall`|Enumerates all available shares.|
|`netsharegetinfo <share>`|Provides information about a specific share.|
|`enumdomusers`|Enumerates all domain users.|
|`queryuser <RID>`|Provides information about a specific user.|

### RPCcient - Enumeration Example
```shell-session
rpcclient $> srvinfo
```

### Brute Forcing User RIDs
```shell-session
$ for i in $(seq 500 1100);do rpcclient -N -U "" <ip address> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
```

An alternative for this could be the [samrdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/samrdump.py) Python script from Impacket.

#### Impacket - Samrdump.py
```shell-session
$ samrdump.py <ip address>
```

### Enumeration With SMBmap
```shell-session
$ smbmap -H <ip address>
```

### Enumeration With CrackMapExec
```shell-session
$ crackmapexec smb <ip address> --shares -u '' -p ''
```

[enum4linux-ng](https://github.com/cddmp/enum4linux-ng) Which is based on enum4linux automates many of the queries and can return a large amount of information.

### Enum4Linux-ng - Installation
```shell-session
$ git clone https://github.com/cddmp/enum4linux-ng.git
$ cd enum4linux-ng
$ pip3 install -r requirements.txt
```

### Enum4Linux-ng - Enumeration
```shell-session
$ ./enum4linux-ng.py <ip address> -A
```

