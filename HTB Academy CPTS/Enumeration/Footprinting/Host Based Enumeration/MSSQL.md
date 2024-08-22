Microsoft SQL (MSSQL) is SQL-based relational database management system, usually found on Window systems (although possible on Linux and MacOS), it's a popular choice when building applications that run on Microsoft's .NET framework, due to its strong native support for .NET.

### MSSQL Clients

SQL Server Management Studio (SSMS) come as a feature that can be installed with the MSSQL install package or separately, it can be installed on any system and not just the server.

Other clients that can be used:

|   |   |   |   |   |
| --- | --- | --- | --- | --- |
| [mssql-cli](https://docs.microsoft.com/en-us/sql/tools/mssql-cli?view=sql-server-ver15) | [SQL Server PowerShell](https://docs.microsoft.com/en-us/sql/powershell/sql-server-powershell?view=sql-server-ver15) | [HeidiSQL](https://www.heidisql.com) | [SQLPro](https://www.macsqlclient.com) | [Impacket's mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py) |

Check if Impacket's mssqlclient is installed on your system:
```shell-session
$ locate mssqlclient
```

### MSSQL Databases

#### Default System Databases
|Default System Database|Description|
|---|---|
|`master`|Tracks all system information for an SQL server instance|
|`model`|Template database that acts as a structure for every new database created. Any setting changed in the model database will be reflected in any new database created after changes to the model database|
|`msdb`|The SQL Server Agent uses this database to schedule jobs & alerts|
|`tempdb`|Stores temporary objects|
|`resource`|Read-only database containing system objects included with SQL server|

## Default Configuration

When the MSSQL configured to be network accessible, the service will usually run as `NT SERVICE\MSSQLSERVER`. Encryption is not usually enforced when authenticating.

## Dangerous Configuration

### Some Things to Look for

- MSSQL clients not using encryption to connect to the MSSQL server
    
- The use of self-signed certificates when encryption is being used. It is possible to spoof self-signed certificates
    
- The use of [named pipes](https://docs.microsoft.com/en-us/sql/tools/configuration-manager/named-pipes-properties?view=sql-server-ver15)
    
- Weak & default `sa` credentials. Admins may forget to disable this account

## Footprinting the Service

Nmap as default mssql scripts that can be used to target the default TCP port 1433 that MSSQL listens on.

### NMAP MSSQL Script Scan
```shell-session
$ sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <ip address>
```

Metasploit's auxiliary scanner mssql_ping will scan the MSSQL service and will provide useful information.

### MSSQL Ping in Metasploit
```shell-session
msf6 auxiliary(scanner/mssql/mssql_ping) > set rhosts <ip address>
msf6 auxiliary(scanner/mssql/mssql_ping) > run
```

### Connecting with Mssqlclient.py

With credentials we can remotely connect and interact with databases using T-SQL (Transact-SQL), it'll enable us to interact directly with the SQL database engine. We can use Impacket's mssqlclient.py to connect.

```shell-session
$ python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL-01): Line 1: Changed database context to 'master'.
[*] INFO(SQL-01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands

SQL> select name from sys.databases
```