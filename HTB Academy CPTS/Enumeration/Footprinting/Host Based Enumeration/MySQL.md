MySQL is an open source relational data base, developed and supported by Orcale, it consists of MySQL server (database management system or DBMS) which takes care of data storage and distribution and one or more MySQL clients. Databases are often stored in a single file with `.sql` extension.

### MySQL Clients

The MySQL clients can retrieve and edit the data of one or multiple databases using structured query to the database engine, depending on the use, access is possible via the internal network or public internet.

### MySQL Databases

MySQL is suited for applications such as dynamic websites, It is often combined with [LAMP](https://en.wikipedia.org/wiki/LAMP_(software_bundle)) (Linux, Apache, MySQL, PHP) or [LEMP](https://lemp.io/) in case of using Nginx.

Passwords stored are usually encrypted using secure methods such as [One-Way-Encryption](https://en.citizendium.org/wiki/One-way_encryption).

### MySQL Commands

The web application informs the user if an error occurs during processing, those error can reveal valuable information, and confirms the the web application interacts with the database in a different way than the developers intended.

`MariaDB`, which is often connected with MySQL, is a fork of the original MySQL code. This is because the chief developer of MySQL left the company `MySQL AB` after it was acquired by `Oracle` and developed another open-source SQL database management system based on the source code of MySQL and called it MariaDB.

## Default Configuration

The topic of SQL databases and their configuration is so vast that database administrators deal with almost nothing but databases, it is a core competency for software developers and information security analysts.

### Default Configuration
```shell-session
$ sudo apt install mysql-server -y
$ cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#" | sed -r '/^\s*$/d'

[client]
port		= 3306
socket		= /var/run/mysqld/mysqld.sock

[mysqld_safe]
pid-file	= /var/run/mysqld/mysqld.pid
socket		= /var/run/mysqld/mysqld.sock
nice		= 0

[mysqld]
skip-host-cache
skip-name-resolve
user		= mysql
pid-file	= /var/run/mysqld/mysqld.pid
socket		= /var/run/mysqld/mysqld.sock
port		= 3306
basedir		= /usr
datadir		= /var/lib/mysql
tmpdir		= /tmp
lc-messages-dir	= /usr/share/mysql
explicit_defaults_for_timestamp

symbolic-links=0

!includedir /etc/mysql/conf.d/
```

## Dangerous Settings
|**Settings**|**Description**|
|---|---|
|`user`|Sets which user the MySQL service will run as.|
|`password`|Sets the password for the MySQL user.|
|`admin_address`|The IP address on which to listen for TCP/IP connections on the administrative network interface.|
|`debug`|This variable indicates the current debugging settings|
|`sql_warnings`|This variable controls whether single-row INSERT statements produce an information string if warnings occur.|
|`secure_file_priv`|This variable is used to limit the effect of data import and export operations.|

The configurations are in plain text and often the rights for the configuration file are not assigned correctly, which can reveal us the credentials for the database.

The `debug` and `sql_warnings` provide verbose information output in case of errors, it should only be seen by the administrator and no one else.

## Footprinting the Service

There are many reasons why a MySQL server could be accessed from an external network, it could be something the meant to be temporary but was forgotten, it could also be used as a workaround for a technical problem.

### Scanning MySQL Server
```shell-session
$ sudo nmap <ip address> -sV -sC -p3306 --script mysql*
```

### Interaction with the MySQL Server
```shell-session
$ mysql -u <username> -p<password> -h <ip address>
```

The system schema database (sys) contains tables, information and metadata necessary for management.

The information schema (information_schema) database also contains metadata, this metadata is mostly retrieved from the system schema database. The reason for the existence of both is the ANSI/ISO standard that has been established. ANSI/ISO standard that has been established.

### Some Commands
|**Command**|**Description**|
|---|---|
|`mysql -u <user> -p<password> -h <IP address>`|Connect to the MySQL server. There should **not** be a space between the '-p' flag, and the password.|
|`show databases;`|Show all databases.|
|`use <database>;`|Select one of the existing databases.|
|`show tables;`|Show all available tables in the selected database.|
|`show columns from <table>;`|Show all columns in the selected database.|
|`select * from <table>;`|Show everything in the desired table.|
|`select * from <table> where <column> = "<string>";`|Search for needed `string` in the desired table.|