IMAP allows the management of emails on a remote server, it's also allows client-server synchronization which allows to synchronize several independent clients. POP3 only provides the listing, retrieving and deleting of emails on the mail server.

With IMAP several clients can access the mail server together. It's impossible to manage emails without active connections, but clients can make changes offline, and synchronize them once a connection is reestablished.

Clients establish connection with the server through port 143, the client can send several commands without waiting for confirmation, the server can than assign confirmations to the commands using the identifiers sent with them. The client can access the mailbox only after authentication.

SMTP is usually used to send emails, and the emails can be copied to an IMAP folder, which allows all client access to the emails regardless of the client that sent it, another advantage of IMAP is the folder structure which makes it easier to organize the emails.

IMAP works unencrypted by default, but it can be used with SSL/TLS, using the standard port 143 or alternative port such as 993 depending on the method and implementation used.

## Default Configuration

You can play with the configuration by installing the packages `dovecot-imapd`, and `dovecot-pop3d`.

### IMAP Commands
| **Command**                     | **Description**                                                                                               |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `1 LOGIN username password`     | User's login.                                                                                                 |
| `1 LIST "" *`                   | Lists all directories.                                                                                        |
| `1 CREATE "INBOX"`              | Creates a mailbox with a specified name.                                                                      |
| `1 DELETE "INBOX"`              | Deletes a mailbox.                                                                                            |
| `1 RENAME "ToRead" "Important"` | Renames a mailbox.                                                                                            |
| `1 LSUB "" *`                   | Returns a subset of names from the set of names that the User has declared as being `active` or `subscribed`. |
| `1 SELECT INBOX`                | Selects a mailbox so that messages in the mailbox can be accessed.                                            |
| `1 UNSELECT INBOX`              | Exits the selected mailbox.                                                                                   |
| `1 FETCH <ID> all`              | Retrieves data associated with a message in the mailbox.                                                      |
| `1 CLOSE`                       | Removes all messages with the `Deleted` flag set.                                                             |
| `1 LOGOUT`                      | Closes the connection with the IMAP server.                                                                   |

### POP3 Commands
| **Command**     | **Description**                                             |
| --------------- | ----------------------------------------------------------- |
| `USER username` | Identifies the user.                                        |
| `PASS password` | Authentication of the user using its password.              |
| `STAT`          | Requests the number of saved emails from the server.        |
| `LIST`          | Requests from the server the number and size of all emails. |
| `RETR id`       | Requests the server to deliver the requested email by ID.   |
| `DELE id`       | Requests the server to delete the requested email by ID.    |
| `CAPA`          | Requests the server to display the server capabilities.     |
| `RSET`          | Requests the server to reset the transmitted information.   |
| `QUIT`          | Closes the connection with the POP3 server.                 |

## Dangerous Settings

Some companies may use their own mail server, which can lead to misconfiguration.

|**Setting**|**Description**|
|---|---|
|`auth_debug`|Enables all authentication debug logging.|
|`auth_debug_passwords`|This setting adjusts log verbosity, the submitted passwords, and the scheme gets logged.|
|`auth_verbose`|Logs unsuccessful authentication attempts and their reasons.|
|`auth_verbose_passwords`|Passwords used for authentication are logged and can also be truncated.|
|`auth_anonymous_username`|This specifies the username to be used when logging in with the ANONYMOUS SASL mechanism.|

## Footprinting the Service

By default ports 110 and 143 are used for POP3 and IMAP, 993 and 995 use TLS/SSL.

### Nmap
```shell-session
$ sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC
```

The displayed capabilities can show us the commands available on the server.

### cURL
```shell-session
Wildland4958@htb[/htb]$ curl -k 'imaps://<ip address>' --user <username>:<password>

* LIST (\HasNoChildren) "." Important
* LIST (\HasNoChildren) "." INBOX
```

### cURL Verbose
```shell-session
$ curl -k 'imaps://<ip address>' --user <username>:<password> -v
```

Verbose can give us details such as about the certificate and even the banner.

We can interact with IMAP or POP4 over SSL using `openssl` as well as `ncat`.

### OpenSSL - TLS Encrypted Interaction POP3
```shell-session
$ openssl s_client -connect <ip address>:pop3s
```

### OpenSSL - TLS Encrypted Interaction IMAP
```shell-session
$ openssl s_client -connect <ip address>:imaps
```