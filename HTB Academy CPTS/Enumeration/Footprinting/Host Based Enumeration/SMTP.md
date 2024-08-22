The Simple Mail Transfer Protocol (SMTP) is used to send emails in an IP network, it is often used with IMAP or POP3 protocols which can fetch and send emails, it can be used between an email client and an outgoing mail server or between tow SMTP servers.

Newer SMTP servers use ports like 587 to receive mail from authenticated users/severs, usually using the STARTTLS command to switch the existing plaintext connection to encrypted connection, in the beginning authentication occurs, for the email to be transmitted the client sends the sender and recipient address, the email's content, and other information and parameters, the connection can than be terminated again. The mail server than starts sending the email to another SMTP server.

SMTP by default works in plaintext, but can be used in conjunction with SSL/TLS encryption, and uses for example TCP port 465.

Most modern SMTP servers support the protocol extension ESMTP with SMTP-Auth, the Mail User Agent (MUA) which is the client sends the email with an header and a body, than the Mail Transfer Agent (MTA) which is the software basis for sending and receiving emails checks the mail for size and spam and stores it. To relieve the MTA it is occasionally preceded by a Mail Submission Agent (MSA) which checks the validity, for example the email origin, This MSA is also called Relay server, the MSA than searches the DNS for the IP address of the recipient mail server.

When the email arrives at the destination SMTP server, the data packets are reassembled to form a complete e-mail. From there, the Mail Delivery Agent (MDA) transfers it to the recipient's mailbox.

|Client (`MUA`)|`➞`|Submission Agent (`MSA`)|`➞`|Open Relay (`MTA`)|`➞`|Mail Delivery Agent (`MDA`)|`➞`|Mailbox (`POP3`/`IMAP`)|
|---|---|---|---|---|---|---|---|---|

SMTP disadvantages inherent to the network protocol:

1. In case of errors usually only an error message and the header of the undelivered message is returned.
2. Users are not authenticated when a connection is established, originators of spam messages use fake address to not be traces, For rejection and quarantine (spam folder) of suspicious emails there are the identification protocol [DomainKeys](http://dkim.org/) (`DKIM`), the [Sender Policy Framework](https://dmarcian.com/what-is-spf/) (`SPF`).

For this purpose Extended SMTP (ESMTP) has been created, it uses TLS which is done after the HELO command by sending STARTTLS, the connection than is more or less secure. Now [AUTH PLAIN](https://www.samlogic.net/articles/smtp-commands-reference-auth.htm) extension for authentication can also be used safely.

## Default Configuration
```shell-session
$ cat /etc/postfix/main.cf | grep -v "#" | sed -r "/^\s*$/d"

smtpd_banner = ESMTP Server 
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 2
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
myhostname = mail1.inlanefreight.htb
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
smtp_generic_maps = hash:/etc/postfix/generic
mydestination = $myhostname, localhost 
masquerade_domains = $myhostname
mynetworks = 127.0.0.0/8 10.129.0.0/16
mailbox_size_limit = 0
recipient_delimiter = +
smtp_bind_address = 0.0.0.0
inet_protocols = ipv4
smtpd_helo_restrictions = reject_invalid_hostname
home_mailbox = /home/postfix
```

## Commands for Sending and Communicating
| **Command**  | **Description**                                                                                  |
| ------------ | ------------------------------------------------------------------------------------------------ |
| `AUTH PLAIN` | AUTH is a service extension used to authenticate the client.                                     |
| `HELO`       | The client logs in with its computer name and thus starts the session.                           |
| `MAIL FROM`  | The client names the email sender.                                                               |
| `RCPT TO`    | The client names the email recipient.                                                            |
| `DATA`       | The client initiates the transmission of the email.                                              |
| `RSET`       | The client aborts the initiated transmission but keeps the connection between client and server. |
| `VRFY`       | The client checks if a mailbox is available for message transfer.                                |
| `EXPN`       | The client also checks if a mailbox is available for messaging with this command.                |
| `NOOP`       | The client requests a response from the server to prevent disconnection due to time-out.         |
| `QUIT`       | The client terminates the session.                                                               |

### Telnet - HELO/EHLO
```shell-session
$ telnet 10.129.14.128 25

Trying 10.129.14.128...
Connected to 10.129.14.128.
Escape character is '^]'.
220 ESMTP Server 


HELO mail1.inlanefreight.htb

250 mail1.inlanefreight.htb


EHLO mail1

250-mail1.inlanefreight.htb
250-PIPELINING
250-SIZE 10240000
250-ETRN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING
```

The command VRFY can enumerate existing user, but depending on the configuration, the SMTP server might issue code 252 (user exist) for a user that doesn't exist, a list of SMTP response codes can be found [here](https://serversmtp.com/smtp-error/).

### Telnet - VRFY
```shell-session
$ telnet 10.129.14.128 25

Trying 10.129.14.128...
Connected to 10.129.14.128.
Escape character is '^]'.
220 ESMTP Server 

VRFY root

252 2.0.0 root


VRFY cry0l1t3

252 2.0.0 cry0l1t3


VRFY testuser

252 2.0.0 testuser


VRFY aaaaaaaaaaaaaaaaaaaaaaaaaaaa

252 2.0.0 aaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

Sometimes we may have to work through a web proxy. We can also make this web proxy connect to the SMTP server. The command that we would send would then look something like this: `CONNECT 10.129.14.128:25 HTTP/1.0`.

### Send an Email
```shell-session
$ telnet 10.129.14.128 25

Trying 10.129.14.128...
Connected to 10.129.14.128.
Escape character is '^]'.
220 ESMTP Server


EHLO inlanefreight.htb

250-mail1.inlanefreight.htb
250-PIPELINING
250-SIZE 10240000
250-ETRN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING


MAIL FROM: <cry0l1t3@inlanefreight.htb>

250 2.1.0 Ok


RCPT TO: <mrb3n@inlanefreight.htb> NOTIFY=success,failure

250 2.1.5 Ok


DATA

354 End data with <CR><LF>.<CR><LF>

From: <cry0l1t3@inlanefreight.htb>
To: <mrb3n@inlanefreight.htb>
Subject: DB
Date: Tue, 28 Sept 2021 16:32:51 +0200
Hey man, I am trying to access our XY-DB but the creds don't work. 
Did you make any changes there?
.

250 2.0.0 Ok: queued as 6E1CF1681AB


QUIT

221 2.0.0 Bye
Connection closed by foreign host.
```

## Dangerous Settings

The sender can authenticate to relay server and send the email through there, to get the email to the recipient through spam filters.

Often, administrators don't have an overview of what IP address to allow or not, so they allow all IP addresses to not disturb or interrupt the communication with potential and current customers.

### Open Relay Configuration
```shell-session
mynetworks = 0.0.0.0/0
```

Another attack could be to spoof the email and read it.

## Footprinting the Service

The default Nmap scripts include `smtp-commands`, which uses the `EHLO` command to list all possible commands that can be executed on the target SMTP server.

### Nmap
```shell-session
$ sudo nmap <ip address> -sC -sV -p25
```

However, we can also use the [smtp-open-relay](https://nmap.org/nsedoc/scripts/smtp-open-relay.html) NSE script to identify the target SMTP server as an open relay using 16 different tests. If we also print out the output of the scan in detail, we will also be able to see which tests the script is running.

### Nmap - Open Relay
```shell-session
$ sudo nmap <ip address> -p25 --script smtp-open-relay -v
```