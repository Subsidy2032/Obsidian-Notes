When we send an email it is sent to an SMTP server, which is used to deliver emails from clients to servers and from servers to other servers.

When we download an email it will connect to a POP3 or IMAP4 server on the internet, which allows us to save messages in a server mailbox and download them periodically.

By default POP3 removes downloaded messages from the server, but usually can be configured to keep copies of them.

In IMAP message aren't removed by default when downloading messages, making it easy to access email messages from multiple devices.

![[SMTP-IMAP-1.webp]]

### Enumeration

Email server are complex and usually require enumeration of multiple servers, ports, and services. Furthermore today most companies have their email services in the cloud, therefore our attack approach can largely depend.

We can use the Mail eXchanger (MX) DNS records to identify a mail server. The MX record specifies the mail server responsible for accepting mail messages in behalf of a domain name. Several MX records can be configured, typically pointing to an array of mail servers for load balancing and redundancy.

We can use tools such as `host` or `dig` and online websites such as [MXToolbox](https://mxtoolbox.com/) to query information about the MX records:

#### Host - MX Records
```shell-session
$ host -t MX hackthebox.eu

hackthebox.eu mail is handled by 1 aspmx.l.google.com.
```

```shell-session
$ host -t MX microsoft.com

microsoft.com mail is handled by 10 microsoft-com.mail.protection.outlook.com.
```

#### DIG - MX Records
```shell-session
$ dig mx plaintext.do | grep "MX" | grep -v ";"

plaintext.do.           7076    IN      MX      50 mx3.zoho.com.
plaintext.do.           7076    IN      MX      10 mx.zoho.com.
plaintext.do.           7076    IN      MX      20 mx2.zoho.com.
```

```shell-session
$ dig mx inlanefreight.com | grep "MX" | grep -v ";"

inlanefreight.com.      300     IN      MX      10 mail1.inlanefreight.com.
```

#### Host - A Records
```shell-session
$ host -t A mail1.inlanefreight.htb.

mail1.inlanefreight.htb has address 10.129.14.128
```

With mail services configured by the organization, we are more likely to find bad practices and misconfigurations then if the organization uses cloud services.

If we are targetting a custom mail server implementation such as `inlanefreight.htb`, we can enumerate the following ports:

|**Port**|**Service**|
|---|---|
|`TCP/25`|SMTP Unencrypted|
|`TCP/143`|IMAP4 Unencrypted|
|`TCP/110`|POP3 Unencrypted|
|`TCP/465`|SMTP Encrypted|
|`TCP/587`|SMTP Encrypted/[STARTTLS](https://en.wikipedia.org/wiki/Opportunistic_TLS)|
|`TCP/993`|IMAP4 Encrypted|
|`TCP/995`|POP3 Encrypted|

We can use `Nmap`'s default script `-sC` option to enumerate those ports on the target system:
```shell-session
$ sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 10.129.14.128
```

### Misconfigurations

Misconfigurations can happen when the SMTP allows anonymous authentication or support protocols that can be used to enumerate valid usrnames.

#### Authentication

The SMTP server has different commands that can be used to enumerate valid usernames, like `VRFY`, `EXPN`, and `RCPT TO`. With a list of valid usernames we can password spray, brute force, or guess valid passwords.

`VRFY` checks the validity of a username, this feature can be disabled.

#### VRFY Command
```shell-session
$ telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


VRFY root

252 2.0.0 root


VRFY www-data

252 2.0.0 www-data


VRFY new-user

550 5.1.1 <new-user>: Recipient address rejected: User unknown in local recipient tab
```

`EXPN` is similar to `VRFY`, except that  when used with a distribution list, it will list all users on that list, this can be a bigger problem then the `VRFY` command since sites often have alias such as all.

#### EXPN Command
```shell-session
$ telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


EXPN john

250 2.1.0 john@inlanefreight.htb


EXPN support-team

250 2.0.0 carol@inlanefreight.htb
250 2.1.5 elisa@inlanefreight.htb
```

`RCPT TO` identifies the recipient of the email message. It can be repeated for a single message to deliver a single message to multiple recipients.

#### RCPT TO Command
```shell-session
$ telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


MAIL FROM:test@htb.com
it is
250 2.1.0 test@htb.com... Sender ok


RCPT TO:julio

550 5.1.1 julio... User unknown


RCPT TO:kate

550 5.1.1 kate... User unknown


RCPT TO:john

250 2.1.5 john... Recipient ok
```

We can also use the `POP3` protocol to enumerate users depending on the service implementation, for example with the `USER` command followed by the username, and if the server responds `OK`, it means the user exists.

#### USER Command
```shell-session
$ telnet 10.10.110.20 110

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
+OK POP3 Server ready

USER julio

-ERR


USER john

+OK
```

We can use a tool called [smtp-user-enum](https://github.com/pentestmonkey/smtp-user-enum) to automate our enumeration process, we can use `-M` to specify the enumeration mode (`VRFY`, `EXPN`, or `RCPT`), and `-U` followed by the list of users, depending on the server implementation and enumeration mode we might need to use `-D` to add the domain for the email address, the target is specified with `-t`.

```shell-session
$ smtp-user-enum -M <mode> -U <users list> -D <domain> -t <ip address>
```

### Cloud Enumeration

Cloud service providers use their own implementation for email services, usually with custom features that we can abuse for operation, such as username enumeration, lets take Office 365 as an example.

[O365spray](https://github.com/0xZDH/o365spray) is a username enumeration and password spraying tool aimed at Microsoft office 365 (O365), This tool reimplements a collection of enumeration and spray techniques researched and identified.

First we will validated if our target is using Office 365.

#### O365 Spray
```shell-session
$ python3 o365spray.py --validate --domain <domain>

            *** O365 Spray ***            

>----------------------------------------<

   > version        :  2.0.4
   > domain         :  msplaintext.xyz
   > validate       :  True
   > timeout        :  25 seconds
   > start          :  2022-04-13 09:46:40

>----------------------------------------<

[2022-04-13 09:46:40,344] INFO : Running O365 validation for: msplaintext.xyz
[2022-04-13 09:46:40,743] INFO : [VALID] The following domain is using O365: msplaintext.xyz
```

Now, we can attempt to identify usernames.

```shell-session
$ python3 o365spray.py --enum -U <users wordlist> --domain <domain>
```

### Password Attacks

We can use Hydra for password spray or brute force against services such as `SMTP`, `POP3`, or `IMAP4`.

#### Hydra - Password Attack
```shell-session
$ hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3
```

If cloud services support `SMTP`, `POP3`, or `IMAP4`, we can attempt to use Hydra, but those tools are usually blocked. We can instead try to use custom tools such as [o365spray](https://github.com/0xZDH/o365spray) or [MailSniper](https://github.com/dafthack/MailSniper) for Microsoft O365 or [CredKing](https://github.com/ustayready/CredKing) for Gmail or Okta. Those tools must be up to date, since they may not work when the service provider changes something.

#### O365 Spray - Password Spraying
```shell-session
$ python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz
```

### Protocol Specific Attacks

An open relay is Simple Transfer Mail Protocol (SMTP) server, which is improperly configured and allows an unauthenticated email relay. Messaging servers that are configured as open relays allow mail from any source to be transparently  re-routed through the open relay server. This behavior masks the source of the message and makes it look like the mail originated from the open relay server.

#### Open Relay

We can abuse this for phishing by sending emails as non-existing users or spoofing someone else's email. With the `nmap smtp-open-relay` script, we can identify if an SMTP port allows open relay.

```shell-session
# nmap -p25 -Pn --script smtp-open-relay 10.10.11.213
```

Next, we can use any mail client to connect to the mail server and send our email.

```shell-session
# swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Company Notification' --body 'Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/' --server 10.10.11.213
```

## Latest Email Services Vulnerabilities

One of the most recent publicly disclosed and dangerous SMTP vulnerabilities was discovered in [OpenSMTPD](https://www.opensmtpd.org/) up to version 6.6.2 service was in 2020. This vulnerability was assigned [CVE-2020-7247](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-7247) and leads to RCE. It has been exploitable since 2018. This service has been used in many different Linux distributions. The danger of this vulnerability is the possibility of executing system commands remotely on the system and that exploiting this vulnerability doesn't require authentication.

According to [Shodan.io](https://www.shodan.io), at the time of writing (April 2022) there are over 5000 publicly accessible OpenSMTPD servers worldwide, and the trend is growing. It doesn't mean that the vulnerability effects every service.

### The Concept of the Attack

The vulnerability in the service lies in the program's code, namely in the function that records the sender's email address. This offers the possibility of escaping the function using a semicolon (`;`) and making the system execute arbitrary shell commands. However there is a limit of 64 characters, which can be inserted as a command. The technical details of this vulnerability can be found [here](https://www.openwall.com/lists/oss-security/2020/01/28/3).

First we will need to initialize a connection with the SMTP service, this can be automated by a script or done manually. Then an email must be composed in which we define the sender, the recipient, and the actual message. The desired system command is inserted in the sender field connected to the sender address with a semicolon (`;`).

#### Initiation of the Attack
| **Step** | **Remote Code Execution**                                                                                                                                                     | **Concept of Attacks - Category** |
| -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| `1.`     | The source is the user input that can be entered manually or automated during direct interaction with the service.                                                            | `Source`                          |
| `2.`     | The service will take the email with the required information.                                                                                                                | `Process`                         |
| `3.`     | Listening to the standardized ports of a system requires `root` privileges on the system, and if these ports are used, the service runs accordingly with elevated privileges. | `Privileges`                      |
| `4.`     | As the destination, the entered information is forwarded to another local process.                                                                                            | `Destination`                     |

#### Trigger Remote Code Execution
| **Step** | **Remote Code Execution**                                                                                                                                                                               | **Concept of Attacks - Category** |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| `5.`     | This time, the source is the entire input, especially from the sender area, which contains our system command.                                                                                          | `Source`                          |
| `6.`     | The process reads all the information, and the semicolon (`;`) interrupts the reading due to special rules in the source code that leads to the execution of the entered system command.                | `Process`                         |
| `7.`     | Since the service is already running with elevated privileges, other processes of OpenSMTPD will be executed with the same privileges. With these, the system command we entered will also be executed. | `Privileges`                      |
| `8.`     | The destination for the system command can be, for example, the network back to our host through which we get access to the system.                                                                     | `Destination`                     |

An [exploit](https://www.exploit-db.com/exploits/47984) has been published on the [Exploit-DB](https://www.exploit-db.com) platform for this vulnerability which can be used for more detailed analysis and the functionality of the trigger for the execution of system commands.