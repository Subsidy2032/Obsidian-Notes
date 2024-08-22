## Telnet

`$` Indicates it is not a root terminal.

## Hypertext Transfer Protocol (HTTP)

The browser connects to web servers and uses HTTP to request web pages, images and other files, and also to submit forms and upload various files.

![[a23a13cef49ae7fff87bfd94f6a175dc.png]]

Since HTTP sends and receives data as clear text you can communicate with him through a simple tool like telnet:

1. `telnet <ip address> 80` - Connect to telnet with port 80.
2. `GET /index.html HTTP/1.1` to retrieve `index.html` or `GET / HTTP/1.1` to retrieve the default page.
3. `host: telnet` - Provide some value to the host.

## File Transfer Protocol

**Active mode**: The data is sent over a separate channel originating from the FTP server's port 20
**Passive mode**: The data is sent over a separate channel originating from an FTP client's port above 1023.

Use Telnet to communicate with an FTP server:

1. `telnet <ip address> 21`
2. `USER <username>` - Provide a username.
3. `PASS <password>` - Provide a password.
4. If the username and password are correct we get logged in.

After we connected:

`SYST` - Show the system type.
`PASV` - Change to passive mode.
`TYPE A` - Switch the file transfer mode to ASCII.
`TYPE I` - Switch the file transfer mode to binary.

Note: You can't use telnet to transfer files, since FTP uses a separate connection for this.

![[da71a52fddfbb268dc6c5857daf07f18.png]]

## Simple Mail Transfer Protocol

Email delivery over the Internet requires the following components:

1. Mail Submission Agent (MSA): Checks the message for errors and sends it to the MTA, commonly on the same server.
2. Mail Transfer Agent (MTA): Transfers the message to the recipient's MTA server, commonly also the MDA.
3. Mail Delivery Agent (MDA): The recipient will collect their email using the email client.
4. Mail User Agent (MUA): A mail client that connects to the MSA to send a message.

![[822a449fd569c16c875a13ca2487b714.png]]

SMTP is used to communicate with the MTA.

After connecting with Telnet to port 25:

`helo <hostname>` - Say hello.
`mail from:` - Specify sender.
`rcpt to:` - Specify receiver.
`data` - To start sending data.
`Enter . Enter` - When you are done writing the data.

The commands are sent in clear text.

## Post Office Protocol 3 (POP3)

Used to download email messages from the MDA server.

After connecting with Telnet to port 110:

`USER <username>` - Specify username.
`PASS <password>` - Specify password.
`STAT` - Positive response is `+OK nn mm`, `nn` is the number of messages in the inbox and `mm` is the size of the inbox in octets.
`LIST` - Provides a list of new messages.
`RETR 1` - Retrieves the first message in the list.

The commands are sent in clear text, the default behavior is to delete the messages from the server after downloading, as there is no sync between different clients.

## Internet Message Access Protocol (IMAP)

With IMAP the email is synchronized across devices.

After connecting with Telnet to port 143 (IMAP requires to track the commands with a random string):

`c1 LOGIN <username> <password>` - Login.
`c2 LIST "" "*"` - List mail folders.
`c3 EXAMINE INBOX` - Check for new messages in the inbox.

The commands are sent in clear text.

## Summary

|Protocol|TCP Port|Application(s)|Data Security|
|---|---|---|---|
|FTP|21|File Transfer|Cleartext|
|HTTP|80|Worldwide Web|Cleartext|
|IMAP|143|Email (MDA)|Cleartext|
|POP3|110|Email (MDA)|Cleartext|
|SMTP|25|Email (MTA)|Cleartext|
|Telnet|23|Remote Access|Cleartext|
