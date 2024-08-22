## Transport Layer Security (TLS)

TLS replaced SSL (Secure Sockets Layer) as a more secure protocol, this protocols sits in the presentation layer in the OSI model.

|Protocol|Default Port|Secured Protocol|Default Port with TLS|
|---|---|---|---|
|HTTP|80|HTTPS|443|
|FTP|21|FTPS|990|
|SMTP|25|SMTPS|465|
|POP3|110|POP3S|995|
|IMAP|143|IMAPS|993|

Steps for HTTPS communication:

1. Establish TCP connection.
2. Establish SSL/TLS connection.
3. send HTTP requests to the web server.

SSL handshake (RFC 6101):

![[ea654470ae699d10e9c07bd11a8320ac.png]]

1. The client sends a ClientHello to the server to indicate his capabilities, such as supported algorithms.
2. The server sends the ServerHello to indicate the selected connection parameters, the server also sends his certificate if server authentication is required, it also might send the required information to generate the master key trough ServerKeyExchange message, finally it will send the ServerHelloDone message to indicate it's done with the negotiation.
3. The client sends the ClientKeyExchange which contains more information for the master key and the ChangeCipherSpec to notify the server it switches to use encrypton.
4. The server switches to use encryption too and informs the client.

When using SSL/TLS we rely on public signed certificates trusted by our computer or the browser.

## Secure Shell (SSH)

With SSH you can confirm the identity of the remote server, the exchanged messages are encrypted and both sides can detect modification.

When connecting to the system for the first time we will need to accept the public key's fingerprint, since we don't usually have a third party to do this for us.

`scp <username>@<ip address>:<remote file path> <local folder path>` - Transfer a file to your local system from a remote one using SSH.

`scp <local file path> <username>@<ip address>:<remote folder>` Transfer a file from your local machine to a remote folder.

## Password Attack

Hydra options:

|   |   |
|---|---|
|`-l username`|Provide the login name|
|`-P WordList.txt`|Specify the password list to use|
|`server service`|Set the server address and service to attack|
|`-s PORT`|Use in case of non-default service port number|
|`-V` or `-vV`|Show the username and password combinations being tried|
|`-d`|Display debugging output if the verbose output is not helping|
|`-t <number>`|Number of parallel connections to make to the target|
