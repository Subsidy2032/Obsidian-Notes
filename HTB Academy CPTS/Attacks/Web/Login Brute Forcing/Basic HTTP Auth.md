## Password Attacks

Many web servers or individual contents on the web servers are still often used with the [Basic HTTP AUTH](https://tools.ietf.org/html/rfc7617) scheme.

The HTTP specification Provides two parallel authentication mechanisms:

1. `Basic HTTP AUTH` is used to authenticate the user to the HTTP server.
    
2. `Proxy Server Authentication` is used to authenticate the user to an intermediate proxy server.

The Basic HTTP Authentication scheme uses user ID and password for authentication. The client first sends a request without authentication information. The server's response contains the `WWW-Authenticate` header field, which requests the client to provide the credentials. This header field also defines details of how the authentication has to take place. The client uses the Base64 method for encoding the identifier and password. This encoded character string is transmitted to the server in the Authorization header field.

There are several types of password attacks, such as:

|**Password Attack Type**|
|---|
|`Dictionary attack`|
|`Brute force`|
|`Traffic interception`|
|`Man In the Middle`|
|`Key Logging`|
|`Social engineering`|

### Methods of Brute Force Attacks
|**Attack**|**Description**|
|---|---|
|Online Brute Force Attack|Attacking a live application over the network, like HTTP, HTTPs, SSH, FTP, and others|
|Offline Brute Force Attack|Also known as Offline Password Cracking, where you attempt to crack a hash of an encrypted password.|
|Reverse Brute Force Attack|Also known as username brute-forcing, where you try a single common password with a list of usernames on a certain service.|
|Hybrid Brute Force Attack|Attacking a user by creating a customized password wordlist, built using known intelligence about the user or the service.|

## Default Passwords

When we don't know both the username and password, brute forcing should be our last resort.

It is very common to find pairs of usernames and passwords used together, especially when it's the default passwords, this is why it's always best to start with a wordlist of such pairs.

We can find such a list in `/usr/share/SecLists/Passwords/Default-Credentials`. Flags we will use:

|**Options**|**Description**|
|---|---|
|`-C ftp-betterdefaultpasslist.txt`|Combined Credentials Wordlist|
|`SERVER_IP`|Target IP|
|`-s PORT`|Target Port|
|`http-get`|Request Method|
|`/`|Target Path|

### Using the Attack with Burpe Suite
![[Pasted image 20240505205237.png]]

## Username Brute Force

`Hydra` requires at least 3 specific flags if the credentials are in one single list to perform a brute force attack against a web service:

1. `Credentials`
2. `Target Host`
3. `Target Path`

```shell-session
$ hydra -L /opt/useful/SecLists/Usernames/Names/names.txt -P /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt -u -f 178.35.49.134 -s 32901 http-get /
```