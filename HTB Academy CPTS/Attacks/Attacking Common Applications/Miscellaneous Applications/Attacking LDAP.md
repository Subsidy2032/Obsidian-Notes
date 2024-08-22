`LDAP` (Lightweight Directory Access Protocol) is `a protocol` used to `access and manage directory information`. A `directory` is a `hierarchical data store` that contains information about network resources such as `users`, `groups`, `computers`, `printers`, and other devices. LDAP provides some excellent functionality:

|**Functionality**|**Description**|
|---|---|
|`Efficient`|Efficient and fast queries and connections to directory services, thanks to its lean query language and non-normalised data storage.|
|`Global naming model`|Supports multiple independent directories with a global naming model that ensures unique entries.|
|`Extensible and flexible`|This helps to meet future and local requirements by allowing custom attributes and schemas.|
|`Compatibility`|It is compatible with many software products and platforms as it runs over TCP/IP and SSL directly, and it is `platform-independent`, suitable for use in heterogeneous environments with various operating systems.|
|`Authentication`|It provides `authentication` mechanisms that enable users to `sign on once` and access multiple resources on the server securely.|

However, it also suffers some significant issues:

|Functionality|Description|
|---|---|
|`Compliance`|Directory servers `must be LDAP compliant` for service to be deployed, which may `limit the choice` of vendors and products.|
|`Complexity`|`Difficult to use and understand` for many developers and administrators, who may not know how to configure LDAP clients correctly or use it securely.|
|`Encryption`|LDAP `does not encrypt its traffic by default`, which exposes sensitive data to potential eavesdropping and tampering. LDAPS (LDAP over SSL) or StartTLS must be used to enable encryption.|
|`Injection`|`Vulnerable to LDAP injection attacks`, where malicious users can manipulate LDAP queries and `gain unauthorised access` to data or resources. To prevent such attacks, input validation and output encoding must be implemented.|

LDAP is `commonly used` for providing a `central location` for `accessing` and `managing` directory services. Directory services are collections of information about the organisation, its users, and assets–like usernames and passwords. LDAP enables organisations to store, manage, and secure this information in a standardised way. Here are some common use cases:

|**Use Case**|**Description**|
|---|---|
|`Authentication`|LDAP can be used for `central authentication`, allowing users to have single login credentials across multiple applications and systems. This is one of the most common use cases for LDAP.|
|`Authorisation`|LDAP can `manage permissions` and `access control` for network resources such as folders or files on a network share. However, this may require additional configuration or integration with protocols like Kerberos.|
|`Directory Services`|LDAP provides a way to `search`, `retrieve`, and `modify data` stored in a directory, making it helpful for managing large numbers of users and devices in a corporate network. `LDAP is based on the X.500 standard` for directory services.|
|`Synchronisation`|LDAP can be used to `keep data consistent` across multiple systems by `replicating changes` made in one directory to another.|

There are two popular implementations of LDAP: `OpenLDAP`, an open-source software widely used and supported, and `Microsoft Active Directory`, a Windows-based implementation that seamlessly integrates with other Microsoft products and services.

Although LDAP and AD are `related`, they `serve different purposes`. `LDAP` is a `protocol` that specifies the method of accessing and modifying directory services, whereas `AD` is a `directory service` that stores and manages user and computer data. While LDAP can communicate with AD and other directory services, it is not a directory service itself. AD offers extra functionalities such as policy administration, single sign-on, and integration with various Microsoft products.

| **LDAP**                                                                                                                                   | **Active Directory (AD)**                                                                                                                                                                                    |
| ------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| A `protocol` that defines how clients and servers communicate with each other to access and manipulate data stored in a directory service. | A `directory server` that uses LDAP as one of its protocols to provide authentication, authorisation, and other services for Windows-based networks.                                                         |
| An `open and cross-platform protocol` that can be used with different types of directory servers and applications.                         | `Proprietary software` that only works with Windows-based systems and requires additional components such as DNS (Domain Name System) and Kerberos for its functionality.                                    |
| It has a `flexible and extensible schema` that allows custom attributes and object classes to be defined by administrators or developers.  | It has a `predefined schema` that follows and extends the X.500 standard with additional object classes and attributes specific to Windows environments. Modifications should be made with caution and care. |
| Supports `multiple authentication mechanisms` such as simple bind, SASL, etc.                                                              | It supports `Kerberos` as its primary authentication mechanism but also supports NTLM (NT LAN Manager) and LDAP over SSL/TLS for backward compatibility.                                                     |

LDAP is a protocol that is simpler and more efficient than X.500, on which it is based. It uses a client-server model, where clients send requests to servers using LDAP messages encoded in ASN.1 (Abstract Syntax Notation One) and transmitted over TCP/IP (Transmission Control Protocol/Internet Protocol). The servers process the requests and send back responses using the same format. LDAP supports various requests, such as `bind`, `unbind`, `search`, `compare`, `add`, `delete`, `modify`, etc.

`LDAP requests` are `messages` that clients send to servers to `perform operations` on data stored in a directory service. An LDAP request is comprised of several components:

1. `Session connection`: The client connects to the server via an LDAP port (usually 389 or 636).
2. `Request type`: The client specifies the operation it wants to perform, such as `bind`, `search`, etc.
3. `Request parameters`: The client provides additional information for the request, such as the `distinguished name` (DN) of the entry to be accessed or modified, the scope and filter of the search query, the attributes and values to be added or changed, etc.
4. `Request ID`: The client assigns a unique identifier for each request to match it with the corresponding response from the server.

Once the server receives the request, it processes it and sends back a response message that includes several components:

1. `Response type`: The server indicates the operation that was performed in response to the request.
2. `Result code`: The server indicates whether or not the operation was successful and why.
3. `Matched DN:` If applicable, the server returns the DN of the closest existing entry that matches the request.
4. `Referral`: The server returns a URL of another server that may have more information about the request, if applicable.
5. `Response data`: The server returns any additional data related to the response, such as the attributes and values of an entry that was searched or modified.

After receiving and processing the response, the client disconnects from the LDAP port.

### ldapsearch

For example, `ldapsearch` is a command-line utility used to search for information stored in a directory using the LDAP protocol. It is commonly used to query and retrieve data from an LDAP directory service:
```shell-session
$ ldapsearch -H ldap://ldap.example.com:389 -D "cn=admin,dc=example,dc=com" -w secret123 -b "ou=people,dc=example,dc=com" "(mail=john.doe@example.com)"
```

This command can be broken down as follows:

- Connect to the server `ldap.example.com` on port `389`.
- Bind (authenticate) as `cn=admin,dc=example,dc=com` with password `secret123`.
- Search under the base DN `ou=people,dc=example,dc=com`.
- Use the filter `(mail=john.doe@example.com)` to find entries that have this email address.

The server would process the request and send back a response, which might look something like this:
```ldap
dn: uid=jdoe,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: John Doe
sn: Doe
uid: jdoe
mail: john.doe@example.com

result: 0 Success
```

This response includes the entry's `distinguished name (DN)` that matches the search criteria and its attributes and values.

## LDAP Injection

`LDAP injection` is an attack that `exploits web applications that use LDAP` (Lightweight Directory Access Protocol) for authentication or storing user information. The attacker can `inject malicious code` or `characters` into LDAP queries to alter the application's behaviour, `bypass security measures`, and `access sensitive data` stored in the LDAP directory.

To test for LDAP injection, you can use input values that contain `special characters or operators` that can change the query's meaning:

|Input|Description|
|---|---|
|`*`|An asterisk `*` can `match any number of characters`.|
|`( )`|Parentheses `( )` can `group expressions`.|
|`\|`|A vertical bar `\|` can perform `logical OR`.|
|`&`|An ampersand `&` can perform `logical AND`.|
|`(cn=*)`|Input values that try to bypass authentication or authorisation checks by injecting conditions that `always evaluate to true` can be used. For example, `(cn=*)` or `(objectClass=*)` can be used as input values for a username or password fields.|

LDAP injection attacks are `similar to SQL injection attacks` but target the LDAP directory service instead of a database.

For example, suppose an application uses the following LDAP query to authenticate users:
```php
(&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))
```

If an attacker injects the `*` character into the `$username` field, the LDAP query will match any user account with any password. This would allow the attacker to gain access to the application with any password, as shown below:
```php
$username = "*";
$password = "dummy";
(&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))
```

The same can be done with `*` in the password field and any username.

We might also have to inject `*` to both fields.

LDAP injection attacks can lead to `severe consequences`, such as `unauthorised access` to sensitive information, `elevated privileges`, and even `full control over the affected application or server`. These attacks can also considerably impact data integrity and availability, as attackers may `alter or remove data` within the directory service, causing disruptions to applications and services dependent on that data.

To mitigate the risks associated with LDAP injection attacks, it is crucial to `thoroughly validate` and `sanitize user input` before incorporating it into LDAP queries. This process should involve `removing LDAP-specific special characters` like `*` and `employing parameterised queries` to ensure user input is `treated solely as data`, not executable code.

## Enumeration

### Nmap
```shell-session
$ nmap -p- -sC -sV --open --min-rate=1000 10.129.204.229

Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-23 14:43 SAST
Nmap scan report for 10.129.204.229
Host is up (0.18s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE VERSION
80/tcp  open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Login
389/tcp open  ldap    OpenLDAP 2.2.X - 2.3.X

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 149.73 seconds
```

### Injection

As `OpenLDAP` runs on the server, it is safe to assume that the web application running on port `80` uses LDAP for authentication.

Attempting to log in using a wildcard character (`*`) in the username and password fields grants access to the system, effectively `bypassing any authentication measures that had been implemented`. This is a `significant` security issue as it allows anyone with knowledge of the vulnerability to `gain unauthorised access` to the system and potentially sensitive data.