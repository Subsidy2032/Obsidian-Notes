### Enumeration

The default scripts in nmap includes the [ftp-anon](https://nmap.org/nsedoc/scripts/ftp-anon.html) which checks if anonymous login is allowed.

### Misconfiguration

Anonymous login could be dangerous, since it can allow an attacker to read sensitive files, or even upload dangerous scripts to a web folder and visit the page in the browser.

We can use `get` to get a file, `mget` to get multiple files, `put` to upload a file, and `mput` to upload multiple files.

### Protocol Specifics Attacks

#### Brute Forcing

[Medusa](https://github.com/jmk-foofus/medusa) can be used for FTP brute forcing:
```shell-session
$ medusa -u <username> -P /usr/share/wordlists/rockyou.txt -h <ip address> -M ftp 
```

**Note:** Although we may find services vulnerable to brute force, most applications today prevent these types of attacks. A more effective method is Password Spraying.

#### FTP Bounce Attack

This is an attack that uses FTP servers to deliver outbound traffic to another device on the network, using the `PORT` command the attacker tricks the connection to running commands and getting information from a device other then the intended server.

For example if we are targeting an FTP server that is exposed to the internet, and another server that isn't exposed to the internet, we can use the FTP server to scan the other server.
![[ftp_bounce_attack.webp]]
Source: [https://www.geeksforgeeks.org/what-is-ftp-bounce-attack/](https://www.geeksforgeeks.org/what-is-ftp-bounce-attack/)

The `nmap` `-b` flag can be used to perform the attack:
```shell-session
$ nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2
```

Modern FTP serves has protections that protect from this attack by default, but can become vulnerable if those features are misconfigured.

## Latest FTP Vulnerabilities

We will discuss the `CoreFTP before build 727` vulnerability assigned [CVE-2022-22836](https://nvd.nist.gov/vuln/detail/CVE-2022-22836). This vulnerability is for an FTP service that does not correctly process the `HTTP PUT` request and leads to an `authenticated directory / path traversal,` and `arbitrary file write` vulnerability. This vulnerability allows to write files outside of the directory to which the service has access to.

### The Concept of the Attack

This FTP service uses an HTTP `POST` request to upload files. However the CoreFTP service allows an HTTP `PUT` request, which we can use to write contents to files. The [exploit](https://www.exploit-db.com/exploits/50652) for this attack is based on a single `cURL` command.

### CoreFTP Exploitation
```shell-session
$ curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops
```

We create an HTTP `PUT` request with basic auth, the path for the file, and its content, we also specify the host header with the IP address of our target system.

The actual process misinterprets the user's input of the path, which leads to access to the restricted folder. As a result the write permissions for the `PUT` request are not controlled properly, so we can create the file we want outside of the authorized folders.

### Directory Traversal
|**Step**|**Directory Traversal**|**Concept of Attacks - Category**|
|---|---|---|
|`1.`|The user specifies the type of HTTP request with the file's content, including escaping characters to break out of the restricted area.|`Source`|
|`2.`|The changed type of HTTP request, file contents, and path entered by the user are taken over and processed by the process.|`Process`|
|`3.`|The application checks whether the user is authorized to be in the specified path. Since the restrictions only apply to a specific folder, all permissions granted to it are bypassed as it breaks out of that folder using the directory traversal.|`Privileges`|
|`4.`|The destination is another process that has the task of writing the specified contents of the user on the local system.|`Destination`|

### Arbitrary File Write
|**Step**|**Arbitrary File Write**|**Concept of Attacks - Category**|
|---|---|---|
|`5.`|The same information that the user entered is used as the source. In this case, the filename (`whoops`) and the contents (`--data-binary "PoC."`).|`Source`|
|`6.`|The process takes the specified information and proceeds to write the desired content to the specified file.|`Process`|
|`7.`|Since all restrictions were bypassed during the directory traversal vulnerability, the service approves writing the contents to the specified file.|`Privileges`|
|`8.`|The filename specified by the user (`whoops`) with the desired content (`"PoC."`) now serves as the destination on the local system.|`Destination`|

### Target System
```cmd-session
C:\> type C:\whoops

PoC.
```
