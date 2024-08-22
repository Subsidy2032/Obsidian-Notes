Found a tomcat application running on port 8080 and found the version(9.0.0.M1) with nmap.

Found [this](https://github.com/setrus/CVE-2019-0232) exploit, use the `exploit/windows/http/tomcat_cgi_cmdlineargs` module from Metasploit. changed the target page to `/cgi/cmd.bat` (which I found with gobuster for brute forcing .bat files in the cgi directory), and rhosts to target's IP.