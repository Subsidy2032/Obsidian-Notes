Remote management is enabled by default starting with Windows Server 2016. Remote management is a component of the Windows hardware management features that manage server hardware locally and remotely. These features include a service that implements the WS-Management protocol, hardware diagnostics and control through baseboard management controllers, and a COM API and script objects that enable us to write applications that communicate remotely through the WS-Management protocol.

The main components used for remote management of Windows and Windows servers are the following:

- Remote Desktop Protocol (`RDP`)
    
- Windows Remote Management (`WinRM`)
    
- Windows Management Instrumentation (`WMI`)

## RDP

The Remote Desktop Protocol (RDP) allows display and control commands to be transmitted via GUI encrypted over IP networks. It works at the application layer of TCP/IP, typically utilizing TCP port 3389, but UDP can be used too.

For an RDP session to be established, bot the network firewall and the firewall on the server should allow connections from the outside. If Network Address Translation (NAT) is used on the route between the client and server, the remote computer needs the public IP address to reach the server, port-forwarding should be set-up on the NAT router in the direction of the server.

RDP has handled TLS/SSL since Windows Vista, many Windows systems still accept inadequate encryption via [RDP Security](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/8e8b2cca-c1fa-456c-8ecb-a82fc60b2322). An attacker is far from being locked out anyway sincethe identity-providing certificates are merely self-signed by default. This means that the client cannot distinguish a genuine certificate from a forged one and generates a certificate warning for the user.

This service can be activated using the Server Manager, and comes with a default setting to allow connections to the service only to hostswith [Network level authentication](https://en.wikipedia.org/wiki/Network_Level_Authentication) (`NLA`).

## Footprinting the Service

By scanning RDP service we can get information such as if NLA is enabled on the server, the product version, and the hostname.

### Nmap
```shell-session
$ nmap -sV -sC <ip address> -p3389 --script rdp*
```

We can also use `--packet-trace` to track individual packets, for example `mstshash=nmap` means that RDP cookies are used, and can be identified by security services and lock us out.

```shell-session
$ nmap -sV -sC <ip address> -p3389 --packet-trace --disable-arp-ping -n
```

A Perl script named [rdp-sec-check.pl](https://github.com/CiscoCXSecurity/rdp-sec-check) has also been developed by [Cisco CX Security Labs](https://github.com/CiscoCXSecurity) that can unauthentically identify the security settings of RDP servers based on the handshakes.

### RDP Security Check - Installation
```shell-session
$ sudo cpan
```

### RDP Security Check
```shell-session
$ git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check
$ ./rdp-sec-check.pl <ip address>
```

### Initiate an RDP Session
```shell-session
$ xfreerdp /u:<username> /p:<password> /v:<ip address>
```

## WinRM

The Windows Remote Management (WinRM) protocol is a simple Windows integrated remote management protocol based on the command line, it uses Simple Object Access Protocol (`SOAP`) to establish connections, it should be explicitly enabled and configured starting with Windows 10. WinRM relies on TCP ports 5985 and 5986, with 5986 using HTTPS, previously ports 80 and 443 were used for this task, but today port 80 is mostly blocked due to security reasons.

Another component that fits WinRM for administration is Windows Remote Shell (`WinRS`), which lets us execute arbitrary commands on the remote system. The program is even included on Windows 7 by default. Thus, with WinRM, it is possible to execute a remote command on another server.

Services like remote sessions using PowerShell and event log merging require WinRM. It is enabled by default starting with the `Windows Server 2012` version, but it must first be configured for older server versions and clients, and the necessary firewall exceptions created.

## Footprinting the Service

### Nmap WinRM
```shell-session
$ nmap -sV -sC <ip address> -p5985,5986 --disable-arp-ping -n
```

We can easily interact with WinRM using the [Test-WsMan](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/test-wsman?view=powershell-7.2) cmdlet in power shell, or [evil-winrm](https://github.com/Hackplayers/evil-winrm) in Linux based environments.

```shell-session
$ evil-winrm -i <ip address> -u <username> -p <password>
```

## WMI

Windows Management Instrumentation (WMI) is Microsoft's implementation and an extension of the Common Information Model (CIM), core functionality of the standardized Web-Based Enterprise Management (WBEM) for the Windows platform. WMI allows read and write access almost to all settings on Windows systems, it's typically accessed via PowerShell, VBScript, or other Windows Management Instrumentation Console (WMIC). WMI is not a single program but consists of several programs and various databases, also known as repositories.

## Footprinting the Service

The initialization of the WMI communication always takes place on TCP port 135, and after the successful establishment of the connection, the communication is moved to another port. For example, the program [wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py) from the Impacket toolkit can be used for this.

### WMIexec.py
```shell-session
$ /usr/share/doc/python3-impacket/examples/wmiexec.py <username>:"<password>"@<ip address> "hostname"
```