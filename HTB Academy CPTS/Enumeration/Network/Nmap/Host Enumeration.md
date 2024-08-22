## Host Discovery

### Scan network Range
```shell-session
$ sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
```

This method only works if the firewall of the hosts allow it.

### Scan IP List
```shell-session
$ sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5
```

### Scan Multiple IPs
```shell-session
$ sudo nmap -sn -oA tnet 10.129.2.18 10.129.2.19 10.129.2.20| grep for | cut -d" " -f5
```

If they are next to each other:
```shell-session
$ sudo nmap -sn -oA tnet 10.129.2.18-20| grep for | cut -d" " -f5
```

### ICMP Echo Requests Scan, Tracing the Packets
```shell-session
$ sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace 
```

### ICMP Echo Requests Scan, Getting a Reason
```shell-session
$ sudo nmap 10.129.2.18 -sn -oA host -PE --reason 
```

### Forcing ICMP Echo Request, While Disabling ARP Pings
```shell-session
$ sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace --disable-arp-ping 
```

## Host and Port Scanning

### Port states
|**State**|**Description**|
|---|---|
|`open`|This indicates that the connection to the scanned port has been established. These connections can be **TCP connections**, **UDP datagrams** as well as **SCTP associations**.|
|`closed`|When the port is shown as closed, the TCP protocol indicates that the packet we received back contains an `RST` flag. This scanning method can also be used to determine if our target is alive or not.|
|`filtered`|Nmap cannot correctly identify whether the scanned port is open or closed because either no response is returned from the target for the port or we get an error code from the target.|
|`unfiltered`|This state of a port only occurs during the **TCP-ACK** scan and means that the port is accessible, but it cannot be determined whether it is open or closed.|
|`open\|filtered`|If we do not get a response for a specific port, `Nmap` will set it to that state. This indicates that a firewall or packet filter may protect the port.|
|`closed\|filtered`|This state only occurs in the **IP ID idle** scans and indicates that it was impossible to determine if the scanned port is closed or filtered by a firewall.|

### Discovering Open TCP Ports

Nmap Will do a SYN scan by default in case of running as root, TCP scan otherwise.

#### Scanning Top 10 TCP Ports
```shell-session
$ sudo nmap 10.129.2.28 --top-ports=10 
```

#### Trace the Packets
```shell-session
$ sudo nmap 10.129.2.28 -p 21 --packet-trace -Pn -n --disable-arp-ping
```

#### Connect Scan
```shell-session
$ sudo nmap 10.129.2.28 -p 443 -Pn -sT 
```

This scan is slower but less likely to be detected.

#### Filtered Ports
```shell-session
$ sudo nmap 10.129.2.28 -p <ports> --packet-trace -n --disable-arp-ping -Pn
```

In case the Firewall drops the packets, there will be long latency of the 2 sent packets by Nmap. In case the Firewall rejects the packets, we will get ICMP replay with type 3 and error code 3.

### Discovering Open UDP Ports
```shell-session
$ sudo nmap 10.129.2.28 -F -sU -Pn
```

This scan will be slower. ICMP response with error code 3 will tell us the port is closed, for other ICMP responses the port will be marked as open|filtered, we will only get response if the application is configured to do so.

### Version Scan
```shell-session
$ sudo nmap 10.129.2.28 -p 445 -Pn -sV
```

## Saving the Results

### All Formats
```shell-session
$ sudo nmap 10.129.2.28 -p- -oA target
```

## Normal Output
```shell-session
$ sudo nmap 10.129.2.28 -p- -oN target
```

### Grepable Output
```shell-session
$ sudo nmap 10.129.2.28 -p- -oG target
```

### XML Output
```shell-session
$ sudo nmap 10.129.2.28 -p- -oX target
```

### Create Style sheet from XML Report
```shell-session
$ xsltproc target.xml -o target.html
```

## Service Enumeration

### Get Update any Specific Number of Seconds (m for minutes)
```shell-session
$ sudo nmap 10.129.2.28 -p- -sV --stats-every=5s
```

### Banner Grabbing

Sometimes Nmap wouldn't give us the full picture, because the server didn't give us the response immediately, or Nmap doesn't know how to handle it, so we will need to use other tools.

#### Tcpdump
```shell-session
$ sudo tcpdump -i eth0 host 10.10.14.2 and 10.129.2.28
```

#### Nc
```shell-session
$  nc -nv 10.129.2.28 25
```

## Nmap Scripting Engine

NSE provides us with the ability to create scripts in Lua for interaction with certain services.

### Scripts Categories
|**Category**|**Description**|
|---|---|
|`auth`|Determination of authentication credentials.|
|`broadcast`|Scripts, which are used for host discovery by broadcasting and the discovered hosts, can be automatically added to the remaining scans.|
|`brute`|Executes scripts that try to log in to the respective service by brute-forcing with credentials.|
|`default`|Default scripts executed by using the `-sC` option.|
|`discovery`|Evaluation of accessible services.|
|`dos`|These scripts are used to check services for denial of service vulnerabilities and are used less as it harms the services.|
|`exploit`|This category of scripts tries to exploit known vulnerabilities for the scanned port.|
|`external`|Scripts that use external services for further processing.|
|`fuzzer`|This uses scripts to identify vulnerabilities and unexpected packet handling by sending different fields, which can take much time.|
|`intrusive`|Intrusive scripts that could negatively affect the target system.|
|`malware`|Checks if some malware infects the target system.|
|`safe`|Defensive scripts that do not perform intrusive and destructive access.|
|`version`|Extension for service detection.|
|`vuln`|Identification of specific vulnerabilities.|

### Default Scripts
```shell-session
$ sudo nmap <target> -sC
```

### Specific Scripts Category
```shell-session
$ sudo nmap <target> --script <category>
```

### Defined Scripts

### Aggressive Scan

scans the target with multiple options as service detection (`-sV`), OS detection (`-O`), traceroute (`--traceroute`), and with the default NSE scripts (`-sC`).

## Performance

We can make Nmap perform faster, but in the price of less accurate results, and more possibility to get detected in some cases.

### Optimized RTT (Round-Trip-Time)
```shell-session
$ sudo nmap 10.129.2.0/24 -F --initial-rtt-timeout 50ms --max-rtt-timeout 100ms
```

The default is 100ms.

### Reduced Retries
```shell-session
$ sudo nmap 10.129.2.0/24 -F --max-retries 0
```

The default value is 10.

### Min Number of Packets to Send Per Second
```shell-session
$ sudo nmap 10.129.2.0/24 -F -oN tnet.minrate300 --min-rate 300
```

### Insane Scan
```shell-session
$ sudo nmap 10.129.2.0/24 -F -oN tnet.T5 -T 5
```

After the T can be a number from 0-5, those are templates with set options for the level of are aggressiveness.