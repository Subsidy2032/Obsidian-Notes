ICMP errors possible from firewall that rejected are packets and sent RST flag:
- Net Unreachable
- Net Prohibited
- Host Unreachable
- Host Prohibited
- Port Unreachable
- Proto Unreachable

## ACK Scan
```shell-session
$ sudo nmap <ip address> -p <ports> -sA -Pn
```

This is harder for firewalls to detect.

## Detect IDS/IPS

We can use several virtual private server (VPS) to aggressively scan the target and see if there are any security measures triggered or if the host lost access to the internet at any point, we can than know how sneaky we should be and use another VPS.

## Decoys

Decoys are the right choice when the administrator blocks specific subnets, or when IPS should block us, the decoys may be alive or we might trigger SYN-flooding security mechanism which can make the services unavialable.

### Scan by Using Decoys
```shell-session
$ sudo nmap <ip address> -p <port> -sS -Pn -D RND:<number of decoys>
```

The spoofed packets can be filtered by ISPs and routers, so we can specify our VPS servers' IP addresses and use them in combination with IP ID manipulation in IP headers.

We can try to use another IP address as the source if only individual subnets don't have access to the server's specific services.

### Testing Firewall Rule
```shell-session
$ sudo nmap <ip address> -n -Pn -p<port> -O
```

### Scan by Using Different Source IP
```shell-session
$ sudo nmap <ip address> -n -Pn -p <port> -O -S 10.129.2.200 -e tun0
```

## DNS Proxying

Nmap performs DNS resolution by default for more accurate results, it should usually pass because it's expected, TCP was only used previously for zone transfers, but it starts to change due to IPv6 and DNSSEC expansions.

We can specify DNS servers to use (`--dns-server <ns>,<ns>`), so for example if we are in the DMZ the target's servers could be more trusted. we can use TCP port 53 as our source, so if the administrator uses the firewall to control this port, without filtering IPS/IDS properly we can pass.

### SYN-Scan From DNS Port
```shell-session
$ sudo nmap <ip address> -p<filtered port> -sS -Pn -n --source-port 53
```

If we can pass through it means that IDS/IPS filters may be configured much weaker than others.

### Connect to the Filtered Port
```shell-session
$ ncat -nv --source-port 53 <ip address> <port>
```