When landing on a host for the first time we can check for privilege level, network connection, VPN, or other remote access software. If a host has more than one network adapter, we can likely use it to move to another network segment.

Common terms to describe a host we can use to pivot:

- `Pivot Host`
- `Proxy`
- `Foothold`
- `Beach Head system`
- `Jump Host`

Pivoting's primary use is to defeat segmentation (both physically and virtually), tunneling is a subset of pivoting which encapsulates network traffic into another protocol.

## Lateral Movement, Pivoting, and Tunneling Compared

### Lateral Movoment

Lateral movement is used to further our access to additional hosts, applications, and services within a network environment. It can also help us gain access to specific domain resources we may need to elevate our privileges. Here are 2 other explanations:

[Palo Alto Network's Explanation](https://www.paloaltonetworks.com/cyberpedia/what-is-lateral-movement)

[MITRE's Explanation](https://attack.mitre.org/tactics/TA0008/)

### Pivoting

Utilizing multiple hosts to cross `network` boundaries you would not usually have access to.

### Tunnling

Using various protocols to shuttle traffic in/out of a network where there is a chance of our traffic being detected. We utilize secured protocols like HTTPS over TLS, or SSH. It also can help with tactics like the exfiltration of data, or the delivery of more payloads and instructions into the network.