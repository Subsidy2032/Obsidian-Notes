Simple Network Management Protocol (SNMP) is a protocol for monitoring and managing network devices, The current version SNMPv3 increased the security and complexity of the protocol.

SNMP transmits control commands using agents over UDP port 161, the client can send specific options and change options and settings with those commands. In classical communication the client request information from the sever, but traps over UDP port 162 are possible. Those are data packets sent from the SNMP server to the client without being requested, once a specific event occurs on the server.

The SNMP objects must have unique addresses known in both sides to communicate.

### MIB

Management Information Base (MIB) was created to ensure access across manufacturers, it's a text file that contains information off all objects and at least one Object Identifier (OID), in addition to the unique address and name for information about the type, access rights and description. MIB files are written in the `Abstract Syntax Notation One` (`ASN.1`) based ASCII text format. They do not contain data, but they explain where to find the information and what it looks like, which returns values for specific OID, or which data type is used.

### OID

OID determine the position of a node in the tree with unique numbers, the information is more specific with longer chains. Many nodes contain nothing but references to the nodes below them. The integers are usually concatenated by dot notation.

### SNMPv1

This is the first version which is still used in small networks. It allows the retrieval of information and configuration of devices, and provides traps which are notifications of events, it has no built-in authentication mechanism and does not use encryption.

### SNMPv2

It existed in different versions, the one that still exists today is v2c, c for community-based, it is in the same level of security as v1, and has been extended with additional functions from the party-based SNMP no longer in use. The community string which provides security is transmitted in plain-text.

### SNMPv3

It has authentication and encryption (via pre-shared key), but the complexity also increases with v3 with significantly more configuration options the v2c.

### Community Strings

Community strings are like passwords that are used to determine whether the requested information can be viewed or not, many organizations still use SNMPv2 since the complexity of transitioning to SNMPv3 can be very complex, this causes many concerns for the administrators.

## Default configuration

The default configurations of the SNMP daemon defines the basic settings for the service, which includes the IP addresses, ports, MIB, OIDs, authentication and community strings.

### SNMP Daemon Config
```shell-session
$ cat /etc/snmp/snmpd.conf | grep -v "#" | sed -r '/^\s*$/d'
```

## Dangerous Settings
|**Settings**|**Description**|
|---|---|
|`rwuser noauth`|Provides access to the full OID tree without authentication.|
|`rwcommunity <community string> <IPv4 address>`|Provides access to the full OID tree regardless of where the requests were sent from.|
|`rwcommunity6 <community string> <IPv6 address>`|Same access as with `rwcommunity` with the difference of using IPv6.|

## Footprinting the service

Snmpwalk is used to query to OIDs with their information.

Onesixtyone can be used to brute-force the names of community strings, identifying the existing community strings can take quite some time.

### SNMPwalk
```shell-session
$ snmpwalk -v2c -c public <ip address>
```

This can be used for versions v1 and v2c, in case of misconfiguration we can get a lot of information.

### OneSixtyOne
```shell-session
$ sudo apt install onesixtyone
$ onesixtyone -c /usr/share/SecLists/Discovery/SNMP/snmp.txt <ip address>
```

Community string are often bound to IP address, they are named with the hostname of the host, and sometimes symbols are added to those names, but in extensive network with over 100 different server there would be some pattern to them, we can use different rules to guess them, for example using crunch.

With tee community string we can use braa to brute force the individual OIDs and enumerate the information behind them.

### Braa
```shell-session
$ sudo apt install braa
$ braa <community string>@<IP>:.1.3.6.*   # Syntax
$ braa public@10.129.14.128:.1.3.6.*
```