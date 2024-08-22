## Server Types
|**Server Type**|**Description**|
|---|---|
|`DNS Root Server`|The root servers of the DNS are responsible for the top-level domains (`TLD`). As the last instance, they are only requested if the name server does not respond. Thus, a root server is a central interface between users and content on the Internet, as it links domain and IP address. The [Internet Corporation for Assigned Names and Numbers](https://www.icann.org/) (`ICANN`) coordinates the work of the root name servers. There are `13` such root servers around the globe.|
|`Authoritative Nameserver`|Authoritative name servers hold authority for a particular zone. They only answer queries from their area of responsibility, and their information is binding. If an authoritative name server cannot answer a client's query, the root name server takes over at that point.|
|`Non-authoritative Nameserver`|Non-authoritative name servers are not responsible for a particular DNS zone. Instead, they collect information on specific DNS zones themselves, which is done using recursive or iterative DNS querying.|
|`Caching DNS Server`|Caching DNS servers cache information from other name servers for a specified period. The authoritative name server determines the duration of this storage.|
|`Forwarding Server`|Forwarding servers perform only one function: they forward DNS queries to another DNS server.|
|`Resolver`|Resolvers are not authoritative DNS servers but perform name resolution locally in the computer or router.|

For protection IT security professionals apply DNS over TLS (DoT) or DNS over HTTPS (DoH), the network protocol DNSCrypt also encrypts the traffic between the computer and the name server.

DNS also stores and outputs information about the domain, for example how the domain's name servers are called or which computer serves as the mail server for the domain.

![[tooldev-dns.png]]

## DNS Records
|**DNS Record**|**Description**|
|---|---|
|`A`|Returns an IPv4 address of the requested domain as a result.|
|`AAAA`|Returns an IPv6 address of the requested domain.|
|`MX`|Returns the responsible mail servers as a result.|
|`NS`|Returns the DNS servers (nameservers) of the domain.|
|`TXT`|This record can contain various information. The all-rounder can be used, e.g., to validate the Google Search Console or validate SSL certificates. In addition, SPF and DMARC entries are set to validate mail traffic and protect it from spam.|
|`CNAME`|This record serves as an alias. If the domain www.hackthebox.eu should point to the same IP, and we create an A record for one and a CNAME record for the other.|
|`PTR`|The PTR record works the other way around (reverse lookup). It converts IP addresses into valid domain names.|
|`SOA`|Provides information about the corresponding DNS zone and email address of the administrative contact.|

### Querying the SOA Record
```shell-session
$ dig soa <url>
```

The `@` sign can be replaced by a `.` in the email address.

## Default Configuration

All servers work with 3 different types of configuration files (not exclusively):

1. local DNS configuration files
2. zone files
3. reverse name resolution files

Configuration files of the [Bind9](https://www.isc.org/bind/) DNS server which is commonly used with Linux distributions:

- `named.conf.local`
- `named.conf.options`
- `named.conf.log`

It contains the associated RFC to customize the server to our needs, the `named.conf` is roughly divided into tow sections, the options section for general settings and the zone entries for individual domains, zone options takes precedence.

### Local DNS Configuration

You can find the configuration in `/etc/bind/named.conf.local`.

In this file we can define the different zones which are divided into individual files, which in most cases are mainly intended for one domain only, exceptions are ISP and public DNS servers. Many different options extend or reduce the functionality.

### Zone Files

A zone file is a text file that describes a DNS zone with the BIND file format, it describes a zone completely. There must be precisely one SOA record and at least one NS record. The SOA record is usually located at the beginning of the file. A syntax error causes the name server to act as if it didn't exist, it responds to DNS queries with a `SERVFAIL` error message. 

In short this is the phone book where the DNS server looks up the addresses for the domains it is searching for.

This file can be found at `/etc/bind/db.domain.com`.

### Reverse Name Resolution Zone Files

This is a reverse lookup file to resolve IP address from Fully Qualified Domain Names (FQDN), the computer name is assigned to the last octet of an IP address, using PTR records which are responsible for the reverse translation of IP address into names.

The location of the file is `/etc/bind/db.10.129.14`.

## Dangerous Settings

A list of vulnerabilities targeting the BIND9 server can be found at [CVEdetails](https://www.cvedetails.com/product/144/ISC-Bind.html?vendor_id=64), in addition SecurityTrails provides a short [list](https://securitytrails.com/blog/most-popular-types-dns-attacks) of the most popular attacks on DNS servers.

Since DNS can be tricky and cause a lot of errors, functionality can have a higher priority over security in a lot of the cases.

|**Option**|**Description**|
|---|---|
|`allow-query`|Defines which hosts are allowed to send requests to the DNS server.|
|`allow-recursion`|Defines which hosts are allowed to send recursive requests to the DNS server.|
|`allow-transfer`|Defines which hosts are allowed to receive zone transfers from the DNS server.|
|`zone-statistics`|Collects statistical data of zones.|

## Footprinting the Service

Other DNS servers may be configured differently, and may be permanent for other zones.

### DIG - NS Query
```shell-session
$ dig ns inlanefreight.htb @10.129.14.128
```

### DIG - Version Query
```shell-session
$ dig CH TXT version.bind 10.129.120.85
```

For this the entry must exist on the DNS server.

### DIG - Any Query
```shell-session
$ dig any inlanefreight.htb @10.129.14.128
```

This will cause the server to show all available entries it is willing to disclose.

### Zone Transfer

Zone transfers refers to the transfer of zones to another server in DNS, generally happens over TCP port 53. This procedure is abbreviated Asynchronous Full Transfer Zone (AXFR). Since a DNS server usually have several consequences for a company, the zone file is almost invariably kept identical in several name servers. The synchronization is realized by zone transfers. Using a secret key `rndc-key`, the servers make sure they communicate with their own master or slave. Zone transfer involves the mere transfer of files or records and the detection of discrepancies in the data sets of the servers involved.

The original data of a zone is located in a DNS server which is called the primary name server for this zone, secondary name servers are almost for the zone always installed to increase reliability, realize a simple load distribution, or protect the primary from attacks. For some Top-Level Domains (TLDs), making zone files for the second level domains accessible in at least 2 servers is mandatory.

DNS entries are generally only created, modified, or deleted on the primary. This can be done manually or dynamically from a database. A master is a DNS server that serves as a direct source for synchronizing a zone file. A DNS server that obtains zone data from master is called slave. A primary is always a master, secondary can be a slave or a master.

The slave fetches the SOA record of the relevant zone from the master at certain intervals, the so-called refresh time usually one hour and compare the serial numbers. The data sets no longer match if the number of the SOA record of the server is higher.

#### DIG - AXFR Zone Transfer
```shell-session
$ dig axfr inlanefreight.htb @10.129.14.128
```

Using overly broad settings like "allow-transfer any" or wide subnets in DNS zone transfer configurations can inadvertently expose sensitive data, allowing unauthorized access to entire zone files and potentially revealing internal IP addresses and hostnames, posing significant security risks.

#### DIG - AXFR Zone Transfer - Internal
```shell-session
$ dig axfr internal.inlanefreight.htb @10.129.14.128
```

### Subdomain Brute Forcing
```shell-session
$ for sub in $(cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
```

### Brute Forcing with [DNSenum](https://github.com/fwaeytens/dnsenum)
```shell-session
$ dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```