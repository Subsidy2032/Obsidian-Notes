## WHOIS

WHOIS is a TCP-based transaction-oriented query/response protocol listening on TCP port 43 by default. With this protocol we can query databases containing domain names, IP address or autonomous systems.

All registered domains are required to enter the holder's contact information, the domain creation and expiration date, and other information. We can search all registered domains with WHOIS.

WHOIS command line tool for Linux: [WHOIS](https://linux.die.net/man/1/whois)

WHOIS command line tool for Windows: [Sysinternals WHOIS](https://docs.microsoft.com/en-gb/sysinternals/downloads/whois)

We can use `whois <target>` for LInux or `whois.exe <target>` for Windows.

## DNS

### Resource Records Structure

Resource records are the result of DNS query, and have the following structure:

|   |   |
|---|---|
|`Resource Record`|A domain name, usually a fully qualified domain name, is the first part of a Resource Record. If you don't use a fully qualified domain name, the zone's name where the record is located will be appended to the end of the name.|
|`TTL`|In seconds, the Time-To-Live (`TTL`) defaults to the minimum value specified in the SOA record.|
|`Record Class`|Internet, Hesiod, or Chaos|
|`Start Of Authority` (`SOA`)|It should be first in a zone file because it indicates the start of a zone. Each zone can only have one `SOA` record, and additionally, it contains the zone's values, such as a serial number and multiple expiration timeouts.|
|`Name Servers` (`NS`)|The distributed database is bound together by `NS` Records. They are in charge of a zone's authoritative name server and the authority for a child zone to a name server.|
|`IPv4 Addresses` (`A`)|The A record is only a mapping between a hostname and an IP address. 'Forward' zones are those with `A` records.|
|`Pointer` (`PTR`)|The PTR record is a mapping between an IP address and a hostname. 'Reverse' zones are those that have `PTR` records.|
|`Canonical Name` (`CNAME`)|An alias hostname is mapped to an `A` record hostname using the `CNAME` record.|
|`Mail Exchange` (`MX`)|The `MX` record identifies a host that will accept emails for a specific host. A priority value has been assigned to the specified host. Multiple MX records can exist on the same host, and a prioritized list is made consisting of the records for a specific host.|

### Nslookup and DIG

#### Querying: A Records
```shell-session
$ nslookup <target domain>
```

#### Specify Nameserver with DIG (Which Shows More Information in General)
```shell-session
$ dig <target domain> @<nameserver/ip address>
```

#### Querying: A Records for a Subdomain
```shell-session
$ nslookup -query=A <target>
```

```shell-session
$ dig a www.facebook.com @1.1.1.1
```

#### Querying: PTR Records for an IP Address
```shell-session
$ nslookup -query=PTR <ip address>
```

```shell-session
$ dig -x <ip address> @1.1.1.1
```

### Querying: ANY Existing Records
```shell-session
$ nslookup -query=ANY <target>
```

```shell-session
$ dig any google.com @8.8.8.8
```

We might not get response to `ANY` DNS requests.

#### Querying: TXT Records
```shell-session
$ nslookup -query=TXT <target>
```

```shell-session
$ dig txt facebook.com @1.1.1.1
```

#### Querying: MX Records
```shell-session
$ nslookup -query=MX <target>
```

```shell-session
$ dig mx facebook.com @1.1.1.1
```

We can also start with `nslookup` and `dig`, than use the IP address we found with WHOIS query.

## Passive Subdomain Enumeration

### VirusTotal

VirusTotal maintains is own DNS replication service, which is developed by preserving DNS resolutions made when users visit URLs given by them.

### Certificates

Certificate Transparency (CT) is a project that requires every SSL/TLS certificate issued by Certificate Authority (CA) to be published in a publicly accessible log.

Resources:

- [https://censys.io](https://censys.io)
- [https://crt.sh](https://crt.sh)

#### Certificate Transparency

```shell-session
$ export TARGET="facebook.com"
$ curl -s "https://crt.sh/?q=#{TARGET}&output=json" | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | sort -u > "${TARGET}_crt.sh.txt"
```

```shell-session
$ head -n20 facebook.com_crt.sh.txt
```

##### Perform the Operation manually with OpenSSL:

```shell-session
$ export TARGET="facebook.com"
$ export PORT="443"
$ openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' -connect "${TARGET}:${PORT}" | openssl x509 -noout -text -in - | grep 'DNS' | sed -e 's|DNS:|\n|g' -e 's|^\*.*||g' | tr -d ',' | sort -u
```

### Automating Passive Subdomain Enumeration

#### TheHarvester

[TheHarvester](https://github.com/laramies/theHarvester) collects emails, names, subdomains, IP address, and URL's from various public data sources.

Some of the modules:

|   |   |
|---|---|
|[Baidu](http://www.baidu.com/)|Baidu search engine.|
|`Bufferoverun`|Uses data from Rapid7's Project Sonar - [www.rapid7.com/research/project-sonar/](http://www.rapid7.com/research/project-sonar/)|
|[Crtsh](https://crt.sh/)|Comodo Certificate search.|
|[Hackertarget](https://hackertarget.com/)|Online vulnerability scanners and network intelligence to help organizations.|
|`Otx`|AlienVault Open Threat Exchange - [https://otx.alienvault.com](https://otx.alienvault.com/)|
|[Rapiddns](https://rapiddns.io/)|DNS query tool, which makes querying subdomains or sites using the same IP easy.|
|[Sublist3r](https://github.com/aboul3la/Sublist3r)|Fast subdomains enumeration tool for penetration testers|
|[Threatcrowd](http://www.threatcrowd.org/)|Open source threat intelligence.|
|[Threatminer](https://www.threatminer.org/)|Data mining for threat intelligence.|
|`Trello`|Search Trello boards (Uses Google search)|
|[Urlscan](https://urlscan.io/)|A sandbox for the web that is a URL and website scanner.|
|`Vhost`|Bing virtual hosts search.|
|[Virustotal](https://www.virustotal.com/gui/home/search)|Domain search.|
|[Zoomeye](https://www.zoomeye.org/)|A Chinese version of Shodan.|

Create this file to automate the process:
```shell-session
$ cat sources.txt

baidu
bufferoverun
crtsh
hackertarget
otx
projectdiscovery
rapiddns
sublist3r
threatcrowd
trello
urlscan
vhost
virustotal
zoomeye
```

```shell-session
$ export TARGET="facebook.com"
$ cat sources.txt | while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}_${TARGET}";done
```

Extract and sort all subdomains found:
```shell-session
$ cat *.json | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f 1 | sort -u > "${TARGET}_theHarvester.txt"
```

Merge all passive reconnaissance files:
```shell-session
$ cat facebook.com_*.txt | sort -u > facebook.com_subdomains_passive.txt
$ cat facebook.com_subdomains_passive.txt | wc -l
```

## Passive Infrastructure Identification

[Netcraft](https://www.netcraft.com) can offer us information about the servers without even interacting with them.

Some of the details we can observer from the report:

|   |   |
|---|---|
|`Background`|General information about the domain, including the date it was first seen by Netcraft crawlers.|
|`Network`|Information about the netblock owner, hosting company, nameservers, etc.|
|`Hosting history`|Latest IPs used, webserver, and target OS.|

The latest IPs used can tell us the actual IP address, which may now be placed behind a load balancer, web application firewall, or IDS.

### Wayback Machine

The [Internet Archive](https://en.wikipedia.org/wiki/Internet_Archive) is an American digital library that provides free public access to digitalized materials, including websites, collected automatically via its web crawlers.

We can access old versions of websites, and we might find interesting comments in the source code, files, plugins, and more.

With [waybackurls](https://github.com/tomnomnom/waybackurls) we can inspect URLs save by Wayback Machine and look for specific keywords.

Install the tool:
```shell-session
$ go install github.com/tomnomnom/waybackurls@latest
```

To get a list of crawled URLs from a domain with the date it was obtained, we can add the `-dates` switch to our command as follows:
```shell-session
Wildland4958@htb[/htb]$ waybackurls -dates https://facebook.com > waybackurls.txt
```

