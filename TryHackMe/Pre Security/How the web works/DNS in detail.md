#Networking 

Top-Level Domain(TLD) - The most righthand part of a domain name
gTLD(generic top level) - For telling the purpose of the domain
ccTLD(Country Code Top Level Domain) - For geographical purposes

Second-Level Domain - The domain name, cant start or end with hyphens or have a consecutive hyphens

Subdomains - comes before the Second-Level Domain, with the same restrictions

## Dns Most Common Record Types:
**A Record** - Resolves to IPv4 addresses

**AAAA Record** - Resolves to IPv6 addresses

**CNAME Record** - Resolves to another domain name, than to the IP address of the other domain name

**MX Record** - Resolves to the servers that handle the email of the domain, comes with a priority flag which tells the client in which order to try the servers, perfect for when the main server goes down and you need to use the backup server

**TXT Record** - Free text fields, can be used for example for storing the servers with the authority to send an email in behalf of the domain (helps against spam or spoofed emails) or to verify ownership of the domain name when signing up for third party services

## DNS Request:
1. The computer checks if you made a request for this address recently, if not a request to your recursive DNS server will be made
2. If the address can be found locally the requests end here, otherwise the server searches for the correct answer starting with the internet's root DNS servers
3. The root servers redirect you to the correct top-level domain(TLD) server
4. The TLD server holds record for where to find the authoritative/nameserver, often more than 1
5. The authoritative DNS server stores the particular domain names and where updates to the domain name would be made, the record than sent back to the recursive server and cached for future reference and than relayed back to the client, comes with a TTL value in seconds for how long the record should be saved locally until you have to look it up again

`nslookup --type=<Record type> website` - Make DNS requests
