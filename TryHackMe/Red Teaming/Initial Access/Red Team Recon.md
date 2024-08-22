## Taxonomy of Reconnaissance

**Passive Recon:** Searching for publicly accessible information and using OSINT.
**Active Recon:** Involves sending packet and observing if and how the target responds.

Active recon types:

**External Recon:** Conducted outside that target's network, and focuses on assets accessible from the internet
**Internal Recon:** Conducted from within the target company's network.

## Built-in Tools

WHOIS is a request and response protocol, a WHOIS server listens on TCP port 43, the domain register maintains the WHOIS records. Information can be withheld for privacy.

Commands to query DNS servers:

- `nslookup`
- `dig`
- `host`

## Advanced Searching

|Symbol / Syntax|Function|
|---|---|
|`"search phrase"`|Find results with exact search phrase|
|`OSINT filetype:pdf`|Find files of type `PDF` related to a certain term.|
|`salary site:blog.tryhackme.com`|Limit search results to a specific site.|
|`pentest -site:example.com`|Exclude a specific site from results|
|`walkthrough intitle:TryHackMe`|Find pages with a specific term in the page title.|
|`challenge inurl:tryhackme`|Find pages with a specific term in the page URL.|

[Google Hacking Database](https://www.exploit-db.com/google-hacking-database) (GHDB) collects specific searches that can find sensitive information.

##### Social Media

Social media platforms can reveal tons of information, some of them are:

- LinkedIn
- Twitter
- Facebook
- Instsgram

##### Job Ads

Can reveal names and email address and also insight into target company's systems and infrastructure.

## Specialized Search Engines

##### WHOIS and DNS Related

Some websites offer paid services for whois history, which can be helpful if the domain registrant didn't use DNS privacy at the time.

##### ViewDNS.info

[ViewDNS.info](https://viewdns.info/) offers reverse IP lookup, a lot use a shred hosting servers which use the same IP address for multiple web server, with reverse IP lookup you can find multiple websites with a single IP address.

##### Threat Intelligence Platform

[Threat Intelligence Platform](https://threatintelligenceplatform.com/) can launch a series of tests from malware checks to WHOIS and DNS queries, it can also perform reverse IP lookup.

##### Specialized Search Engines

[Censys](https://search.censys.io/): Provides a lot of information about IP addresses and domains.

[Shodan](https://www.shodan.io/): Can be used from the CLI or web browser.

## Recon-ng

[Recon-ng](https://github.com/lanmaster53/recon-ng) is a framework that helps automate the OSINT work, with some modules requiring keys to query the related online API. All data collected is automatically saved in the database.

You can use Recon-ng in the terminal.

## Maltego

Maltego blends mind-map with OSINT, transform is a piece of code which let's you query API to retrieve information related to specific entity, some of the transforms will connect to the target.

![[c54a869cffca4d657f46dac618cc9135.png]]