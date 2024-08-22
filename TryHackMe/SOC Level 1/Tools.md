### Hash lookups (Trivial)

Color: Blue

- [VirusTotal](https://www.virustotal.com/gui/)
- [Metadefender Cloud - OPSWAT](https://metadefender.opswat.com/?lang=en)
- [SSDeep](https://ssdeep-project.github.io/ssdeep/index.html): For hash fuzzing
### Network analysis

- TShark: command line tool to generate and analyze PCAP files
- [snort](https://www.snort.org/)
- [NetworkMiner](https://www.netresec.com/?page=NetworkMiner): Open Source traffic sniffer, pcap handler and protocol analyzer
- [Zeek](https://docs.zeek.org/en/master/index.html): Focused on specific threats to trigger alarms
- [Brim](https://www.brimdata.io/): Desktop app that mainly provides search and analytics of PCAP and log files, uses Zeek log processing format

### Checking files

- [MalwareBazaar](https://bazaar.abuse.ch/)
- [Malshare](https://malshare.com/)

### Detection rules

- [SOC Prime Threat Detection Marketplace](https://tdm.socprime.com/)

### OSINT

- [theHarvester](https://github.com/laramies/theHarvester) - other than gathering emails, this tool is also capable of gathering names, subdomains, IPs, and URLs using multiple public data sources 
- [Hunter.io](https://hunter.io/) - this is  an email hunting tool that will let you obtain contact information associated with the domain
- [OSINT Framework](https://osintframework.com/) - OSINT Framework provides the collection of OSINT tools based on various categories

## Threat Intelligence

- [**CrowdStrike**](https://www.crowdstrike.com)
- [TAXII](https://oasis-open.github.io/cti-documentation/taxii/intro)
- [STIX](https://oasis-open.github.io/cti-documentation/stix/intro)
- [[Threat Intelligence Tools]]([**Urlscan.io**](https://urlscan.io))
- [[Threat Intelligence Tools]]([Abuse.ch](https://abuse.ch))
- [[Threat Intelligence Tools]]([Talos Intelligence](https://talosintelligence.com))

### Email Analysis

- [[Threat Intelligence Tools]]([PhishTool](https://www.phishtool.com))
- [IPinfo](https://ipinfo.io/): Check information about sender's IP address
- [URL Extractor](https://www.convertcsv.com/url-extractor.htm)
- [CyberChef](https://gchq.github.io/CyberChef/)

#### Header Analysis

- [Messageheader](https://toolbox.googleapps.com/apps/messageheader/analyzeheader)
- [Message Header Analyzer](https://mha.azurewebsites.net/)
- [mailheader](https://mailheader.org/)

#### URL analysis

- [URLScan](https://urlscan.io/)
- [Talos Reputation Center](https://talosintelligence.com/reputation)

## Windows Host Security

- Sysinternals: Compilation of 70+ tools for Windows
- Sysmon: Used to monitor log events

## Endpoint Security monitoring

- Process Hacker: Like Task Manager with added functionality
- Process Explorer: Like Task Manager with added functionality
- Osquery: Converts the operating system into a relational database
- Wazuh: Extensive EDR solution which operates on a management and agent model

## Siem

- [Splunk](https://www.splunk.com/)
- [Elastic Search](https://www.elastic.co/): Full-text search and analytics engine used to store JSON-formated documents

## Forensics

- [Autopsy](https://www.autopsy.com/): open-source and powerful digital forensics platform
- [Redline](https://fireeye.market/apps/211364): Analyze Windows, Linux and macOS endpoints through memory dump
- [KAPE](https://www.kape.com/): Parses and extracts Windows forensics artifacts, gives results before the imaging process completes
- [Volatility](https://www.volatilityfoundation.org/releases): the world's most widely used framework for extracting digital artifacts from volatile memory (RAM) samples
- [Velociraptor](https://docs.velociraptor.app/): Collect and organize data from client machines
- [TheHive Project](http://thehive-project.org/): Collaborative incident response platform

## Malware analysis

[pecheck](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pecheck.py): Analyzing PE header
#### Sandboxing

- [Any.run](https://any.run/): Executes sample, can review connections like HTTP requests, DNS requests or processes communicating with an IP address
- [Cukoo](https://cuckoosandbox.org/): Outdated
- CAPE
- [Intezer](https://analyze.intezer.com/)
- [Hybrid Analysis](https://www.hybrid-analysis.com/)
