## External Recon and Enumeration Principles

External reconnaissance have many different functions, such as:

- Validating information provided to you in the scoping document from the client
- Ensuring you are taking actions against the appropriate scope when working remotely
- Looking for any information that is publicly accessible that can affect the outcome of your test, such as leaked credentials

### What are We Looking for

Some key items to look for are listed in the table below.

|**Data Point**|**Description**|
|---|---|
|`IP Space`|Valid ASN for our target, netblocks in use for the organization's public-facing infrastructure, cloud presence and the hosting providers, DNS record entries, etc.|
|`Domain Information`|Based on IP data, DNS, and site registrations. Who administers the domain? Are there any subdomains tied to our target? Are there any publicly accessible domain services present? (Mailservers, DNS, Websites, VPN portals, etc.) Can we determine what kind of defenses are in place? (SIEM, AV, IPS/IDS in use, etc.)|
|`Schema Format`|Can we discover the organization's email accounts, AD usernames, and even password policies? Anything that will give us information we can use to build a valid username list to test external-facing services for password spraying, credential stuffing, brute forcing, etc.|
|`Data Disclosures`|For data disclosures we will be looking for publicly accessible files ( .pdf, .ppt, .docx, .xlsx, etc. ) for any information that helps shed light on the target. For example, any published files that contain `intranet` site listings, user metadata, shares, or other critical software or hardware in the environment (credentials pushed to a public GitHub repo, the internal AD username format in the metadata of a PDF, for example.)|
|`Breach Data`|Any publicly released usernames, passwords, or other critical information that can help an attacker gain a foothold.|

### Where are We Looking

The table below lists a few potential resources and examples that can be used.

#### Finding Address Spaces

The `BGP-Toolkit` hosted by [Hurricane Electric](http://he.net/) is good for searching what address is assigned to an organization, and what ASN they reside within. The toolkit will search the results it con for any domain or IP address. Large company usually will self host their infrastructure and have their own ASN, this will usually not be the case for small companies. Understanding where the infrastructure resides is important, or we might go out of scope.

Sometimes a written approval is needed from a third-party hosting provider is needed before testing. Others, such as AWS have specific [guidelines](https://aws.amazon.com/security/penetration-testing/) for performing pen test and doesn't require approval for some of their services. Others, such as Oracle, ask you to submit a [Cloud Security Testing Notification](https://docs.oracle.com/en-us/iaas/Content/Security/Concepts/security_testing-policy_notification.htm). These types of steps should be handled by your company management, legal team, contracts team, etc. Its your responsibility to ensure we have explicit permissions to attack any host (internal or external).

#### DNS

DNS is a great way to validate our scope and find out about reachable hosts the costumer did not disclose in their scoping document. Sites like [domaintools](https://whois.domaintools.com/), and [viewdns.info](https://viewdns.info/) are a great place to start. We can get back many records and data, ranging from DNS resolution to testing for DNSSEC and if the site is accessible in more restricted countries. If we find hosts out of scope, we can bring a list to our client to see if it should be included. subdomains that aren't in the scoping document, but reside on in-scope IP addresses are fair game.

This is also a great way to validate some of the data found from our IP/ASN searches. Not all information about the domain found will be current, and running checks that can validate what we see is always good practice.

#### Public Data

Social media can be a treasure trove of interesting data that can clue us in to how the organization is structured, what kind of equipment they operate, potential software and security implementations, their schema, and more. On top of that list are job-related sites like LinkedIn, Indeed.com, and Glassdoor. Simple job postings often reveal a lot about a company.

Websites hosted by the organization are also great places to dig for information. We can gather contact emails, phone numbers, organizational charts, published documents, etc. These sites, specifically the embedded documents, can often have links to internal infrastructure or intranet sites that you would not otherwise know about. It can help us formulate a picture of the domain structure. With the growing use of sites like GitHub and AWS, data can also be leaked unintentionally. Tools like [Trufflehog](https://github.com/trufflesecurity/truffleHog) and sites like [Greyhat Warfare](https://buckets.grayhatwarfare.com/) are fantastic resources for finding these breadcrumbs.

### Overarching Enumeration Principles

we are looking for every possible avenue we can find that will provide us with a potential route to the inside. Enumeration is our primary source of information on any step. We will start with passive enumeration, at first wide in scope then narrowing down, then we need to examine the results and move to active enumeration.

### Example Enumeration Process

We will practice our enumeration tactics on the `inlanefreight.com` domain. We will first use BGP.he.

### Check for ASN/IP & Domain Data
![[BGPhe-inlane.webp]]

Some interesting info:

- IP Address: 134.209.24.248
- Mail Server: mail1.inlanefreight.com
- Nameservers: NS1.inlanefreight.com & NS2.inlanefreight.com

This is not a large organization, so he doesn't have it's own ASN. Now let's validate some of this information.

#### Viewdns Results
![[viewdns-results.webp]]

With `viewdns.info` we validated the IP address of the target. Now let's try another route to validate the two nameservers in our results.

```shell-session
$ nslookup ns1.inlanefreight.com

Server:		192.168.186.1
Address:	192.168.186.1#53

Non-authoritative answer:
Name:	ns1.inlanefreight.com
Address: 178.128.39.165

nslookup ns2.inlanefreight.com
Server:		192.168.86.1
Address:	192.168.86.1#53

Non-authoritative answer:
Name:	ns2.inlanefreight.com
Address: 206.189.119.186 
```

Now we have 2 new IP address to add to our list for validation and testing.

#### Hunting for Files
![[google-dorks.webp]]

One document popped up, so we need to ensure we note the document and its location and download a copy locally to dig through. It is always best to save files, screenshots, scan output, tool output, etc., as soon as we come across them or generate them. This helps us keep as comprehensive a record as possible and not risk forgetting where we saw something or losing critical data.

#### Hunting E-mail Addresses
![[intext-dork.webp]]

With this we can find email addresses of employees that are probably active. Also to find email naming conventions, which can help us with password spraying or social engineering/phishing if in scope.

#### Username Harvesting

We can use a tool such as [linkedin2username](https://github.com/initstring/linkedin2username) to scrape data from a company's LinkedIn page and create various mashups of usernames (flast, first.last, f.last, etc.) that can be added to our list of potential password spraying targets.

#### Credential Hunting

[Dehashed](http://dehashed.com/) is an excellent tool for hunting for cleartext credentials and password hashes in breach data. We can use the site or a script that performs queries via API. Typically we will find many old password that wouldn't work. But we might get lucky! This tool is also useful for creating a user list.

```shell-session
$ sudo python3 dehashed.py -q inlanefreight.local -p

id : 5996447501
email : roger.grimes@inlanefreight.local
username : rgrimes
password : Ilovefishing!
hashed_password : 
name : Roger Grimes
vin : 
address : 
phone : 
database_name : ModBSolutions

id : 7344467234
email : jane.yu@inlanefreight.local
username : jyu
password : Starlight1982_!
hashed_password : 
name : Jane Yu
vin : 
address : 
phone : 
database_name : MyFitnessPal

<SNIP>
```

## Initial Enumeration of the Domain

### Setting Up

Types of setups a client might choose for us when performing internal penetration testing include:

- A penetration testing distro (typically Linux) as a virtual machine in their internal infrastructure that calls back to a jump host we control over VPN, and we can SSH into.
- A physical device plugged into an ethernet port that calls back to us over VPN, and we can SSH into.
- A physical presence at their office with our laptop plugged into an ethernet port.
- A Linux VM in either Azure or AWS with access to the internal network that we can SSH into using public key authentication and our public IP address whitelisted.
- VPN access into their internal network (a bit limiting because we will not be able to perform certain attacks such as LLMNR/NBT-NS Poisoning).
- From a corporate laptop connected to the client's VPN.
- On a managed workstation (typically Windows), physically sitting in their office with limited or no internet access or ability to pull in tools. They may also elect this option but give you full internet access, local admin, and put endpoint protection into monitor mode so you can pull in tools at will.
- On a VDI (virtual desktop) accessed using Citrix or the like, with one of the configurations described for the managed workstation typically accessible over VPN either remotely or from a corporate laptop.

The client can also come up with a different version of one of those. He may also choose a gray box or a black box approach. They may also elect to have us start with no credentials or from the perspective of a standard domain user.

### Tasks

It's a common approach to start without credentials, for the client to see what an attacker with access to the network can do to infiltrate the domain from a blind perspective. They might later provide you with access to a domain-joined host, or a set of credentials to expedite testing, and allow us to cover as much ground as possible.

Below are some of the key data points that we should be looking for at this time and noting down into our notetaking tool of choice and saving scan/tool output to files whenever possible.

#### Key Data Points
|**Data Point**|**Description**|
|---|---|
|`AD Users`|We are trying to enumerate valid user accounts we can target for password spraying.|
|`AD Joined Computers`|Key Computers include Domain Controllers, file servers, SQL servers, web servers, Exchange mail servers, database servers, etc.|
|`Key Services`|Kerberos, NetBIOS, LDAP, DNS|
|`Vulnerable Hosts and Services`|Anything that can be a quick win. ( a.k.a an easy host to exploit and gain a foothold)|

### TTPs

We need to enumerate the AD environment in progressive ways, since there is abundance of data stored in the AD. We will need to find our own approach.

We will start with passive identification of hosts in the network, then move to active validation. Once we know what hosts exist we can start probing them, looking for interesting data. Now we can look at the data we gathered, hopefully we have a set of credentials or a user account to target for a foothold into a domain joined host, or have the ability to begin credentialed enumeration from the attack host.

#### Identifying Hosts

We can use Wireshark and TCPDump to "put ear to the wire" and see what hosts and types of network traffic we can capture. This is particularly helpful with a black box approach.

[ARP](https://en.wikipedia.org/wiki/Address_Resolution_Protocol) can make us aware of hosts IP address, [MDNS](https://en.wikipedia.org/wiki/Multicast_DNS) can make us aware of host names, and there can be other interesting protocols.

On a host without GUI we can use [tcpdump](https://linux.die.net/man/8/tcpdump), [net-creds](https://github.com/DanMcInerney/net-creds), and [NetMiner](https://www.netminer.com/en/product/netminer.php), etc. We can also use tcpdump to save a capture to .pcap file, transfer it to another host, and open it in Wireshark.

##### TCPDump
```shell-session
$ sudo tcpdump -i <interface> 
```

Depending on the host you are in, you might already have a built-in sniffing tool, like `pktmon.exe` which is added to all editions of Windows 10. It's always good to save a PCAP file, for later reference and additional information for the report.

We can now utilize `Responder` to analyze network traffic and determine if anything else in the domain pops up.

[Responder](https://github.com/lgandx/Responder-Windows) is a tool built in to listen, analyze, and poison LLMNR, NBT-NS, and MDNS requests and responses. It has many functions, but for now we will use analyze mode, which only listens to the network.

##### Starting Responder
```bash
sudo responder -I <interface> -A 
```

We can now add to the list any additional IPs and DNS hostnames we find.

[Fping](https://fping.org/) has the functionality of regular ping, along with the ability to issue ICMP packets against a list multiple hosts at once and its scriptability. Also it works in a round robin fashion, querying host in a cyclical manner instead of waiting for multiple requests to a single host to return before moving on. ICMP is an easy way to get an initial idea of what exists. We might discover more later with open ports and active protocols.

##### Fping Active Checks
```shell-session
$ fping -asgq 172.16.5.0/23
```

With this command we can see which hosts are active, without it spamming the terminal with results for any single IP on the list.

##### Nmap Scanning

We are now looking to find out which services are running on each host from our list, identify critical hosts such as domain controllers and web servers, and identify potentially vulnerable hosts to probe later. We will look for standard AD services such as SMB, DNS, LDAP, and Kerberos to name a few.

```bash
sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum
```

We need to be aware of what scans we run and how they work. Some of the Nmap scripted scans run active vulnerability checks against a host that could cause system instability or take it offline, causing issues for the customer or worse. For example, running a large discovery scan against a network with devices such as sensors or logic controllers could potentially overload them and disrupt the customer's industrial equipment causing a loss of product or capability. Take the time to understand the scans you use before running them in a customer's environment.

### Identifying Users

In case the client doesn't provide us with a user to start testing with, we will need to establish a foothold in the domain by obtaining clear text credentials or an NTLM password hash for a user, a SYSTEM shell on a domain joined host, or a shell in the context of a domain user account.

#### Kerbrute - Internal AD Username Enumeration

[Kerbrute](https://github.com/ropnop/kerbrute) can be a stealthier option for domain account enumeration. It takes advantage of the fact that Kerberos pre-authentication failures often will not trigger logs or alerts. [Insidetrust](https://github.com/insidetrust/statistically-likely-usernames) is a repository which contains many different user lists that can be extremely useful when attempting to enumerate users from an unauthenticated perspective. We can point Kerbrute at the DC we found earlier. The tool is quick, and the results will show if the accounts found are valid or not.

We can download [precompiled binaries](https://github.com/ropnop/kerbrute/releases/latest) for the tool, or we can compile it ourselves which is usually the best practice when introducing tools to the client environment.

##### Cloning Kerbrute GitHub Repo
```shell-session
$ sudo git clone https://github.com/ropnop/kerbrute.git
```

##### Listing Compiling Options
```shell-session
$ make help
```

We can choose to compile one binary, or compile the binaries for all OSs (x86 and x64 version of each).

##### Compiling for Multiple Platforms and Architectures
```shell-session
$ sudo make all
```

##### Listing the Compiled Binaries in dist
```shell-session
$ ls dist/
```

##### Testing the kerbrute_linux_amd64 Binary
```shell-session
$ ./kerbrute_linux_amd64 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 02/17/22 - Ronnie Flathers @ropnop

This tool is designed to assist in quickly bruteforcing valid Active Directory accounts through Kerberos Pre-Authentication.
It is designed to be used on an internal Windows domain with access to one of the Domain Controllers.
Warning: failed Kerberos Pre-Auth counts as a failed login and WILL lock out accounts

Usage:
  kerbrute [command]
```

##### Adding the Tool to our Path
```shell-session
$ echo $PATH
/home/htb-student/.local/bin:/snap/bin:/usr/sandbox/:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/share/games:/usr/local/sbin:/usr/sbin:/sbin:/snap/bin:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/home/htb-student/.dotnet/tools
```

##### Moving the Binary
```shell-session
$ sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
```

##### Enumerating Users with Kerbrute
```shell-session
$ kerbrute userenum -d <domain> --dc <IP address> <users wordlist> -o <output file name>
```

### Identifying Potential Vulnerabilities

The [local system](https://docs.microsoft.com/en-us/windows/win32/services/localsystem-account) account `NT AUTHORITY\SYSTEM` is a built in account in Windows. It has the highest level of privileges and is used to run most Windows services. Third party services also often run in the context of this account. With this account we can enumerate AD by impersonating the computer account, which is just another kind of user account. It is almost equivalent to having a domain user account.

There are several ways to gain SYSTEM-level access on a host, including but not limited to:

- Remote Windows exploits such as MS08-067, EternalBlue, or BlueKeep.
- Abusing a service running in the context of the `SYSTEM account`, or abusing the service account `SeImpersonate` privileges using [Juicy Potato](https://github.com/ohpe/juicy-potato). This type of attack is possible on older Windows OS' but not always possible with Windows Server 2019.
- Local privilege escalation flaws in Windows operating systems such as the Windows 10 Task Scheduler 0-day.
- Gaining admin access on a domain-joined host with a local account and using Psexec to launch a SYSTEM cmd window

By gaining SYSTEM-level access on a domain-joined host, you will be able to perform actions such as, but not limited to:

- Enumerate the domain using built-in tools or offensive tools such as BloodHound and PowerView.
- Perform Kerberoasting / ASREPRoasting attacks within the same domain.
- Run tools such as Inveigh to gather Net-NTLMv2 hashes or perform SMB relay attacks.
- Perform token impersonation to hijack a privileged domain user account.
- Carry out ACL attacks.

### A Word of Caution

Keep the scope and the goal of the assessment in mind. For example if you need to be stealthy using Nmap to scan all hosts on the network might not be a good idea.

