### DNS Zone Transfer

A DNS zone is a portion of the DNS namespace that a specific organization or administrator manages, DNS zones are used to copy a portion of DNS server's database to another server. If a DNS isn't configured correctly (limiting which IPs can perform a DNS zone transfer), anyone can ask the DNS server for a copy of its zone information since DNS zone transfers to not require any authentication. DNS usually runs on UDP, but When performing DNS zone transfer it uses TCP for reliable communication.

With zone transfer we can learn about the target organization's namespace. We can use the `dig` utility with DNS query type `AXFR` option to dump the entire DNS namespaces from a vulnerable DNS server:

#### DIG - AXFR Zone Transfer
```shell-session
# dig AXFR @ns1.inlanefreight.htb inlanefreight.htb
```

Tools like [Fierce](https://github.com/mschwager/fierce) can also be used to enumerate all DNS servers of the root domain and scan for a DNS zone transfer:
```shell-session
# fierce --domain zonetransfer.me
```

### Domain Takeovers & Subdomain Enumeration

`Domain takeover` involves registering a non-existent domain to gain control over another domain. If attackers find an expired domain, it can be used for attacks such as hosting malicious content on a website or sending a phishing email.

Domain takeover is also possible with subdomains called `subdomain takeover`. A DNS's canonical name (CNAME) record is used to map different domains to a parent domain. Many organization use third party services to host their content, they usually create a subdomain and make it point to those services, for example:
```shell-session
sub.target.com.   60   IN   CNAME   anotherdomain.com
```

The domain name uses a CNAME record to another domain, suppose the other domain expires and available to claim, since `target.com` has the CNAME record, anyone who registers `anotherdomain.com` will have complete control over `sub.target.com` until the DNS record is updated.

#### Subdomain Enumeration

We can use tools like [Subfinder](https://github.com/projectdiscovery/subfinder) to perform subdomain enumeration before preforming a domain takeover. This tool can scrape subdomains from open sources like [DNSdumpster](https://dnsdumpster.com/). Other tools like [Sublist3r](https://github.com/aboul3la/Sublist3r) can also be used to brute-force subdomains by supplying a pre-generated wordlist:
```shell-session
# ./subfinder -d inlanefreight.com -v      
```

[Subbrute](https://github.com/TheRook/subbrute) is an alternative which allows us to use self-defined resolvers, and perform pure DNS brute forcing attacks during internal penetration tests on hosts that don't have internet access.

##### Subbrute
```shell-session
$ git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
$ cd subbrute
$ echo "ns1.inlanefreight.com" > ./resolvers.txt
$ ./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt

Warning: Fewer than 16 resolvers per process, consider adding more nameservers to resolvers.txt.
inlanefreight.com
ns2.inlanefreight.com
www.inlanefreight.com
ms1.inlanefreight.com
support.inlanefreight.com
```

If internal physical configurations are poorly secured, we can use it to upload are tools with a USB stick. Another scenario is if we reached an internal host through pivoting.

We can enumerate the CNAME records for subdomains found using the `nslookup` or `host` command.

```shell-session
# host support.inlanefreight.com

support.inlanefreight.com is an alias for inlanefreight.s3.amazonaws.com
```

In this example we have an alias pointing to an AWS S3 bucket, the URL `https://support.inlanefreight.com` shows a `NoSuchBucket` error indicating that the subdomain is potentially vulnerable to a subdomain takeover. Now we can take over the subdomain by creating an AWS S3 bucket with the same subdomain name.

The [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) repository is also an excellent reference for a subdomain takeover vulnerability. It shows whether the target services are vulnerable to a subdomain takeover and provides guidelines on assessing the vulnerability.

### DNS Spoofing

DNS Spoofing (DNS Cache Poisoning) involves altering legitimate DNS records with false information so that they can be used to redirect online traffic to a fraudulent website, example attack paths for DNS Cache Poisoning are as follows:

- An attacker could intercept the communication between a user and a DNS server to route the user to a fraudulent destination instead of a legitimate one by performing a Man-in-the-Middle (`MITM`) attack.
    
- Exploiting a vulnerability found in a DNS server could yield control over the server by an attacker to modify the DNS records.

#### Local DNS Cache Poisoning

From a local network perspective, an attacker can also perform DNS Cache Poisoning using MITM tools like [Ettercap](https://www.ettercap-project.org/) or [Bettercap](https://www.bettercap.org/).

To exploit the DNS cache poisoning via `Ettercap`, we should first edit the `/etc/ettercap/etter.dns` file to map the target domain name (e.g., `inlanefreight.com`) that they want to spoof and the attacker's IP address (e.g., `192.168.225.110`) that they want to redirect a user to:
```shell-session
# cat /etc/ettercap/etter.dns

inlanefreight.com      A   192.168.225.110
*.inlanefreight.com    A   192.168.225.110
```

Next, start the `Ettercap` tool and scan for live hosts within the network by navigating to `Hosts > Scan for Hosts`. Once completed, add the target IP address (e.g., `192.168.152.129`) to Target1 and add a default gateway IP (e.g., `192.168.152.2`) to Target2.
![[target.webp]]

Activate `dns_spoof` attack by navigating to `Plugins > Manage Plugins`. This sends the target machine with fake DNS responses that will resolve `inlanefreight.com` to IP address `192.168.225.110`:
![[etter_plug.webp]]

After a successful DNS spoof attack, if a victim user coming from the target machine `192.168.152.129` visits the `inlanefreight.com` domain on a web browser, they will be redirected to a `Fake page` that is hosted on IP address `192.168.225.110`:
![[etter_site.webp]]

In addition, a ping coming from the target IP address `192.168.152.129` to `inlanefreight.com` should be resolved to `192.168.225.110` as well:
```cmd-session
C:\>ping inlanefreight.com

Pinging inlanefreight.com [192.168.225.110] with 32 bytes of data:
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64

Ping statistics for 192.168.225.110:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms
```

## Latest DNS Vulnerabilities

A lot of times organizations cancel services from third party providers but forget to delete the associated DNS records. Subdomain Takeover is a bounty category in many websites like [HackerOne](https://www.hackerone.com/), With a simple search we can find many tools on github, for example that automates the discovery of vulnerable subdomains or help creates Proof of Concepts (PoC) that can then be submitted to the bug bounty program.

#### RedHuntLabs Study
![[image-3.webp]]
Source: https://redhuntlabs.com/blog/project-resonance-wave-1.html

### The Concept of the Attack

Subdomain takeover can be used for a phishing campaign, customers will look at the subdomain and see it's part of the official domain, so they will trust it, not knowing it's been mirrored.

If we find a CNAM record that points to a subdomain that no longer exists, or return a HTTP 404 error, it can most likely be taken by us through the use of the third-party provider.

### Initiation of Subdomain Takeover
|**Step**|**Subdomain Takeover**|**Concept of Attacks - Category**|
|---|---|---|
|`1.`|The source, in this case, is the subdomain name that is no longer used by the company that we discovered.|`Source`|
|`2.`|The registration of this subdomain on the third-party provider's site is done by registering and linking to own sources.|`Process`|
|`3.`|Here, the privileges lie with the primary domain owner and its entries in its DNS servers. In most cases, the third-party provider is not responsible for whether this subdomain is accessible via others.|`Privileges`|
|`4.`|The successful registration and linking are done on our server, which is the destination in this case.|`Destination`|

### Trigger the Forwarding
| **Step** | **Subdomain Takeover**                                                                                                                                                                                                                                                        | **Concept of Attacks - Category** |
| -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| `5.`     | The visitor of the subdomain enters the URL in his browser, and the outdated DNS record (CNAME) that has not been removed is used as the source.                                                                                                                              | `Source`                          |
| `6.`     | The DNS server looks in its list to see if it has knowledge about this subdomain and if so, the user is redirected to the corresponding subdomain (which is controlled by us).                                                                                                | `Process`                         |
| `7.`     | The privileges for this already lie with the administrators who manage the domain, as only they are authorized to change the domain and its DNS servers. Since this subdomain is in the list, the DNS server considers the subdomain as trustworthy and forwards the visitor. | `Privileges`                      |
| `8.`     | The destination here is the person who requests the IP address of the subdomain where they want to be forwarded via the network.                                                                                                                                              | `Destination`                     |
|          |                                                                                                                                                                                                                                                                               |                                   |

Subdomain takeover can be used not only for phishing but also for many other attacks. These include, for example, stealing cookies, cross-site request forgery (CSRF), abusing CORS, and defeating content security policy (CSP). We can see some examples of subdomain takeovers on the [HackerOne website](https://hackerone.com/hacktivity?querystring=%22subdomain%20takeover%22), which have earned the bug bounty hunters considerable payouts.