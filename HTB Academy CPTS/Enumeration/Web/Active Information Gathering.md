## Active Infrastructure Identification

Some of the most popular web applications are Apache, Nginx, and Microsoft IIS.

Version of IIS installed on Windows versions by default:

- IIS 6.0: Windows Server 2003
- IIS 7.0-8.5: Windows Server 2008 / Windows Server 2008R2
- IIS 10.0 (v1607-v1709): Windows Server 2016
- IIS 10.0 (v1809-): Windows Server 2019

In Windows it will usually be correct, but we can't do the same with Linux.

### Web Servers

#### HTTP Headers

We can look at the response headers to identify the webserver version:
```shell-session
$ curl -I "http://${TARGET}"
```

Other interesting headers:

- X-Powered-By header: Can tell us what the web app is using, for example PHP, ASP.NET, or JSP.
- Cookies: Each technology by default has its cookies, some default cookie values are:
	- .NET: `ASPSESSIONID<RANDOM>=<COOKIE_VALUE>`
	- PHP: `PHPSESSID=<COOKIE_VALUE>`
	- JAVA: `JSESSION=<COOKIE_VALUE>`

Other available tools can analyze common web server characteristics, by probing and comparing the responses to a database of signatures to guess information like version, installed modules, and enabled services.

#### WhatWeb

[Whatweb](https://www.morningstarsecurity.com/research/whatweb) recognizes web technologies, including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices.

```shell-session
$ whatweb -a3 https://www.facebook.com -v
```

[Wappalyzer](https://www.wappalyzer.com) can be installed as a browser extension, and has similar functionality to WhatWeb.

[WafW00f](https://github.com/EnableSecurity/wafw00f) is a web application firewall (`WAF`) fingerprinting tool that sends requests and analyses responses to determine if a security solution is in place.

#### Installing WafW00f
```shell-session
$ sudo apt install wafw00f -y
```

#### Using WafW00f
```shell-session
$ wafw00f -v https://www.tesla.com
```

[Aquatone](https://github.com/michenriksen/aquatone) is a tool for automatic and visual inspection of websites across many hosts and is convenient for quickly gaining an overview of HTTP-based attack surfaces by scanning a list of configurable ports, visiting the website with a headless Chrome browser, and taking a screenshot. This is helpful, especially when dealing with huge subdomain lists.

#### Installing Aquatone
```shell-session
$ sudo apt install golang chromium-driver
$ go get github.com/michenriksen/aquatone
$ export PATH="$PATH":"$HOME/go/bin"
```

#### Using Aquatone
```shell-session
$ cat facebook_aquatone.txt | aquatone -out ./aquatone -screenshot-timeout 1000
```

After running the command we will have file called `aquatone_report.html`.

## Active Subdomain Enumeration

We can perform active subdomain enumeration by probing the infrastructure managed by the target organization, or third party DNS servers.

### Zone Transfers

The zone transfer is how a secondary DNS server receives information from the primary DNS server and updates it. The master-slave approach is used. The master DNS server should be configured to enable zone transfer from secondary (slave) DNS servers, although this might be misconfigured.

we can use the [https://hackertarget.com/zone-transfer/](https://hackertarget.com/zone-transfer/) service and the `zonetransfer.me` domain to have an idea of the information that can be obtained via this technique:

![[zonetransfer.webp]]

A manual approach:

#### 1. Identifying Nameservers
```shell-session
$ nslookup -type=NS zonetransfer.me
```

#### 2. Testing for ANY and AXFR Zone Transfer
```shell-session
$ nslookup -type=any -query=AXFR zonetransfer.me nsztm1.digi.ninja
```

Successful zone transfer will extract all the available information, and there is no need to continue enumerating this domain.

### Gobuster

#### Example for patterns.txt file if We Found a Pattern for a Subdomain
```shell-session
lert-api-shv-{GOBUSTER}-sin6
atlas-pp-shv-{GOBUSTER}-sin6
```

#### Gobuster DNS
```shell-session
$ export TARGET="facebook.com"
$ export NS="d.ns.facebook.com"
$ export WORDLIST="numbers.txt"
$ gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.txt"

Found: lert-api-shv-01-sin6.facebook.com
Found: atlas-pp-shv-01-sin6.facebook.com
Found: atlas-pp-shv-02-sin6.facebook.com
Found: atlas-pp-shv-03-sin6.facebook.com
Found: lert-api-shv-03-sin6.facebook.com
Found: lert-api-shv-02-sin6.facebook.com
Found: lert-api-shv-04-sin6.facebook.com
Found: atlas-pp-shv-04-sin6.facebook.com
```

## Virtual Hosts

A virtual host (vHost) is a feature that allows several websites to be hosted on a single server.

### IP-based Virtual Hosting

The host can have multiple network interfaces, IP addresses, or interface aliases configured on each network interface of a host, different servers can be addressed under different IP address on the host, from the client's point of view, the servers are independent of each other.

### Name-based Virtual Hosting

Several domain names refers to the same IP address, internally on the server those are separated and distinguished using different folders, for example `/var/www/admin` for `admin.inlanefreight.htb` and `/var/www/backup` for `backup.inlanefreight.htb`.

Another possibility for different  subdomains having the same IP address, is if they sit behind a proxy.

You can use cURL with different domains and see if the response changes.

cURL with the default website:
```shell-session
$ curl -s http://192.168.10.10
```

cURL with a previously identified domain (the response will be different):
```shell-session
$ curl -s http://192.168.10.10 -H "Host: randomtarget.com"
```

### Automating the Process
```shell-session
$ cat ./vhosts | while read vhost;do echo "\n********\nFUZZING: ${vhost}\n********";curl -s -I http://192.168.10.10 -H "HOST: ${vhost}.randomtarget.com" | grep "Content-Length: ";done
```

`/usr/share/SecLists/Discovery/DNS/namelist.txt` is a useful wordlist for that.

### Automating Virtual Hosts Discovery

With [ffuf](https://github.com/ffuf/ffuf) we can speed up the process and filter based on parameters present in the response.

#### Filter by Size (discard default response)
```shell-session
$ ffuf -w ./vhosts -u http://<ip address> -H "HOST: FUZZ.randomtarget.com" -fs <size>
```

## Crawling

Crawling a website is a systematic or automatic process of exploring a website to list all resources encountered along the way. It shows the structure of the website, and attack surface, we want to find as many pages and subdirectories belonging to the website as possible.

### ZAP

[Zed Attack Proxy](https://www.zaproxy.org) (`ZAP`) is an open-source web proxy that belongs to the [Open Web Application Security Project](https://owasp.org/) (`OWASP`). It allows us to perform manual and automated security testing on web applications. It can be used as a proxy.

#### Use the Spidering Functionality

Open the browser on the top right corner -> Write the website in the address bar and add it to the scope using the first entry in the left menu -> Head back to the ZAP Window, right-click on the target website, click on the Attack menu, and then the Spider submenu -> Once the process has finished, we can see the resources discovered by the spidering process

ZAP also has a built-in Fuzzer and Manual Request Editor, can be accessed by right clicking requests.

### FFuF

ZAP spidering module only finds resources from links and forms, it can miss information like hidden folders and backup files.

#### Recursively Find Folders Names and Look Through Them
```shell-session
$ ffuf -recursion -recursion-depth 1 -u http://192.168.10.10/FUZZ -w /usr/share/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt
```

If the website responds slower than usual, we can lower the rate of requests using the `-rate` parameter.

### Sensitive Information Disclosure

`raft-[ small | medium | large ]-extensions.txt` files from [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content) has a list of common extensions.

#### Extract Keywords from the Website
```shell-session
$ cewl -m5 --lowercase -w wordlist.txt http://192.168.10.10
```

#### Use FFuF to Find Hidden Folders and Files
```shell-session
$ ffuf -w ./folders.txt:FOLDERS,./wordlist.txt:WORDLIST,./extensions.txt:EXTENSIONS -u http://192.168.10.10/FOLDERS/WORDLISTEXTENSIONS
```

For example we can use previously found folders, keywords from the `cewl` output, and known extensions wordlist.