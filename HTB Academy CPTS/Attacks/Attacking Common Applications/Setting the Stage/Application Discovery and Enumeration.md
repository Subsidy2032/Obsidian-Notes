An organization should always keep an asset inventory that includes everything on his network, including all network connected devices, installed software, and applications in use. The organization should know if applications are installed locally or hosted by a third party, their current patch level, if they are at or nearing end of life, be able to detect any rogue applications in the network (or "shadow IT"), and have enough visibility into each application to ensure they are adequately secure with strong (non-default) passwords, and ideally, multi-factor authentication is enabled. Certain applications have administrative portals that can be restricted to only being accessible from specific IP addresses or the host itself (localhost).

The reality is that many organizations do not know everything on their network, and some organizations have very little visibility, and we can help them with this. The enumeration that we perform can be highly beneficial to our clients to help them enhance or start building an asset inventory. We may very likely identify applications that have been forgotten, demo versions of software that perhaps have had their trial license expired and converted to a version that does not require authentication (in the case of Splunk), applications with default/weak credentials, unauthorized/misconfigured applications, and applications that suffer from public vulnerabilities. We can provide this data to our clients as a combination of the findings in our reports (i.e., an application with default credentials `admin:admin`, as appendices such as a list of identified services mapped to hosts, or supplemental scan data). We can even take it a step further and educate our clients on some of the tools that we use daily so they can begin to perform periodic and proactive recon of their networks and find gaps before penetration testers, or worse, attackers, find them first.

Typically, when we connect to a network, we'll start with a ping sweep to identify "live hosts." From there, we will usually begin targeted port scanning and, eventually, deeper port scanning to identify running services.

### Nmap - Web Discovery
```shell-session
$ nmap -p 80,443,8000,8080,8180,8888,1000 --open -oA web_discovery -iL scope_list
```

Sifting through all the data by hand in large environment would be far too time-consuming.

Two of the tools that can assist us with this are [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) and [Aquatone](https://github.com/michenriksen/aquatone). Those can take raw Nmap XML scan output (Aquatone can also take Masscan XML; EyeWitness can take Nessus XML output) and be used to quickly inspect all hosts running web applications and take screenshots of each. The screenshots are then assembled into a report that we can work through in the web browser to assess the web attack surface.

## Getting Organized

It is important to time and date stamp every scan that we perform and save all output and the exact scan syntax that was performed and the targeted hosts. This can be useful later on if the client has any questions about the activity they saw during the assessment.

An example note taking structure may look like the following for the discovery phase:

`External Penetration Test - <Client Name>`

- `Scope` (including in-scope IP addresses/ranges, URLs, any fragile hosts, testing timeframes, and any limitations or other relative information we need handy)
    
- `Client Points of Contact`
    
- `Credentials`
    
- `Discovery/Enumeration`
    
    - `Scans`
        
    - `Live hosts`
        
- `Application Discovery`
    
    - `Scans`
    - `Interesting/Notable Hosts`
- `Exploitation`
    
    - `<Hostname or IP>`
        
    - `<Hostname or IP>`
        
- `Post-Exploitation`
    
    - `<Hostname or IP>`
        
    - `<<Hostname or IP>`

## Initial Enumeration

We can do an initial scan with ports `80,443,8000,8080,8180,8888,10000` and then run either EyeWitness or Aquatone (or both depending on the results of the first) against the initial scan. We can then run another Nmap scan, for example for the 10000 most common ports. We should then run web screenshotting tool against any subsequent Nmap scans.

We can also run a Nessus scan on a non-evasive full scope penetration test, but we should not rely on scanning tools.

All scans we perform during a non-evasive engagement are to gather data as inputs to our manual validation and manual testing process.

All scans we perform during a non-evasive engagement are to gather data as inputs to our manual validation and manual testing process.

Enumerating one of the hosts further using an Nmap service scan (`-sV`) against the default top 1,000 ports can tell us more about what is running on the webserver.

```shell-session
$ sudo nmap --open -sV 10.129.201.50

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-07 21:58 EDT
Nmap scan report for 10.129.201.50
Host is up (0.13s latency).
Not shown: 991 closed ports
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8000/tcp open  http          Splunkd httpd
8080/tcp open  http          Indy httpd 17.3.33.2830 (Paessler PRTG bandwidth monitor)
8089/tcp open  ssl/http      Splunkd httpd (free license; remote login disabled)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.63 seconds
```

From the output above, we can see that an IIS web server is running on the default port 80, and it appears that `Splunk` is running on port 8000/8089, while `PRTG Network Monitor` is present on port 8080. If we were in a medium to large-sized environment, this type of enumeration would be inefficient. It could result in us missing a web application that may prove critical to the engagement's success.

## Using EyeWitness

EyeWitness can take XML output from both Nmap and Nessus and create a report with screenshots of each web application present on the various ports using Selenium. It will also take things a step further and categorize the applications where possible, fingerprint them, and suggest default credentials based on the application. It can also be given a list of IP addresses and URLs and be told to pre-pend `http://` and `https://` to the front of each. It will perform DNS resolution for IPs and can be given a specific set of ports to attempt to connect to and screenshot.

We can install EyeWitness via apt:
```shell-session
$ sudo apt install eyewitness
```

or clone the [repository](https://github.com/FortyNorthSecurity/EyeWitness), navigate to the `Python/setup` directory and run the `setup.sh` installer script. EyeWitness can also be run from a Docker container, and a Windows version is available, which can be compiled using Visual Studio.

Let's run the default `--web` option to take screenshots using the Nmap XML output from the discovery scan as input:
```shell-session
$ eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness
```

## Using Aquatone

[Aquatone](https://github.com/michenriksen/aquatone) can take screenshots when provided `.txt` file of hosts or an Nmap `.xml` file with the `-nmap` flag. We can compile Aquatone on our own or download a precompiled binary. After downloading the binary, we just need to extract it, and we are ready to go:
```shell-session
$ wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
```

```shell-session
$ unzip aquatone_linux_amd64_1.7.0.zip 
```

We can move it to a location in our `$PATH` such as `/usr/local/bin` to be able to call the tool from anywhere or just drop the binary in our working (say, scans) directory. It's personal preference but typically most efficient to build our attack VMs with most tools available to use without having to constantly change directories or call them from other directories:
```shell-session
$ echo $PATH

/home/mrb3n/.local/bin:/snap/bin:/usr/sandbox/:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/share/games:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
```

In this example, we provide the tool the same `web_discovery.xml` Nmap output specifying the `-nmap` flag, and we're off to the races:
```shell-session
$ cat web_discovery.xml | ./aquatone -nmap
```

## Interpreting the Results

Even with 20 hosts the report will save us time, and more so with 500 or 5000 hosts. The report will be organized into categories, with `High Value Targets` being first and typically the most "juicy" hosts to go after. Some reports can have hundreds of pages that take hours to go through. Often, the very large reports will have interesting hosts buried deep within them, so it's worth reviewing the entire thing and poking at/researching any applications we are not familiar with.

Custom web applications are always worth testing as they may contain a wide variety of vulnerabilities. Here I would also be interested to see if the website was running a popular CMS such as WordPress, Joomla, or Drupal.

During an assessment, I would continue reviewing the report, noting down interesting hosts, including the URL and application name/version for later. It is important at this point to remember that we are still in the information gathering phase, and every little detail could make or break our assessment. During an External Penetration Test, I would expect to see a mix of custom applications, some CMS, perhaps applications such as Tomcat, Jenkins, and Splunk, remote access portals such as Remote Desktop Services (RDS), SSL VPN endpoints, Outlook Web Access (OWA), O365, perhaps some sort of edge network device login page, etc.

Sometimes we will come across applications that absolutely should not be exposed, and we should leave no stone unturned and that there can be an absolute treasure trove of data for us in our application discovery data.

During an Internal Penetration Test, we will see much of the same but often also see many printer login pages (which we can sometimes leverage to obtain cleartext LDAP credentials), ESXi and vCenter login portals, iLO and iDRAC login pages, a plethora of network devices, IoT devices, IP phones, internal code repositories, SharePoint and custom intranet portals, security appliances, and much more.