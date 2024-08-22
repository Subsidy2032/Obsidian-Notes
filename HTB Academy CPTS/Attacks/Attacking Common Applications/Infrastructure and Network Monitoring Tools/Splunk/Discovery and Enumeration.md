Splunk is a log analytics tool used to gather, analyze and visualize data. Though not originally intended to be a SIEM tool, Splunk is often used for security monitoring and business analytics. Splunk deployments are often used to house sensitive data and could provide a wealth of information for an attacker if compromised. Historically, Splunk has not suffered from many known vulnerabilities aside from an information disclosure vulnerability (CVE-2018-11409) and an authenticated remote code execution vulnerability in very old versions (CVE-2011-4642). Here are a few [details](https://www.splunk.com/en_us/customers.html) about Splunk:

- Splunk was founded in 2003, first became profitable in 2009, and had its initial public offering (IPO) in 2012 on NASDAQ under the symbol SPLK
- Splunk has over 7,500 employees and annual revenue of nearly $2.4 billion
- In 2020, Splunk was named to the Fortune 1000 list
- Splunk's clients include 92 companies on the Fortune 100 list
- [Splunkbase](https://splunkbase.splunk.com/) allows Splunk users to download apps and add-ons for Splunk. As of 2021, there are over 2,000 available apps

We will more often than not see Splunk during our assessments, especially in large corporate environments during internal penetration tests. We have seen it exposed externally, but this is rarer. Splunk does not suffer from many exploitable vulnerabilities and is quick to patch any issues. The biggest focus of Splunk during an assessment would be weak or null authentication because admin access to Splunk gives us the ability to deploy custom applications that can be used to quickly compromise a Splunk server and possibly other hosts in the network depending on the way Splunk is set up.

## Discovery/Footprinting

Splunk often runs as root on Linux or SYSTEM on Windows systems. While uncommon, we may encounter Splunk externally facing at times.

The Splunk web server runs by default on port 8000. On older versions of Splunk, the default credentials are `admin:changeme`, which are conveniently displayed on the login page:
![[changme.webp]]

The latest version of Splunk sets credentials during the installation process. If the default credentials do not work, it is worth checking for common weak passwords such as `admin`, `Welcome`, `Welcome1`, `Password123`, etc.

We can discover Splunk with a quick Nmap service scan. Here we can see that Nmap identified the `Splunkd httpd` service on port 8000 and port 8089, the Splunk management port for communication with the Splunk REST API:
```shell-session
$ sudo nmap -sV 10.129.201.50

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-22 08:43 EDT
Nmap scan report for 10.129.201.50
Host is up (0.11s latency).
Not shown: 991 closed ports
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8000/tcp open  ssl/http      Splunkd httpd
8080/tcp open  http          Indy httpd 17.3.33.2830 (Paessler PRTG bandwidth monitor)
8089/tcp open  ssl/http      Splunkd httpd
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.22 seconds
```

## Enumeration

The Splunk Enterprise trial converts to a free version after 60 days, which doesn’t require authentication. It is not uncommon for system administrators to install a trial of Splunk to test it out, which is subsequently forgotten about. Some organizations may opt for the free version due to budget constraints, not fully understanding the implications of having no user/role management:
![[license_group.webp]]

Once logged in to Splunk (or having accessed an instance of Splunk Free), we can browse data, run reports, create dashboards, install applications from the Splunkbase library, and install custom applications.

Splunk has multiple ways of running code, such as server-side Django applications, REST endpoints, scripted inputs, and alerting scripts. A common method of gaining remote code execution on a Splunk server is through the use of a scripted input. These are designed to help integrate Splunk with data sources such as APIs or file servers that require custom methods to access. Scripted inputs are intended to run these scripts, with STDOUT provided as input to Splunk.

As Splunk can be installed on Windows or Linux hosts, scripted inputs can be created to run Bash, PowerShell, or Batch scripts. Also, every Splunk installation comes with Python installed, so Python scripts can be run on any Splunk system.

Aside from this built-in functionality, Splunk has suffered from various public vulnerabilities over the years, such as this [SSRF](https://www.exploit-db.com/exploits/40895) that could be used to gain unauthorized access to the Splunk REST API. At the time of writing, Splunk has [47](https://www.cvedetails.com/vulnerability-list/vendor_id-10963/Splunk.html) CVEs. If we perform a vulnerability scan against Splunk during a penetration test, we will often see many non-exploitable vulnerabilities returned. This is why it is important to understand how to abuse built-in functionality.