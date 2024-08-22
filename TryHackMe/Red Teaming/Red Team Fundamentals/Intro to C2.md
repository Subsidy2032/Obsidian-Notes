## Command and Control Framework Structure

##### What is a Command and Control Framework

C2 framework at the basic level is like Netcat listener with the capability of handling multiple reverse shells at once, C2 shine in their Post Exploitation features.

##### Command and Control Structure

**C2 Server:** Serves as a hub for C2 agents, which will periodically reach out and wait for operator's commands.

**Agents / Payloads:** Program that calls back to the listener on a C2 server, usually with more advanced features than a simple shell.

**listeners:** An application on the C2 server that waits for a callback over a specific port or protocol.

**Beacons:** The process of a C2 agent calling back to the listener running on a C2 server.

###### Obfuscating Agent Callbacks

**Sleep Timers:** One of the things a the security team and features are looking for, is beaconing and the rate, sleep time is once in how much time the agent calls back.

**Jitter:** Jitter adds variation to the sleep timer, with more advanced C2 frameworks you can also do things like add jitter to the file like adding junk.

##### Payload Types

**Stageless Payloads:**

1. The Victim downloads and executes the Dropper.
2. The beaconing to the C2 Server begins.

**Staged Payloads:**

1. The Victim downloads and executes the Dropper.
2. The Dropper calls back to the C2 Server for Stage 2.
3. The C2 Server sends Stage 2 back to the Victim Workstation.
4. Stage 2 is loaded into memory on the Victim Workstation.
5. C2 Beaconing Initializes, and the Red Teamer/Threat Actors can engage with the Victim on the C2 Server.

##### Payload Formats

Various formats supported by C2 frameworks:

- PowerShell Scripts (may contain C# code and may execute with the Add-Type commandlet)
- HTA files
- JScript files
- Visual Basic Application/Scripts
- Microsoft Office Documents

##### Modules

Modules add the ability to make agents and the C2 server more flexible, scripts must be written in different languages depending on the C2 framework.

**Post Exploitation Modules:** Modules that deal with anything after the initial point of compromise.

**Pivoting Modules:** Makes it easier to access restricted network segments with the C2 framework, for example by opening SMB beacon.

![[da7b0247ff1db8e98c9358c39a0c3d21.png]]

##### Facing the World

**Domain Fronting:** Domain Fronting utilizes a good known host like Cloudflare, so it will appear as if the agents are communicating with a known and trusted IP address.

![[cd1ea19e9e0d7bef0d8ec6615061335b.png]]

**C2 Profiles (has many other names):** With this technique the C2 server recognizes connections requests (for example by looking at the headers), and sends back a C2 response, whereas if a normal user makes a request he will see a generic webpage.

## Common C2 Frameworks

##### Common C2 Frameworks

Premium/Paid C2 Frameworks usually are harder to detect than free ones, and also have more advanced features.

##### Free C2 Frameworks

- [Metasploit Framework](https://www.metasploit.com/)
- [Armitage](https://web.archive.org/web/20211006153158/http://www.fastandeasyhacking.com/) (also available in [gitlab](https://gitlab.com/kalilinux/packages/armitage)): Extension of Metasploit written in java, similar to Cobalt Strike, one of his features is the Hail Marry attack which tries exploits against all services on the target.
- [Powershell Empire](https://bc-security.gitbook.io/empire-wiki/)/[Starkiller](https://github.com/BC-SECURITY/Starkiller): A incredibly versatile C2, with agents written in various languages and compatible with different operating systems.
- [Covenant](https://github.com/cobbr/Covenant): Written in C#, primarily used for post-exploitation and lateral movement with HTTP, HTTPS and SMB listeners and highly customizable agents.
- [Silver](https://github.com/BishopFox/sliver): Written in Go and difficult to reverse engineer, supports various protocols for communication, can automatically encrypt certificate generation for HTTPS beacon and much more.

##### Paid C2 Frameworks

- [Cobalt Strike](https://www.cobaltstrike.com/): Written in Java and designed to be as flexible as possible.
- [Brute Ratel](https://bruteratel.com/): Provides a true adversary simulation like experience with being a unique C2 framework.

## C2 Operation Basics

You shouldn't have your C2 management interface directly accessible, or else it can be very easy to fingerprint your C2 server.

##### Listener Type

**Standard listener:** Often communicate directly over raw TCP or UDP socket, sending commands in cleartext, Metasploit has full support for those.

**HTTP/HTTPS listeners:** Often front as some sort of web server and uses techniques like domain fronting or melleable C2 profiles, fully supported by Metasploit.

**DNS listener:** Used in the exfiltration phase, where at least a domain name must be purchased and a public ns server must be configured, Metasploit can support this with the help of additional tools.

**SMB listener:** Using SMB named pipes is a popular choice especially when dealing with restricted network, it often enables more flexible pivoting with multiple devices talking to each other and only one device communicating to the server with a common protocol like HTTP/HTTPS, Metasploit has support for this.

## Advanced C2 Setups

##### Command and Control Redirectors

Redirector is a server that redirects HTTP/HTTPS requests based on information within the HTTP request body, you can see it in the form of load balancer and it often runs Apache 2 or NGINX.

Usually the configuration of a redirector is set on multiple hosts.

![[c38457eb8f35b56a630d1e1b9f2bc75f.png]]

You may set callbacks to a domain, in case your server is taken down with a redirector you can ensure that information you gathered during the engagement is safe and sound.

You can set up a firewall to only allow communication to and from your redirector(s) to mitigate potential risks of your server being taken down.

![[3ac046c94e8d8be64015641690f5e8a7.png]]