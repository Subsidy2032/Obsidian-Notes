Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) broadcast poisoning is a Man-in-the-Middle attack. Depending on the network, we can get low user or administrative password hashes, or even plaintext credentials. These hashes can also sometimes be used to perform SMB Relay attack to authenticate to a host or multiple hosts in the domain with administrative privileges without having to crack the password hash.

## LLMNR & NBT-NS Primer

[Link-Local Multicast Name Resolution](https://datatracker.ietf.org/doc/html/rfc4795) (LLMNR) and [NetBIOS Name Service](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc940063(v=technet.10)?redirectedfrom=MSDN) (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification that can be used when DNS fails. When a machine attempts to resolve a host and DNS resolution fails, typically the machine will try to ask all other machines on the local network via LLMNR. LLMNR is based upon DNS format, it uses port 5335 over UDP nativaly. If LLMNR fails NBT-NS will be used. NBT-NS identifies systems on a local network by their NetBIOS name. NBT-NS utilizes port 137 over UDP.

When those protocols are used any host can reply, allowing us to poison the requests. With network access, we can spoof an authoritative name resolution source (For example a host that's supposed to belong to the network segment) in the broadcast domain by responding to requests as if they have an answer. If the host that made the request requires name resolution or authentication actions, we can capture the NetNTLM hash. The captured authentication request can also be relayed to access another host or used against a different protocol (such as LDAP) on the same host. LLMNR/NBNS spoofing combined with a lack of SMB signing can often lead to administrative access on hosts within a domain.

## Quick Example
1. A host attempts to connect to the print server at \\print01.inlanefreight.local, but accidentally types in \\printer01.inlanefreight.local.
2. The DNS server responds, stating that this host is unknown.
3. The host then broadcasts out to the entire local network asking if anyone knows the location of \\printer01.inlanefreight.local.
4. The attacker (us with `Responder` running) responds to the host stating that it is the \\printer01.inlanefreight.local that the host is looking for.
5. The host believes this reply and sends an authentication request to the attacker with a username and NTLMv2 password hash.
6. This hash can then be cracked offline or used in an SMB Relay attack if the right conditions exist.

## TTPs

We perform this actions to get NTLMv1 and NTLMv2 hashes, which are authentication protocols that utilize the LM or NT hash. We will then attempt to crack the hash offline using tools such as [Hashcat](https://hashcat.net/hashcat/) or [John](https://www.openwall.com/john/).

Several tools can be used to attempt LLMNR & NBT-NS poisoning:

|**Tool**|**Description**|
|---|---|
|[Responder](https://github.com/lgandx/Responder)|Responder is a purpose-built tool to poison LLMNR, NBT-NS, and MDNS, with many different functions.|
|[Inveigh](https://github.com/Kevin-Robertson/Inveigh)|Inveigh is a cross-platform MITM platform that can be used for spoofing and poisoning attacks.|
|[Metasploit](https://www.metasploit.com/)|Metasploit has several built-in scanners and spoofing modules made to deal with poisoning attacks.|

Responder is written in Python and typically used on a Linux attack host, though there is an .exe version that works on Windows. Inveigh is written in both C# and PowerShell (considered legacy). Both tools can be used to attack the following protocols:

- LLMNR
- DNS
- MDNS
- NBNS
- DHCP
- ICMP
- HTTP
- HTTPS
- SMB
- LDAP
- WebDAV
- Proxy Auth

Responder also has support for:

- MSSQL
- DCE-RPC
- FTP, POP3, IMAP, and SMTP auth

## Responder in Action

Some common options we'll typically want to use are `-wf`; this will start the WPAD rogue proxy server, while `-f` will attempt to fingerprint the remote host operating system and version. We can use the `-v` flag for increased verbosity if we are running into issues, but this will lead to a lot of additional data printed to the console. Other options such as `-F` and `-P` can be used to force NTLM or Basic authentication and force proxy authentication, but may cause a login prompt, so they should be used sparingly. The use of the `-w` flag utilizes the built-in WPAD proxy server. This can be highly effective, especially in large organizations, because it will capture all HTTP requests by any users that launch Internet Explorer if the browser has [Auto-detect settings](https://docs.microsoft.com/en-us/internet-explorer/ie11-deploy-guide/auto-detect-settings-for-ie11) enabled.

Responder will listen and answer any requests it sees on the wire. If its successful in getting a hash, it will be printed on the screen and will be written to a log file per host located in the `/usr/share/responder/logs` directory. Hashes are saved in the format `(MODULE_NAME)-(HASH_TYPE)-(CLIENT_IP).txt`. Hashes are also stored in a SQLite database that can be configured in the `Responder.conf` config file, typically located in `/usr/share/responder`.

We must run the tool with sudo privileges or as root and make sure the following ports are available on our attack host for it to function best:
```shell-session
UDP 137, UDP 138, UDP 53, UDP/TCP 389,TCP 1433, UDP 1434, TCP 80, TCP 135, TCP 139, TCP 445, TCP 21, TCP 3141,TCP 25, TCP 110, TCP 587, TCP 3128, Multicast UDP 5355 and 5353
```

Any of the rogue servers can be disabled in the `Responder.conf` file.

### Responder Logs
```shell-session
$ ls

Analyzer-Session.log                Responder-Session.log
Config-Responder.log                SMB-NTLMv2-SSP-172.16.5.200.txt
HTTP-NTLMv2-172.16.5.200.txt        SMB-NTLMv2-SSP-172.16.5.25.txt
Poisoners-Session.log               SMB-NTLMv2-SSP-172.16.5.50.txt
Proxy-Auth-NTLMv2-172.16.5.200.txt
```

### Starting Responder with Default Settings
```bash
sudo responder -I ens224 
```

Typically we will run it and let it run in a tmux windows while we perform other enumeration tasks to maximize the number of hashes we can obtain. We can then use Hashcat with mode `5600` for NTLMv2 hashes which are typically obtained. We can look [Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) for other hashes.

NetNTLMv2 hashes cannot be used for techniques like pass-the-hash, meaning we have to attempt to crack them offline.

### Cracking an NTLMv2 Hash with Hashcat
```shell-session
$ hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt 
```

