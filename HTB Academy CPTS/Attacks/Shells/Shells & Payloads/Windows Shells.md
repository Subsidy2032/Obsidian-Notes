## Prominent Windows Exploits
| **Vulnerability** | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MS08-067`        | MS08-067 was a critical patch pushed out to many different Windows revisions due to an SMB flaw. This flaw made it extremely easy to infiltrate a Windows host. It was so efficient that the Conficker worm was using it to infect every vulnerable host it came across. Even Stuxnet took advantage of this vulnerability.                                                                                                                                                                                      |
| `Eternal Blue`    | MS17-010 is an exploit leaked in the Shadow Brokers dump from the NSA. This exploit was most notably used in the WannaCry ransomware and NotPetya cyber attacks. This attack took advantage of a flaw in the SMB v1 protocol allowing for code execution. EternalBlue is believed to have infected upwards of 200,000 hosts just in 2017 and is still a common way to find access into a vulnerable Windows host.                                                                                                |
| `PrintNightmare`  | A remote code execution vulnerability in the Windows Print Spooler. With valid credentials for that host or a low privilege shell, you can install a printer, add a driver that runs for you, and grants you system-level access to the host. This vulnerability has been ravaging companies through 2021. 0xdf wrote an awesome post on it [here](https://0xdf.gitlab.io/2021/07/08/playing-with-printnightmare.html).                                                                                          |
| `BlueKeep`        | CVE 2019-0708 is a vulnerability in Microsoft's RDP protocol that allows for Remote Code Execution. This vulnerability took advantage of a miss-called channel to gain code execution, affecting every Windows revision from Windows 2000 to Server 2008 R2.                                                                                                                                                                                                                                                     |
| `Sigred`          | CVE 2020-1350 utilized a flaw in how DNS reads SIG resource records. It is a bit more complicated than the other exploits on this list, but if done correctly, it will give the attacker Domain Admin privileges since it will affect the domain's DNS server which is commonly the primary Domain Controller.                                                                                                                                                                                                   |
| `SeriousSam`      | CVE 2021-36924 exploits an issue with the way Windows handles permission on the `C:\Windows\system32\config` folder. Before fixing the issue, non-elevated users have access to the SAM database, among other files. This is not a huge issue since the files can't be accessed while in use by the pc, but this gets dangerous when looking at volume shadow copy backups. These same privilege mistakes exist on the backup files as well, allowing an attacker to read the SAM database, dumping credentials. |
| `Zerologon`       | CVE 2020-1472 is a critical vulnerability that exploits a cryptographic flaw in Microsoft’s Active Directory Netlogon Remote Protocol (MS-NRPC). It allows users to log on to servers using NT LAN Manager (NTLM) and even send account changes via the protocol. The attack can be a bit complex, but it is trivial to execute since an attacker would have to make around 256 guesses at a computer account password before finding what they need. This can happen in a matter of a few seconds.              |

## Enumerating Windows and Fingerprinting Methods

### Identify it's a Windows OS

In Windows the TTL value when pinging the host is usually 128, and sometimes 32, Nmap can aid in detection as well.

### Banner Grab With Nmap to Enumerate Ports
```shell-session
$ sudo nmap -v <ip address> --script banner.nse
```

## Bats, DLLs, and MSI Files

[DLLs](https://docs.microsoft.com/en-us/troubleshoot/windows-client/deployment/dynamic-link-library): A Dynamic Linking Library (DLL) is a library file with a shared code and data that can be used by many different programs at once, those are modular and allows us to have applications that are more dynamic and easier to manage, by injecting a malicious DLL or hijacking a vulnerable library we can elevate privileges to SYSTEM and/or bypass User Account Controls.

[Batch](https://commandwindows.com/batch.htm): Text-based DOS scripts utilized to complete multiple tasks through the command line interpreter, those files have a `.bat` extension, we can run with batch files, for example we can open a port or connect back to our attacker machine.

[VBS](https://www.guru99.com/introduction-to-vbscript.html): VBScript is a lightweight scripting language based on Microsoft's Visual Basic, usually used as a client side scripting language in webservers to enable dynamic web pages, it is dated and disabled in most browsers, but used for attacks like phishing, making user to enable the loading of macros in an excel document, or clicking on a cell to have the Windows scripting engine execute a piece of code.

[MSI](https://docs.microsoft.com/en-us/windows/win32/msi/windows-installer-file-extensions): `.msi` files are installation database for Windows installer, when attempting to install new application, the installer will look for the `.msi` file to understand all of the components required and how to find them, we can use it to create a malicious `.msi` file, and then run it using `msiexec`, which can for example provide us elevated reverse shell.

[Powershell](https://docs.microsoft.com/en-us/powershell/scripting/overview?view=powershell-7.1): Powershell is both shell environment and scripting language, it is a dynamic language based on the .NET Common Language Runtime, it takes input and output as .NET objects, it can provide us with a plethora of options.

## Tools, Tactics, and Procedures for Payload Generation, Transfer, and Execution

### Payload Generation
| **Resource**                      | **Description**                                                                                                                                                                                                                                                                                                   |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MSFVenom & Metasploit-Framework` | [Source](https://github.com/rapid7/metasploit-framework) MSF is an extremely versatile tool for any pentester's toolkit. It serves as a way to enumerate hosts, generate payloads, utilize public and custom exploits, and perform post-exploitation actions once on the host. Think of it as a swiss-army knife. |
| `Payloads All The Things`         | [Source](https://github.com/swisskyrepo/PayloadsAllTheThings) Here, you can find many different resources and cheat sheets for payload generation and general methodology.                                                                                                                                        |
| `Mythic C2 Framework`             | [Source](https://github.com/its-a-feature/Mythic) The Mythic C2 framework is an alternative option to Metasploit as a Command and Control Framework and toolbox for unique payload generation.                                                                                                                    |
| `Nishang`                         | [Source](https://github.com/samratashok/nishang) Nishang is a framework collection of Offensive PowerShell implants and scripts. It includes many utilities that can be useful to any pentester.                                                                                                                  |
| `Darkarmour`                      | [Source](https://github.com/bats3c/darkarmour) Darkarmour is a tool to generate and utilize obfuscated binaries for use against Windows hosts.                                                                                                                                                                    |

### Payload Transfer and Execution

- [Impacket](https://github.com/SecureAuthCorp/impacket): A toolset built in Python and allows us to interact with network protocols directly.
- [Payloads All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Download%20and%20Execute.md): is a great resource to find quick oneliners to help transfer files across hosts expediently.
- SMB: Especially useful when the victim hosts are domain joined and utilize shares to host data, we can use those shares, like C$ and admin$ to transfer payloads or exfiltrate data.
- Remote execution via MSF
- Other protocols: Protocols like FTP, TFTP, HTTP/S, and more can help us upload files to the host.

## PowerShell vs CMD

- CMD is more basic than PowerShell
- CMD does not keep a record of executed commands, and can be more stealthy
- Problems such as Execution Policy and User Account Control (UAC) can inhibit your ability to execute commands on the host, those considerations effect PowerShell but not CMD
- PowerShell isn't present on Windows systems older than Windows 7

## WSL and PowerShell for Linux

The Windows Subsystem for Linux provides a virtual Linux environment built into a Windows host, it can be abused for downloading and installing payloads, for example with built-in Python libraries that are native to both Windows and Linux or using Linux binaries, one other thing is that network requests or functions executed to or from the WSL instance are not parsed by the Windows Firewall and Windows Defender, making it a bit of a blind spot on the host.

The same issues can be found in PowerShell Core which can be installed on Linux operating systems and carry over many normal PowerShell functions.

Both attacks are sneaky since not much is known about them, and have shone to evade EDR and AV detection mechanisms.