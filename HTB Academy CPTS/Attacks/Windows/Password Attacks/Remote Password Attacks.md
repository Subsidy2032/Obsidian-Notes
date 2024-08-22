## Network Services

### WinRM

[Windows Remote Management](https://docs.microsoft.com/en-us/windows/win32/winrm/portal) (`WinRM`) is the Microsoft implementation of the network protocol [Web Services Management Protocol](https://docs.microsoft.com/en-us/windows/win32/winrm/ws-management-protocol) (`WS-Management`). It is a network protocol based on XML web services using the [Simple Object Access Protocol](https://docs.microsoft.com/en-us/windows/win32/winrm/windows-remote-management-glossary) (`SOAP`) used for remote management of Windows systems. It takes care of the communication between [Web-Based Enterprise Management](https://en.wikipedia.org/wiki/Web-Based_Enterprise_Management) (`WBEM`) and the [Windows Management Instrumentation](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page) (`WMI`), which can call the [Distributed Component Object Model](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/4a893f3d-bd29-48cd-9f43-d9777a4415b0) (`DCOM`).

WinRM if used typically using certificates or only specific authentication mechanism, it uses TCP ports `5985` (`HTTP`) and `5986` (`HTTPS`).

We can use CrackMapExec to crack usernames and passwords, and [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) to communicate with the winrm service.

### RDP

We can use Hydra to crack the password.

### SMB

Using Hydra to crack a password we might get an error of invalid reply, we can try to update Hydra or to use another tool like Metasploit, or CrackMapExec.

We can communicate with the SMB server we can use a tool like [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html). This tool will allow us to view the contents of the shares, upload, or download files if our privileges allow it.