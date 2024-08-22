## Laudanum

Laudanum is a repository of ready made files to get a reverse shell or command execution, it has injectable files for many different web application languages to include `asp`, `aspx`, `jsp`, `php`, and more, it is built into Parrot OS and Kali by default.

The Laudanum files can be found in the `/usr/share/laudanum` directory.

## Antak Webshell

### ASPX Explained

Active Server Page Extended (ASPX) is written for [Microsoft's ASP.NET Framework](https://docs.microsoft.com/en-us/aspnet/overview). On a web server running the ASP.NET Framework web form pages can be generated, it will be converted to html in the server side, we can take advantage of this by using ASPX-based web shell to control the underlying Windows OS.

### Antak Webshell

Antak web shell built in ASP.NET included within the [Nishang project](https://github.com/samratashok/nishang), an offensive PowerShell toolset for any portion of a pentest. Antak utilizes PowerShell to interact with the host, making it great for acquiring a web shell on a Windows server.

The Antak files can be found in the `/usr/share/nishang/Antak-WebShell` directory, it functions like a PowerShell console, but it will execute each command as a new process, it can also execute scripts in memory and encode commands you send.