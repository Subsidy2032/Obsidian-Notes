Starting with an Nmap scan to discover all open ports.
```shell-session
# nmap -T4 -p- 10.10.11.29 -oN nmap_all_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-18 07:34 IDT
Warning: 10.10.11.29 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.11.29
Host is up (0.15s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
3000/tcp  open     ppp
24988/tcp filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 987.61 seconds
```

Let's now run a more detailed scan for the open ports.
```shell-session
# nmap -sV -sC -p22,80,3000 10.10.11.29 -oN nmap_open_ports                
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-18 07:55 IDT
Nmap scan report for lantern.htb (10.10.11.29)
Host is up (0.15s latency).

PORT      STATE  SERVICE VERSION
22/tcp    open   ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 80:c9:47:d5:89:f8:50:83:02:5e:fe:53:30:ac:2d:0e (ECDSA)
|_  256 d4:22:cf:fe:b1:00:cb:eb:6d:dc:b2:b4:64:6b:9d:89 (ED25519)
80/tcp    open   http    Skipper Proxy
|_http-title: Lantern
|_http-server-header: Skipper Proxy
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 Not Found
|     Content-Length: 207
|     Content-Type: text/html; charset=utf-8
|     Date: Sun, 18 Aug 2024 04:55:55 GMT
|     Server: Skipper Proxy
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GenericLines, Help, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Length: 225
|     Content-Type: text/html; charset=utf-8
|     Date: Sun, 18 Aug 2024 04:55:49 GMT
|     Location: http://lantern.htb/
|     Server: Skipper Proxy
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://lantern.htb/">http://lantern.htb/</a>. If not, click the link.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, HEAD, OPTIONS
|     Content-Length: 0
|     Content-Type: text/html; charset=utf-8
|     Date: Sun, 18 Aug 2024 04:55:50 GMT
|_    Server: Skipper Proxy
3000/tcp  open   ppp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 500 Internal Server Error
|     Connection: close
|     Content-Type: text/plain; charset=utf-8
|     Date: Sun, 18 Aug 2024 04:55:54 GMT
|     Server: Kestrel
|     System.UriFormatException: Invalid URI: The hostname could not be parsed.
|     System.Uri.CreateThis(String uri, Boolean dontEscape, UriKind uriKind, UriCreationOptions& creationOptions)
|     System.Uri..ctor(String uriString, UriKind uriKind)
|     Microsoft.AspNetCore.Components.NavigationManager.set_BaseUri(String value)
|     Microsoft.AspNetCore.Components.NavigationManager.Initialize(String baseUri, String uri)
|     Microsoft.AspNetCore.Components.Server.Circuits.RemoteNavigationManager.Initialize(String baseUri, String uri)
|     Microsoft.AspNetCore.Mvc.ViewFeatures.StaticComponentRenderer.<InitializeStandardComponentServicesAsync>g__InitializeCore|5_0(HttpContext httpContext)
|     Microsoft.AspNetCore.Mvc.ViewFeatures.StaticC
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Content-Length: 0
|     Connection: close
|     Date: Sun, 18 Aug 2024 04:56:00 GMT
|     Server: Kestrel
|   Help: 
|     HTTP/1.1 400 Bad Request
|     Content-Length: 0
|     Connection: close
|     Date: Sun, 18 Aug 2024 04:55:54 GMT
|     Server: Kestrel
|   RTSPRequest: 
|     HTTP/1.1 505 HTTP Version Not Supported
|     Content-Length: 0
|     Connection: close
|     Date: Sun, 18 Aug 2024 04:56:00 GMT
|     Server: Kestrel
|   SSLSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Length: 0
|     Connection: close
|     Date: Sun, 18 Aug 2024 04:56:16 GMT
|_    Server: Kestrel
```

Going to the vacancies page, we can submit details and upload a resume.
![[Pasted image 20240818074327.png]]

Going to port 3000, we see a login page.
![[Pasted image 20240818090758.png]]

Upon trying to authenticate, no GET or POST requests are sent. Looks like the authentication process is entirely on the client side.
![[Pasted image 20240818092030.png]]

