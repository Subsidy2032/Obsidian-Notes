## Upgrading to PTY shell

#### Python
```shell-session
Wildland4958@htb[/htb]$ python -c 'import pty; pty.spawn("/bin/bash")'
```

#### Script
```shell-session
$ script /dev/null -c bash
```

#### /bin/sh -i
```shell-session
/bin/sh -i
```

#### Perl
```shell-session
perl —e 'exec "/bin/sh";'
```

Should be run from a script:
```shell-session
perl: exec "/bin/sh";
```

#### Ruby

Should be run from a script:
```shell-session
ruby: exec "/bin/sh"
```

#### Lua

We can use the `os.execute` method to execute the shell interpreter.

Should be run from a script:
```shell-session
lua: os.execute('/bin/sh')
```

#### AWK

[AWK](https://man7.org/linux/man-pages/man1/awk.1p.html) is a C-like pattern scanning and processing language present on most UNIX/Linux-based systems, widely used by developers and sysadmins to generate reports.

```shell-session
awk 'BEGIN {system("/bin/sh")}'
```

#### Find
```shell-session
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
```

#### Using Exec to Launch a Shell Directly
```shell-session
find . -exec /bin/sh \; -quit
```

#### Vim
##### Vim To Shell
```shell-session
vim -c ':!/bin/sh'
```

##### Vim Escape
```shell-session
vim
:set shell=/bin/sh
:shell
```

## Upgrading to fully interactive shell
```shell-session
www-data@remotehost$ ^Z // Background the shell

Wildland4958@htb[/htb]$ echo $TERM

xterm-256color

Wildland4958@htb[/htb]$ stty size

67 318

Wildland4958@htb[/htb]$ Wildland4958@htb[/htb]$ stty raw -echo;fg

[Enter]
[Enter]
www-data@remotehost$ export TERM=xterm-256color

www-data@remotehost$ stty rows 21 columns 94
```

![[Pasted image 20240616122531.png]]

