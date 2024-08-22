#Linux 

| Command | Description | Syntax |
| -------- | -------- | -------- |
| man | Manual pages for most linux tools and commands | `man command` |
| dig | Manually query recursive dns servers for domains | `dig <domain> @dns-server-ip` |
| file | Determine the type of a file | `file <file>` |
| wget | Download web files | `wget <web address>` |
| file | Determine the type of a file | `file <file>` |
| scp | Transfer files between 2 systems using ssh | `scp fileToTransfer username@ipAddress:path` (moving the existing file name to the end in case of transfering from a remote computer) |
| ps | See running processes | `ps [aux]` (aux is for only process that are running by the user) |
| top | Real time statistics about processes running | `top` |
| kill | Kill a process | `kill <PID>` |
| systemctl | Interact with processes | `systemctl start/stop/enable/disable [service]` |