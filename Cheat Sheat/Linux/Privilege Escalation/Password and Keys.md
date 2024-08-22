View the contents of all hidden history files in the user's home directory: `cat ~/.*history | less`

Check configuration files like ovpn file

### SSH Keys

1. Check the SSH directory for keys: `ls -l /.ssh`
2. Copy the contents to a file in your own machine
3. Change the permissions of the file: `chmod 6000 [key file]`
4. Connect to SSH using the key: `ssh -i [key file] [username]@[ip address]`