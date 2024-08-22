### /etc/passwd

Generate a new hash to add to the passwd file: `openssl passwd -1 -salt [salt] [password]`
Without salt: `openssl passwd [password]`
### /etc/shadow

Can try to crack a password hash using John The Ripper

Generating a new hash to replace with the current root's hash: `mkpasswd -m sha-512 newpasswordhere`


