Crack services password: `hydra -t [threads] -l [user name] -P /usr/share/wordlists/rockyou.txt -vV [ip address] [service]`

### John The Ripper

Basic john cracking: `john --wordlist=[path to wordlist] [path to file]`

Single crack mode(for when knowing part of the password): `john --single --format=[format] [path to file]`

#### Tools to convert files to format you can crack

- unshadow: `unshadow [path to passwd] [path to shadow]`
- zip2john: `zip2john [options] [zip file] > [output file]`
- rar2john: `rar2john [rar file] > [output file]`
- ssh2john: `ssh2john [id_rsa private key file] > [output file]`