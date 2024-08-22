# File Encryption on Linux

## OpenSSL

Encrypting /etc/passwd with openssl:
```shell-session
Wildland4958@htb[/htb]$ openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc

enter aes-256-cbc encryption password:                                                         
Verifying - enter aes-256-cbc encryption password:       
```

Decrypt passwd.enc with openssl:
```shell-session
Wildland4958@htb[/htb]$ openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd                    

enter aes-256-cbc decryption password:
```