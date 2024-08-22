## Hunting for Encoded Files

We can find a useful list of encrypted/encoded file extensions in [FileInfo](https://fileinfo.com/filetypes/encoded).

### Hunting for the Most Common File Extensions
```shell-session
$ for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```

### Hunting for SSH Keys
```shell-session
$ grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"
```

If we see encrypted header in the SSH key, in most cases we would not be able to use it without further action, because they are protected with a passphrase. But many are often careless in the password selection and the complexity, and many do not know that even lightweight [AES-128-CBC](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) can be cracked.

### Cracking with John

#### John Hashing Scripts
```shell-session
$ locate *2john*

/usr/bin/bitlocker2john
/usr/bin/dmg2john
/usr/bin/gpg2john
/usr/bin/hccap2john
/usr/bin/keepass2john
/usr/bin/putty2john
/usr/bin/racf2john
/usr/bin/rar2john
/usr/bin/uaf2john
/usr/bin/vncpcap2john
/usr/bin/wlanhcx2john
/usr/bin/wpapcap2john
/usr/bin/zip2john
/usr/share/john/1password2john.py
/usr/share/john/7z2john.pl
/usr/share/john/DPAPImk2john.py
/usr/share/john/adxcsouf2john.py
/usr/share/john/aem2john.py
/usr/share/john/aix2john.pl
/usr/share/john/aix2john.py
/usr/share/john/andotp2john.py
/usr/share/john/androidbackup2john.py
...SNIP...
```

```shell-session
$ ssh2john.py SSH.private > ssh.hash
```
```shell-session
$ john --wordlist=rockyou.txt ssh.hash
```
```shell-session
$ john ssh.hash --show
```

### Cracking Documents

#### Cracking Microsoft Office Documents
```shell-session
$ office2john.py Protected.docx > protected-docx.hash
```

#### Cracking PDFs
```shell-session
$ pdf2john.py PDF.pdf > pdf.hash
```

## Protected Archives

Extensive list of archive types can be found on [FileInfo.com](https://fileinfo.com/filetypes/compressed), some of the most common ones are:

|   |   |   |   |
|---|---|---|---|
|`tar`|`gz`|`rar`|`zip`|
|`vmdb/vmx`|`cpt`|`truecrypt`|`bitlocker`|
|`kdbx`|`luks`|`deb`|`7z`|
|`pkg`|`rpm`|`war`|`gzip`|

### Download All File Extensions
```shell-session
$ curl -s https://fileinfo.com/filetypes/compressed | html2text | awk '{print tolower($1)}' | grep "\." | tee -a compressed_ext.txt
```

Not all of the archives support password protection, some other tools may be used to protect the archive. For example, with `tar`, the tool `openssl` or `gpg` is used to encrypt the archives.

### Cracking Archives

#### Cracking ZIP
```shell-session
$ zip2john ZIP.zip > zip.hash
```

### Cracking OpenSSL Encrypted Archives

It is not always directly apparent if a archive uses file protection, as an example `openssl` can be used to encrypt the `gzip` format, with the tool `file` we can obtain information about the file format.

#### Listing the Files
```shell-session
$ ls

GZIP.gzip  rockyou.txt
```

#### Using File
```shell-session
$ file GZIP.gzip 

GZIP.gzip: openssl enc'd data with salted password
```

When trying to decrypt OpenSSL encrypted files and archives, we can get many false positives or even fail, the safest choice for success is the `openssl` tool in a `for-loop` that tries to extract the files from the archive directly if the password is guessed correctly.

The following one-liner will show many errors related to the GZIP format, which we can ignore. If we have used the correct password list, as in this example, we will see that we have successfully extracted another file from the archive.

#### Using a for-loop to Display Extracted Contents
```shell-session
$ for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done
```

#### Listing the Contents of the Cracked Archive
```shell-session
$ ls

customers.csv  GZIP.gzip  rockyou.txt
```

### Cracking BitLocker Encrypted Files

[BitLocker](https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-device-encryption-overview-windows-10) is an encryption program for entire partitions and external drives. It has been available since Windows Vista and uses the `AES` encryption algorithm with 128-bit or 256-bit length. If the password or pin is forgotten we can use the recovery key to decrypt the partition or drive. The recovery key is a 48-digit string of numbers generated during BitLocker setup that also can be brute-forced.

We can use a script called `bitlocker2john` to extract the hash. [Four different hashes](https://openwall.info/wiki/john/OpenCL-BitLocker) will be extracted, which can be used with different Hashcat hash modes, for example the first one refers to the BitLocker password.

#### Using bitlocker2john
```shell-session
$ bitlocker2john -i Backup.vhd > backup.hashes
$ grep "bitlocker\$0" backup.hashes > backup.hash
```

#### Using Hashcat to Crack backup.hash
```shell-session
$ hashcat -m 22100 backup.hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt -o backup.cracked
```

The easiest way to view the drive is to transfer him to a Windows machine, mount it and then open it there.