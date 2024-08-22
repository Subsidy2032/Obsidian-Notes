## Jobs

Terminating a session using `[CTRL] + [C]` will leave the port the module is running under still in use, so if we want to use the port in a different module, we will need to use the `jobs` command to see the currently active tasks running in the background and terminate the old ones.

Other types of tasks inside sessions can be converted to jobs to run in the background, even if the session dies or disappears.

### Viewing the Jobs Command Help Menu
```shell-session
msf6 exploit(multi/handler) > jobs -h
```

Using `exploit -j` instead of `exploit` or `run` will run the exploit as a job.

`job -l` - List running jobs

`kill [index no.]` - Kill a job

`jobs -k` - Kill all jobs

## Meterpreter

Meterpreter payload is an extensive payload which uses DLL injection to ensure stable and hard to detect connection, it can be configured to be consistent across reboots or system changes, it also resides completely in memory, making it hard to detect.

It can provide us with a lot of option in the post exploitation stage, like privilege escalation techniques, AV evasion techniques, vulnerability research, persistent access, pivot, etc.

For some interesting reading, check out this [post](https://blog.rapid7.com/2015/03/25/stageless-meterpreter-payloads/) on Meterpreter stageless payloads and this [post](https://www.blackhillsinfosec.com/modifying-metasploit-x64-template-for-av-evasion) on modifying Metasploit templates for evasion.

### Running Meterpreter

When the exploit is completed, the following events occur:

- The target executes the initial stager. This is usually a bind, reverse, findtag, passivex, etc.
    
- The stager loads the DLL prefixed with Reflective. The Reflective stub handles the loading/injection of the DLL.
    
- The Meterpreter core initializes, establishes an AES-encrypted link over the socket, and sends a GET. Metasploit receives this GET and configures the client.

`local_exploit_suggester` - A module for suggesting exploit for a target with open session.

Dump hashes:
```shell-session
meterpreter > hashdump
```
```shell-session
meterpreter > lsa_dump_sam
```

LSA secrets dump:
```shell-session
meterpreter > lsa_dump_secrets
```