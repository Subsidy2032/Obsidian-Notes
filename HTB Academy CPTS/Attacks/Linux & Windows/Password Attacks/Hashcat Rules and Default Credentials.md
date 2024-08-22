## Hashcat Rules

### Functions in a Rule File
|**Function**|**Description**|
|---|---|
|`:`|Do nothing.|
|`l`|Lowercase all letters.|
|`u`|Uppercase all letters.|
|`c`|Capitalize the first letter and lowercase others.|
|`sXY`|Replace all instances of X with Y.|
|`$!`|Add the exclamation character at the end.|

### Example Rule File
```shell-session
$ cat custom.rule

:
c
so0
c so0
sa@
c sa@
c sa@ so0
$!
$! c
$! so0
$! sa@
$! c so0
$! c sa@
$! so0 sa@
$! c so0 sa@
```

### Generating a Rule-Based Wordlist
```shell-session
$ hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```

`best64.rule` is one of the most used rule files.

[CeWL](https://github.com/digininja/CeWL) is another good option to scan potential words from company's website.

## Default Credentials

[DefaultCreds-Cheat-Sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet): Database with a running list of default credentials.

Small Excerpt from the table:

| **Product/Vendor** | **Username** | **Password**                 |
| ------------------ | ------------ | ---------------------------- |
| Zyxel (ssh)        | zyfwp        | PrOw!aN_fXp                  |
| APC UPS (web)      | apc          | apc                          |
| Weblogic (web)     | system       | manager                      |
| Weblogic (web)     | system       | manager                      |
| Weblogic (web)     | weblogic     | weblogic1                    |
| Weblogic (web)     | WEBLOGIC     | WEBLOGIC                     |
| Weblogic (web)     | PUBLIC       | PUBLIC                       |
| Weblogic (web)     | EXAMPLES     | EXAMPLES                     |
| Weblogic (web)     | weblogic     | weblogic                     |
| Weblogic (web)     | system       | password                     |
| Weblogic (web)     | weblogic     | welcome(1)                   |
| Weblogic (web)     | system       | welcome(1)                   |
| Weblogic (web)     | operator     | weblogic                     |
| Weblogic (web)     | operator     | password                     |
| Weblogic (web)     | system       | Passw0rd                     |
| Weblogic (web)     | monitor      | password                     |
| Kanboard (web)     | admin        | admin                        |
| Vectr (web)        | admin        | 11_ThisIsTheFirstPassword_11 |
| Caldera (web)      | admin        | admin                        |
| Dlink (web)        | admin        | admin                        |
| Dlink (web)        | 1234         | 1234                         |
| Dlink (web)        | root         | 12345                        |
| Dlink (web)        | root         | root                         |
| JioFiber           | admin        | jiocentrum                   |
| GigaFiber          | admin        | jiocentrum                   |
| Kali linux (OS)    | kali         | kali                         |
| F5                 | admin        | admin                        |
| F5                 | root         | default                      |
| F5                 | support      |                              |
| ...                | ...          | ...                          |

Attacking service with default or obtained credentials is called [Credential Stuffing](https://owasp.org/www-community/attacks/Credential_stuffing)

### Credential Stuffing - Hydra Syntax
```shell-session
$ hydra -C <user_pass.list> <protocol>://<IP>
```