## Detailed User Enumeration

There are several ways to gather a list of valid usernames:

- By leveraging an SMB NULL session to retrieve a complete list of domain users from the domain controller
- Utilizing an LDAP anonymous bind to query LDAP anonymously and pull down the domain user list
- Using a tool such as `Kerbrute` to validate users utilizing a word list from a source such as the [statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames) GitHub repo, or gathered by using a tool such as [linkedin2username](https://github.com/initstring/linkedin2username) to create a list of potentially valid users
- Using a set of credentials from a Linux or Windows attack system either provided by our client or obtained through another means such as LLMNR/NBT-NS response poisoning using `Responder` or even a successful password spray using a smaller wordlist

Knowing the password policy can help us with knowing which passwords to use, and how to avoid locking out accounts.

Again, if we do not know the password policy, we can always ask our client, and, if they won't provide it, we can either try one very targeted password spraying attempt as a "hail mary" if all other options for a foothold have been exhausted. We could also try one spray every few hours in an attempt to not lock out any accounts. Regardless of the method we choose, and if we have the password policy or not, we must always keep a log of our activities, including, but not limited to:

- The accounts targeted
- Domain Controller used in the attack
- Time of the spray
- Date of the spray
- Password(s) attempted

This will help us ensure that we do not duplicate efforts. If an account lockout occurs or our client notices suspicious logon attempts, we can supply them with our notes to crosscheck against their logging systems and ensure nothing nefarious was going on in the network.

## SMB NULL Session to Pull User List

if we are on internal machine with no credentials, we can look for SMB Null session or LDAP anonymous binds on domain controllers. Either of those will give us an accurate list of all users within the AD and the password policy. If you have credentials for a domain user or SYSTEM access on a Windows host, then you can easily query AD for this information.

It is possible with the SYSTEM account because it can impersonate the computer. A computer object is treated as a domain user account (with some differences, such as authenticating across forest trusts). Without a valid domain account, and SMB NULL sessions and LDAP anonymous binds not possible, we can use external resources such as email harvesting and LinkedIn to create user list (not as complete).

Some tools that can leverage SMB NULL sessions and LDAP anonymous binds include [enum4linux](https://github.com/portcullislabs/enum4linux), [rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html), and [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec), among others. With each tool we will have to do a bit of filtering to clean up the output and obtain a list of only usernames, one on each line.

### Using enum4linux
```shell-session
$ enum4linux -U <ip address>  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```

### Using rpcclient
```shell-session
$ rpcclient -U "" -N <ip address>

rpcclient $> enumdomusers
```

CrackMapExec will also show the `badpwdcount` (invalid login attempts), so we can remove any accounts from our list that are close to the lockout threshold. It also shows the `baddpwdtime`, which is the date and time of the last bad password attempt, so we can see how close an account is to having its `badpwdcount` reset. In an environment with multiple domain controllers, this value is maintained separately on each one. To get an accurate total of the account's bad password attempts, we would have to either query each DC and use the sum of values or query the DC with the PDC Emulator FSMO role.

### Using CrackMapExec --users Flag
```shell-session
$ crackmapexec smb <ip address> --users
```

## Gathering Users with LDAP Anonymous

We can use various tools to gather users when we find LDAP anonymous bind. Some examples include [windapsearch](https://github.com/ropnop/windapsearch) and [ldapsearch](https://linux.die.net/man/1/ldapsearch). If we choose to use `ldapsearch` we will need to specify a valid LDAP search filter. We can learn more about these search filters in the [Active Directory LDAP](https://academy.hackthebox.com/course/preview/active-directory-ldap) module.

### Using ldapsearch
```shell-session
$ ldapsearch -h <ip address> -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
```

Tools such as `windapsearch` make this easier (though we should still understand how to create our own LDAP search filters). Here we can specify anonymous access by providing a blank username with the `-u` flag and the `-U` flag to tell the tool to retrieve just users.

### Using windapsearch
```shell-session
]$ ./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
```

## Enumerating Users with Kerbrute

From a position in the internal network with no access at all we can use kerbrute to enumerate valid AD accounts and for password spraying.

This tool uses [Kerberos Pre-Authentication](https://ldapwiki.com/wiki/Wiki.jsp?page=Kerberos%20Pre-Authentication), which is much faster and potentially stealthier way to perform password spraying. This method doesn't generate Windows event ID [4625: An account failed to log on](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625), or a logon failure which is often monitored for. The tool sends TGT requests to the DC without Kerberos Pre-Authentication to perform username enumeration. If the KDC responds with the error `PRINCIPAL UNKNOWN` the username is invalid. Whenever the KDC prompts for Kerberos Pre-Authentication, this signals that the username exists. This method will not generate failures or logout an account. However in the password spraying stage failed Kerberos Pre-Authentication attempts will count towards an account's failed login attempts.

### Kerbrute User Enumeration
```shell-session
$  kerbrute userenum -d <domain> --dc <ip address> /opt/jsmith.txt 
```

Using Kerbrute for username enumeration will generate event ID [4768: A Kerberos authentication ticket (TGT) was requested](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768). This will only be triggered if [Kerberos event logging](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-kerberos-event-logging) is enabled via Group Policy. If we are successful with this attack, looking for an influx of this event ID in the SIEM tools is an excellent recommendation for the defenders to add to our report.

If we are unable to create a valid username list using any of the methods highlighted above, we could turn back to external information gathering and search for company email addresses or use a tool such as [linkedin2username](https://github.com/initstring/linkedin2username) to mash up possible usernames from a company's LinkedIn page.

## Credentialed Enumeration to Build our User List

With credentials we can use any of the previous tools, A quick and easy way is using CrackMapExec.

### Using CrackMapExec with Valid Credentials
```shell-session
$ sudo crackmapexec smb <ip address> -u <username> -p <password> --users
```