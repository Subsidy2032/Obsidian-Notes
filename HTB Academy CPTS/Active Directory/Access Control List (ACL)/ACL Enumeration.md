## Enumerating ACLs with PowerView

We can use PowerView to enumerate ACLs, but digging through all the results will be extremely time consuming and likely inaccurate.

### Using Find-InterestingDomainAcl
```powershell-session
PS C:\htb> Find-InterestingDomainAcl
```

To be more effective we can perform targeted enumeration starting with a user that we have control over. We first need to get the SID of the target to search effectively.

### Getting the SID
```powershell-session
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> $sid = Convert-NameToSid <username>
```

We can then use the `Get-DomainObjectACL` function to perform our targeted search. Below we find all domain objects that our user has right over, the `SecurityIdentifier` property tells us who has the given right over an object. If we don't use `ResolveGUIDs` we will get results where the `ExtendedRight` does not give us a clear picture of what ACE entry the user have over the object. This is because the `ObjectAceType` property is returning a GUID value that is not human readable.

### Using Get-DomainObjectACL
```powershell-session
PS C:\htb> Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```

We could Google the GUID value and find what rights the user have. Alternatively, we could do a reverse search using PowerShell to map the right name back to the GUID value.

### Performing a Reverse Search & Mapping to a GUID Value
```powershell-session
PS C:\htb> $guid= "00299570-246d-11d0-a768-00aa006e0529"
PS C:\htb> Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl
```

PowerView has the `ResolveGUIDs` flag, which does this very thing for us.

### Use the -ResolveGUIDs Flag
```powershell-session
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 
```

Now we will look at how to do this with [Get-Acl](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl?view=powershell-7.2) and [Get-ADUser](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-aduser?view=windowsserver2022-ps) which is good in case we can't use PowerView.

### Using Get-Acl and Get-ADUser to Do the Same

The next command will take a long time to run.

#### Getting a List of Domain Users
```powershell-session
PS C:\htb> Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
```

Now we will need to loop over the file, and use the `Get-Acl` cmdlet to retrieve ACL information for each domain user by feeding each line of the file to the `Get-ADUser` cmdlet. We then select just the `Access property`, which will give us information about access rights. Finally we set the `IdentityReference` property to the user we are looking to see what rights they have.

#### A Useful foreach Loop
```powershell-session
PS C:\htb> foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}
```

With this data we can follow the same methods above to convert the GUID to a human readable format.

Now we can continue our enumeration with the objects we have control over.

### Further Enumeration of Rights Using damundsen
```powershell-session
PS C:\htb> $sid2 = Convert-NameToSid damundsen
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose
```

If we have generic write over a group, even if low privileged we can check if it's nested to a more interesting group, which we inherit the rights from.

### Investigating a Group with Get-DomainGroup
```powershell-session
PS C:\htb> Get-DomainGroup -Identity "Help Desk Level 1" | select memberof
```

We can now use `Get-DomainObjectACL` again to check for what the groups we found have rights to do.

For example with `GenericAll` we can:

- Modify group membership
- Force change a password
- Perform a targeted Kerberoasting attack and attempt to crack the user's password if it is weak

### Investigating a Group
```powershell-session
PS C:\htb> $itgroupsid = Convert-NameToSid "Information Technology"
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose
```

We can repeat this process for other objects we find.

## Enumerating ACLs Using BloodHound

It's all easier to do using BloodHound. We can set the user we want as the starting node, select the `Node Info` tab and scroll down to `Outbound Control Rights`. This option will show us objects we have control over directly, via group membership, and the number of objects that our user can lead to us controlling via ACL attack paths under `Transitive Object Control`. If we click on the `1` next to `First Degree Object Control`, we see the first set of rights.

### Viewing Node Info Through BloodHound
![[wley_damundsen.webp]]

If we right-click on the line between the two objects, a menu will pop up. If we select `Help`, we will be presented with help around abusing this ACE, including:

- More info on the specific right, tools, and commands that can be used to pull off this attack
- Operational Security (Opsec) considerations
- External references.

### Investigating ForceChangePassword Further
![[help_edge.webp]]

If we click on the `16` next to `Transitive Object Control`, we will see the entire path that we painstakingly enumerated above. From here, we could leverage the help menus for each edge to find ways to best pull off each attack.

### Viewing Potential Attack Paths Through BloodHound
![[wley_path.webp]]

Finally, we can use the pre-built queries in BloodHound to confirm that the user has DCSync rights.

### Viewing Pre-Build Queries Through BloodHound
![[adunn_dcsync.webp]]
