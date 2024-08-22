## Active Directory PowerShell Module

The [ActiveDirectory PowerShell module](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps) is a group of cmdlets for administering an AD environment from the command line. It consists of 147 cmdlets at the time of writing.

We have to make sure it's imported first. the [Get-Module](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/get-module?view=powershell-7.2) cmdlet, which is part of the [Microsoft.PowerShell.Core module](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/?view=powershell-7.2), will list all available modules, their version, and potential commands for use. This is a great way to see if anything like Git or custom administrator scripts are installed. If the module is not loaded, run `Import-Module ActiveDirectory` to load it for use.

### Discover Modules
```powershell-session
PS C:\htb> Get-Module
```

### Load ActiveDirectory Module
```powershell-session
PS C:\htb> Import-Module ActiveDirectory
```

### Get Basic Domain Info
```powershell-session
PS C:\htb> Get-ADDomain
```

This will print out helpful information like the domain SID, domain functional level, any child domains, and more. Next we will use the [Get-ADUser](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-aduser?view=windowsserver2022-ps) cmdlet. Looking for accounts with the `ServicePrincipalName` property populated.

### Get-ADUser
```powershell-session
PS C:\htb> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

### Checking for Trust Relationships
```powershell-session
PS C:\htb> Get-ADTrust -Filter *
```

### Group Enumeration
```powershell-session
PS C:\htb> Get-ADGroup -Filter * | select name
```

### Detailed Group Info
```powershell-session
PS C:\htb> Get-ADGroup -Identity "<group name>"
```

Now that we know more about the group, let's get a member listing using the [Get-ADGroupMember](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adgroupmember?view=windowsserver2022-ps) cmdlet.

### Group Membership
```powershell-session
PS C:\htb> Get-ADGroupMember -Identity "<group name>"
```

## PowerView

[PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon) is a tool written in PowerShell to help us gain situational awareness within an AD environment. It provides a way to identify where users are logged in on a network, enumerate domain information such as users, computers, groups, ACLs, trusts, hunt for file shares and passwords, perform Kerberoasting, and more. It requires more manual work then Bloodhound, but when used right can help identify subtle misconfigurations.

some of the most useful functions PowerView offers:

|**Command**|**Description**|
|---|---|
|`Export-PowerViewCSV`|Append results to a CSV file|
|`ConvertTo-SID`|Convert a User or group name to its SID value|
|`Get-DomainSPNTicket`|Requests the Kerberos ticket for a specified Service Principal Name (SPN) account|
|**Domain/LDAP Functions:**||
|`Get-Domain`|Will return the AD object for the current (or specified) domain|
|`Get-DomainController`|Return a list of the Domain Controllers for the specified domain|
|`Get-DomainUser`|Will return all users or specific user objects in AD|
|`Get-DomainComputer`|Will return all computers or specific computer objects in AD|
|`Get-DomainGroup`|Will return all groups or specific group objects in AD|
|`Get-DomainOU`|Search for all or specific OU objects in AD|
|`Find-InterestingDomainAcl`|Finds object ACLs in the domain with modification rights set to non-built in objects|
|`Get-DomainGroupMember`|Will return the members of a specific domain group|
|`Get-DomainFileServer`|Returns a list of servers likely functioning as file servers|
|`Get-DomainDFSShare`|Returns a list of all distributed file systems for the current (or specified) domain|
|**GPO Functions:**||
|`Get-DomainGPO`|Will return all GPOs or specific GPO objects in AD|
|`Get-DomainPolicy`|Returns the default domain policy or the domain controller policy for the current domain|
|**Computer Enumeration Functions:**||
|`Get-NetLocalGroup`|Enumerates local groups on the local or a remote machine|
|`Get-NetLocalGroupMember`|Enumerates members of a specific local group|
|`Get-NetShare`|Returns open shares on the local (or a remote) machine|
|`Get-NetSession`|Will return session information for the local (or a remote) machine|
|`Test-AdminAccess`|Tests if the current user has administrative access to the local (or a remote) machine|
|**Threaded 'Meta'-Functions:**||
|`Find-DomainUserLocation`|Finds machines where specific users are logged in|
|`Find-DomainShare`|Finds reachable shares on domain machines|
|`Find-InterestingDomainShareFile`|Searches for files matching specific criteria on readable shares in the domain|
|`Find-LocalAdminAccess`|Find machines on the local domain where the current user has local administrator access|
|**Domain Trust Functions:**||
|`Get-DomainTrust`|Returns domain trusts for the current domain or a specified domain|
|`Get-ForestTrust`|Returns all forest trusts for the current forest or a specified forest|
|`Get-DomainForeignUser`|Enumerates users who are in groups outside of the user's domain|
|`Get-DomainForeignGroupMember`|Enumerates groups with users outside of the group's domain and returns each foreign member|
|`Get-DomainTrustMapping`|Will enumerate all trusts for the current domain and any others seen.|

This table is not all-encompassing for what PowerView offers, but it includes many of the functions we will use repeatedly. For more on PowerView, check out the [Active Directory PowerView module](https://academy.hackthebox.com/course/preview/active-directory-powerview).

### Domain User Information
```powershell-session
PS C:\htb> Get-DomainUser -Identity <username> -Domain <domain> | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
```

With [Get-DomainGroupMember](https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainGroupMember/) we can use the `-Recurse` flag to list nested groups. For example below we will see users which have Domain Admins privileges from a nested group.

### Recursive Group Membership
```powershell-session
PS C:\htb>  Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```

### Trust Enumeration
```powershell-session
PS C:\htb> Get-DomainTrustMapping
```

### Testing for Local Admin Access
```powershell-session
PS C:\htb> Test-AdminAccess -ComputerName <computer name>
```

### Finding Users With SPN Set
```powershell-session
PS C:\htb> Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```

## SharpView

PowerView is part of the now deprecated PowerSploit offensive PowerShell toolkit. The tool as been receiving updates from BC-Security as part of their [Empire 4](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/data/module_source/situational_awareness/network/powerview.ps1) framework. Empire for is BC-Security's fork of the original Empire project and is actively maintained as of April 2022. The development version of PowerView is an excellent tool for AD recon, even though the original method is not maintained. The BC-Security version of [PowerView](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/data/module_source/situational_awareness/network/powerview.ps1) has some new functions such as `Get-NetGmsa`, used to hunt for [Group Managed Service Accounts](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview).

SharpView is a .NET port of PowerView, it supports many of the function of PowerView. We can type a method name with `-Help` to get an argument list.

```powershell-session
PS C:\htb> .\SharpView.exe Get-DomainUser -Help
```

Here we can use SharpView to enumerate information about a specific user.

```powershell-session
PS C:\htb> .\SharpView.exe Get-DomainUser -Identity <username>
```

## Shares

It's important to look for share access, which might disclose sensitive data. We can use PowerView to hunt for shares and then help us dig through them or use various manual commands to hunt for common strings such as files with `pass` in the name. This can be a tedious process, and we may miss things, especially in large environments. Now, let's take some time to explore the tool `Snaffler` and see how it can aid us in identifying these issues more accurately and efficiently.

## Snaffler

[Snaffler](https://github.com/SnaffCon/Snaffler) can help us acquire credentials or other sensitive data in AD environment. It works by obtaining a list of hosts within the domain and then enumerating them for shares and readable directories. It then iterates through any directories readable by our user and hunt for files that could serve to better our position within this assessment. Snaffler requires that it be run from a domain-joined host or in a domain-user context.

### Snaffler Execution
```bash
Snaffler.exe -s -d <domain> -o snaffler.log -v data
```

Typically `data` is best as it only displays results to the screen, so it's easier to begin looking through the tool runs. Snaffler can produce a considerable amount of data, so we should typically output to file and let it run and then come back to it later. It can also be helpful to provide Snaffler raw output to clients as supplemental data during a penetration test as it can help them zero in on high-value shares that should be locked down first.

We may find passwords, SSH keys, configuration files, or other data that can be used to further our access. Snaffler color codes the output for us and provides us with a rundown of the file types found in the shares.

## BloodHound

`Bloodhound` is an exceptional open-source tool that can identify attack paths within an AD environment by analyzing the relationships between objects.

First, we must authenticate as a domain user from a Windows attack host positioned within the network (but not joined to the domain) or transfer the tool to a domain-joined host.

### SharpHound in Action
```powershell-session
PS C:\htb>  .\SharpHound.exe --help
```

#### Run the SharpHound.exe Collector
```powershell-session
PS C:\htb> .\SharpHound.exe -c All --zipfilename ILFREIGHT
```

Now we can ingest the dataset into BloodHound GUI. Then click on `Upload Data`, select the zip file, and click `Open`. An `Upload Progress` window will pop up. Once all .json files show 100% complete, click the X at the top of that window.

We can start by typing `domain:` in the search bar on the top left and choosing the domain we want. We can then see info on the domain in the node info tab.

Now we can check out a few pre-built queries in the `Analysis` tab. The query `Find Computers with Unsupported Operating Systems` is great for finding outdated and unsupported operating systems running legacy software. If we come across these older hosts during an assessment, we should be careful before attacking them (or even check with our client) as they may be fragile and running a critical application or service. We can advise our client to segment these hosts off from the rest of the network as much as possible if they cannot remove them yet, but should also recommend that they start putting together a plan to decommission and replace them.

Sometimes we will see hosts that are no longer powered on but still appear as records in AD. We should always validate whether they are "live" or not before making recommendations in our reports. We may write up a high-risk finding for Legacy Operating Systems or a best practice recommendation for cleaning up old records in AD.

We might see users with local admin access, which might should have been temporarily, or isn't required. Other times we'll see excessive local admin rights handed out across the organization, such as multiple groups in the IT department with local admin over groups of servers or even the entire Domain Users group with local admin over one or more hosts. We can run the query `Find Computers where Domain Users are Local Admin` to quickly see if there are any hosts where all users have local admin rights. If this is the case, then any account we control can typically be used to access the host(s) in question, and we may be able to retrieve credentials from memory or find other sensitive data.

For a more in-depth study on BloodHound, check out the module [Active Directory Bloodhound](https://academy.hackthebox.com/course/preview/active-directory-bloodhound). It's also worth experimenting with [custom Cypher queries](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/) by pasting them into the `Raw Query` box at the bottom of the screen.

Keep in mind as we go through the engagement, we should be documenting every file that is transferred to and from hosts in the domain and where they were placed on disk. This is good practice if we have to deconflict our actions with the customer. Also, depending on the scope of the engagement, you want to ensure you cover your tracks and clean up anything you put in the environment at the conclusion of the engagement.

