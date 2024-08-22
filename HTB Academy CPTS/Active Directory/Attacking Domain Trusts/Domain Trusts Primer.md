## Domain Trusts Overview

A trust is used to establish forest-forest or domain-domain (intra-domain) authentication, which allows users to access resources in (or perform administrative tasks) another domain. A trusts creates a link between the authentication systems of two domains and may allow either one-way or two-way communication. An organization can create various types of trusts:

- `Parent-child`: Two or more domains within the same forest. The child domain has a two-way transitive trust with the parent domain, meaning that users in the child domain `corp.inlanefreight.local` could authenticate into the parent domain `inlanefreight.local`, and vice-versa.
- `Cross-link`: A trust between child domains to speed up authentication.
- `External`: A non-transitive trust between two separate domains in separate forests which are not already joined by a forest trust. This type of trust utilizes [SID filtering](https://www.serverbrain.org/active-directory-2008/sid-history-and-sid-filtering.html) or filters out authentication requests (by SID) not from the trusted domain.
- `Tree-root`: A two-way transitive trust between a forest root domain and a new tree root domain. They are created by design when you set up a new tree root domain within a forest.
- `Forest`: A transitive trust between two forest root domains.
- [ESAE](https://docs.microsoft.com/en-us/security/compass/esae-retirement): A bastion forest used to manage Active Directory.

When establishing trust, certain elements can be modified depending on the business case.

Trust can be transitive or non-transitive.

- A `transitive` trust means that trust is extended to objects that the child domain trusts. For example, let's say we have three domains. In a transitive relationship, if `Domain A` has a trust with `Domain B`, and `Domain B` has a `transitive` trust with `Domain C`, then `Domain A` will automatically trust `Domain C`.
- In a `non-transitive trust`, the child domain itself is the only one trusted.

![[transitive-trusts.png]]
Adapted from [here](https://zindagitech.com/wp-content/uploads/2021/09/Picture2-Deepak-4.png.webp)

### Trust Table Side By Side
|Transitive|Non-Transitive|
|---|---|
|Shared, 1 to many|Direct trust|
|The trust is shared with anyone in the forest|Not extended to next level child domains|
|Forest, tree-root, parent-child, and cross-link trusts are transitive|Typical for external or custom trust setups|

An easy comparison to make can be package delivery to your house. For a `transitive` trust, you have extended the permission to anyone in your household (forest) to accept a package on your behalf. For a `non-transitive` trust, you have given strict orders with the package that no one other than the delivery service and you can handle the package, and only you can sign for it.

Trusts can be set up in two directions: one-way or two way (bidirectional).

- `One-way trust`: Users in a `trusted` domain can access resources in a trusting domain, not vice-versa.
- `Bidirectional trust`: Users from both trusting domains can access resources in the other domain.

Domain trusts are often set up incorrectly and can provide us with critical unintended attack paths. Also, trusts set up for ease might not be reviewed for security. A Merger & Acquisition (M&A) between two companies can result in bidirectional trust, which can unknowingly introduce risk into the acquiring company's environment if the security posture of the acquired company is unknown and untested. The other company can potentially be a softer target to attack, to eventually get to the acquiring company. It is not uncommon to be able to perform an attack such as Kerberoasting against a domain outside the principal domain and obtain a user that has administrative access within the principal domain. This type of "end-around" attack could be prevented if security is considered as paramount before establishing any kind of domain trust. As we examine trust relationships, keep these thoughts in mind for reporting. Often, we will find that the larger organization is unaware that a trust relationship exists with one or more domains.

Below is a graphical representation of the various trust types.

![[trusts-diagram.png]]

## Enumerating Trust Relationships

We can use the [Get-ADTrust](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adtrust?view=windowsserver2022-ps) cmdlet to enumerate domain trust relationships. This is especially helpful if we are limited to just using built-in tools.

### Using Get-ADTrust
```powershell-session
PS C:\htb> Import-Module activedirectory
PS C:\htb> Get-ADTrust -Filter *
```

Both PowerView and BloodHound can also be utilized to enumerate trust relationships, the type of trusts established, and the authentication flow. After importing PowerView we can use the [Get-DomainTrust](https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainTrust/) function to enumerate what trusts exist, if any.

### Checking for Existing Trusts using Get-DomainTrust
```powershell-session
PS C:\htb> Get-DomainTrust 
```

PowerView can be used to perform a domain trust mapping and provide information such as the type of trust and the direction of trust.

### Using Get-DomainTrustMapping
```powershell-session
PS C:\htb> Get-DomainTrustMapping
```

From here, we could begin performing enumeration across the trusts. For example, we could look at all users in the child domain:

### Checking Users in the Child Domain Using Get-DomainUser
```powershell-session
PS C:\htb> Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName
```

The `netdom query` sub-command of the `netdom` command-line tool in Windows can retrieve information about the domain, including a list of workstations, servers, and domain trusts.

### Using netdom to Query Domain Trust
```cmd-session
C:\htb> netdom query /domain:inlanefreight.local trust
```

### Using netdom to Query Domain Controllers
```cmd-session
C:\htb> netdom query /domain:inlanefreight.local dc
```

### Using netdom to Query Workstations and Servers
```cmd-session
C:\htb> netdom query /domain:inlanefreight.local workstation
```

We can also use BloodHound to visualize these trust relationships by using the `Map Domain Trusts` pre-built query. Here we can easily see that two bidirectional trusts exist.

### Visualize Trust Relationships in BloodHound
![[BH_trusts.webp]]

