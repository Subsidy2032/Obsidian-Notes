The general goal of Windows privilege escalation is to further our access in given system to a member of the `Local Administrators` group or the `NT AUTHORITY\SYSTEM` [LocalSystem](https://docs.microsoft.com/en-us/windows/win32/services/localsystem-account) account. Sometimes another user on the system will be enough to reach our goal. Sometimes privilege escalation will be the ultimate goal, if we're hired for "gold image" or "workstation breakout" type assesement. Privilege escalation is often vital to continue through a network towards our ultimate objective, as well as for lateral movement.

That being said, we may need to escalate privileges for one of the following reasons:

|   |   |
|---|---|
|1.|When testing a client's [gold image](https://www.techopedia.com/definition/29456/golden-image) Windows workstation and server build for flaws|
|2.|To escalate privileges locally to gain access to some local resource such as a database|
|3.|To gain [NT AUTHORITY\System](https://docs.microsoft.com/en-us/windows/win32/services/localsystem-account) level access on a domain-joined machine to gain a foothold into the client's Active Directory environment|
|4.|To obtain credentials to move laterally or escalate privileges within the client's network|

It's essential to know to perform privilege escalation checks and leverage flaws manually, since we won't always have tools to help as.

Windows systems present a vast attack surface. Just some of the ways that we can escalate privileges are:

|   |   |
|---|---|
|Abusing Windows group privileges|Abusing Windows user privileges|
|Bypassing User Account Control|Abusing weak service/file permissions|
|Leveraging unpatched kernel exploits|Credential theft|
|Traffic Capture|and more.|
