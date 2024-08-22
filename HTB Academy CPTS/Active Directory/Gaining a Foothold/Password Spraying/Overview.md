Password spraying attack involves using one common password and a long list of usernames or email addresses. The usernames and email addresses can be gathered during the OSINT phase or the initial enumeration attempts.

## Password Spraying Considirations

Carless use of this attack can cause considerable harm, such as locking out hundreds of production accounts.

### Password Spray Visualization
|**Attack**|**Username**|**Password**|
|---|---|---|
|1|bob.smith@inlanefreight.local|Welcome1|
|1|john.doe@inlanefreight.local|Welcome1|
|1|jane.doe@inlanefreight.local|Welcome1|
|DELAY|||
|2|bob.smith@inlanefreight.local|Passw0rd|
|2|john.doe@inlanefreight.local|Passw0rd|
|2|jane.doe@inlanefreight.local|Passw0rd|
|DELAY|||
|3|bob.smith@inlanefreight.local|Winter2022|
|3|john.doe@inlanefreight.local|Winter2022|
|3|jane.doe@inlanefreight.local|Winter2022|

This attack is less likely to lock out users then a brute force attack, but it still presents a risk, so the delay is essential. Internal password spraying can be used to move laterally within a network, with internal access we might be able to obtain the domain password policy, which significantly reduces the risk.

It’s common to find a password policy that allows five bad attempts before locking out the account, with a 30-minute auto-unlock threshold. Some organizations expand upon this, even requiring an administrator to unlock the accounts manually. Without the password policy, a good rule of thumb is to wait a few hours between attempts. We can choose to do just one targeted password spraying attempt as a hail mary if all other options for a foothold or furthering access have been exhausted. Depending on the type of assessment, we can always ask the client to verify the password policy.