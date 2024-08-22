Suppose [auditing of process creation](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-creation) events and corresponding command line values is enabled. The information will be saved to the Windows security event log as event ID [4688: A new process has been created](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688). Enabling it can help defenders monitor and identify possibly malicious behavior and identify binaries that should not be present on a system. The data could be shipped to a SIEM tool or ingested into a search tool, such as ElasticSearch. The tools will flag activities like commands such as `whoami`, `netstat`, and `tasklist` being run from a marketing executive's workstation.

This [study](https://blogs.jpcert.or.jp/en/2016/01/windows-commands-abused-by-attackers.html) shows some of the most run commands by attackers after initial access (`tasklist`, `ver`, `ipconfig`, `systeminfo`, etc.), for reconnaissance (`dir`, `net view`, `ping`, `net use`, `type`, etc.), and for spreading malware within a network (`at`, `reg`, `wmic`, `wusa`, etc.). An organization can also restrict execution of specific commands using fine-tuned AppLocker rules. With tight security budget, those built-in tools can offer excellent visibility into network activities at the host level. Most modern enterprise EDR tools perform detection/blocking but can be out of reach for many organizations due to budgetary and personnel constraints.

Administrators or members of the [Event Log Readers](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255(v=ws.11)?redirectedfrom=MSDN#event-log-readers) group have permission to access this log. It is conceivable that system administrators might want to add power users or developers into this group to perform certain tasks without having to grant them administrative access.

### Confirming Group Membership
```cmd-session
C:\htb> net localgroup "Event Log Readers"

Alias name     Event Log Readers
Comment        Members of this group can read event logs from local machine

Members

-------------------------------------------------------------------------------
logger
The command completed successfully.
```

Microsoft has published a reference [guide](https://download.microsoft.com/download/5/8/9/58911986-D4AD-4695-BF63-F734CD4DF8F2/ws-commands.pdf) for all built-in Windows commands. Many Windows commands support passing a password as a parameter, and if auditing of process command lines is enabled, this sensitive information will be captured.

We can query Windows events from the command line using the [wevtutil](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil) utility and the [Get-WinEvent](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.1) PowerShell cmdlet.

### Searching Security Logs Using wevtutil
```powershell-session
PS C:\htb> wevtutil qe Security /rd:true /f:text | Select-String "/user"

        Process Command Line:   net use T: \\fs01\backups /user:tim MyStr0ngP@ssword
```

We can also specify alternate credentials for `wevtutil` using the parameters `/u` and `/p`.

### Passing Credentials to wevtutil
```cmd-session
C:\htb> wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"
```

For `Get-WinEvent`, the syntax is as follows. In this example, we filter for process creation events (4688), which contain `/user` in the process command line.

Note: Searching the `Security` event log with `Get-WInEvent` requires administrator access or permissions adjusted on the registry key `HKLM\System\CurrentControlSet\Services\Eventlog\Security`. Membership in just the `Event Log Readers` group is not sufficient.

### Searching Security Logs Using Get-WinEvent
```powershell-session
PS C:\htb> Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}

CommandLine
-----------
net use T: \\fs01\backups /user:tim MyStr0ngP@ssword
```

The cmdlet can also be run as another user with the `-Credential` parameter.

Other logs include [PowerShell Operational](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.1) log, which may also contain sensitive information or credentials if script block or module logging is enabled. This log is accessible to unprivileged users.