The tools here can provide different visualization and data for the purpose of auditing.

## Creating an AD Snapshot with Active Directory Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) is part of the Sysinternal Suite and is described as:

"An advanced Active Directory (AD) viewer and editor. You can use it to navigate AD easily, define favorite locations, view object properties, and attributes without opening dialog boxes, edit permissions, view an object's schema, and execute sophisticated searches that you can save and re-execute."

AD Explorer can also be used to take snapshot of an AD database for offline viewing and comparison.

When we first load the tool, we are prompted for login credentials or to load a previous snapshot. We can log in with any valid domain user.

### Logging in with AD Explorer
![[AD_explorer1.webp]]

### Browsing AD with AD Explorer
![[AD_explorer_logged_in.webp]]

To take a snapshot of AD, go to File --> `Create Snapshot` and enter a name for the snapshot. Once it is complete, we can move it offline for further analysis.

### Creating a Snapshot of AD with AD Explorer
![[AD_explorer_snapshot.webp]]

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) is a powerful tool that evaluates the security posture of an AD environment and provides us the results in several different maps and graphs. Without an active inventory of the hosts in the enterprise, PingCastle can be a great resource to help you gather one in a nice user-readable map of the domain. PingCatle is different from tools such as PowerView and BloodHound because, aside from providing us with enumeration data that can inform our attacks, it also provides as a detailed report of the target's domain security level using a methodology based on a risk assessment/maturity framework. The scoring shown in the report is based on the [Capability Maturity Model Integration](https://en.wikipedia.org/wiki/Capability_Maturity_Model_Integration) (CMMI).

### Running PingCastle

To run PingCastle, we can call the executable by typing `PingCastle.exe` into our CMD or PowerShell window or by clicking on the executable, and it will drop us into interactive mode, presenting us with a menu of options inside the `Terminal User Interface` (`TUI`).

### PingCastle Interactive TUI
```cmd-session
|:.      PingCastle (Version 2.10.1.0     1/19/2022 8:12:02 AM)
|  #:.   Get Active Directory Security at 80% in 20% of the time
# @@  >  End of support: 7/31/2023
| @@@:
: .#                                 Vincent LE TOUX (contact@pingcastle.com)
  .:       twitter: @mysmartlogon                    https://www.pingcastle.com
What do you want to do?
=======================
Using interactive mode.
Do not forget that there are other command line switches like --help that you can use
  1-healthcheck-Score the risk of a domain
  2-conso      -Aggregate multiple reports into a single one
  3-carto      -Build a map of all interconnected domains
  4-scanner    -Perform specific security checks on workstations
  5-export     -Export users or computers
  6-advanced   -Open the advanced menu
  0-Exit
==============================
This is the main functionnality of PingCastle. In a matter of minutes, it produces a report which will give you an overview of your Active Directory security. This report can be generated on other domains by using the existing trust links.
```

The default option is the healthcheck run, which will establish a baseline overview of the domain, and provide us with pertinent information dealing with misconfiguration and vulnerabilities. Even better, PingCastle can report recent vulnerability susceptibility, our shares, trusts, the delegation of permissions, and much more about our user and computer states. Under the Scanner option, we can find most of these checks.

### Scanner Options
```cmd-session
|:.      PingCastle (Version 2.10.1.0     1/19/2022 8:12:02 AM)
|  #:.   Get Active Directory Security at 80% in 20% of the time
# @@  >  End of support: 7/31/2023
| @@@:
: .#                                 Vincent LE TOUX (contact@pingcastle.com)
  .:       twitter: @mysmartlogon                    https://www.pingcastle.com
Select a scanner
================
What scanner whould you like to run ?
WARNING: Checking a lot of workstations may raise security alerts.
  1-aclcheck                                                  9-oxidbindings
  2-antivirus                                                 a-remote
  3-computerversion                                           b-share
  4-foreignusers                                              c-smb
  5-laps_bitlocker                                            d-smb3querynetwork
  6-localadmin                                                e-spooler
  7-nullsession                                               f-startup
  8-nullsession-trust                                         g-zerologon
  0-Exit
==============================
Check authorization related to users or groups. Default to everyone, authenticated users and domain users
```

Now that we understand how it works and how to start scans, let's view the report.

### Viewing the Report

Throughout the report, there are sections such as domain, user, group, and trust information and a specific table calling out "anomalies" or issues that may require immediate attention. We will also be presented with the domain's overall risk score.

![[report-example.gif]]

## Group3r

[Group3r](https://github.com/Group3r/Group3r) is a tool purpose-built to find vulnerabilities in Active Directory associated with Group Policy. It must be run from a domain joined host with a domain user, or in the context of a domain user (i.e., using `runas /netonly`).

### Group3r Basic Usage
```cmd-session
C:\htb> group3r.exe -f <filepath-name.log> 
```

The `-f` flag is to specify output file, we'll use the `-s` flag to send results to stdout.

### Reading Output
![[grouper-output.webp]]

When reading the output from Group3r, each indentation is a different level, so no indent will be the GPO, one indent will be policy settings, and another will be findings in those settings. Below we will take a look at the output shown from a finding.

### Group3r Finding
![[grouper-finding.webp]]

## ADRecon

There are several other tools out there that are useful for gathering a large amount of data from AD at once. In an assessment where stealth isn't required, it is also worth running a tool like [ADRecon](https://github.com/adrecon/ADRecon) and analyzing the results, just in case all of our enumeration missed something minor that may be useful to us or worth pointing out to our client.

### Running ADRecon
```powershell-session
PS C:\htb> .\ADRecon.ps1
```

Once done, we will have a report in a new folder under the directory we executed from. When generating the report, the program Excel needs to be installed, or the script will not automatically generate the report in that manner, it will just leave you with the .csv files. If you want output for Group Policy, you need to ensure the host you run from has the `GroupPolicy` PowerShell module installed. We can go back later and generate the Excel report from another host using the `-GenExcel` switch and feeding in the report folder.

### Reporting
```powershell-session
PS C:\htb> ls

    Directory: C:\Tools\ADRecon-Report-20220328092458

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         3/28/2022  12:42 PM                CSV-Files
-a----         3/28/2022  12:42 PM        2758736 GPO-Report.html
-a----         3/28/2022  12:42 PM         392780 GPO-Report.xml
```
