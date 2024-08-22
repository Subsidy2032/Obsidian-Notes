1. Open cmd using administrator privileges
2. Add remote computer to trusted hosts via powershell - set-item wsman:\localhost\client\trustedhosts [remote computer name]
3. Restart WinRm service in order to apply the changes - restart-service winrm
4. Define variable to conyain credentials:
	$password = convertto-securestring ["password"] -asplaintext -force
	$cred = new-object system.management.automation.pscredential(["user"], $password)
	echo $cred
5. Add user remotly using WinRM - invoke-command -computername ["remote computer name"] -credential $cred -scriptblock {net user [username] [password] /add}
6. Verify the user was created in the remote machine - net user [username]
	