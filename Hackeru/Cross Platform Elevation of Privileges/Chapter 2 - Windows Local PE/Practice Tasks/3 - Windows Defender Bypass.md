1. Add the windows 10 ISO to the windows 10 machine storage
2. Press a key to boot the iso file
3. Click next
4. Click repair your computer
5. Select trubleshoot
6. Select commend prompt
7. Get disk name - wmic logicaldisk get name
8. Navigate to D:\windows\system32
	D:
	cd windows\system32
9. Copy the cmd executable to osk.exe - copy cmd.exe osk.exe
10. Force a safe boot to prevent windows defender from loading - bcdedit /set {default} safeboot minimal
11. Boot into the installd system and access the on screen keyboard
12. To disable safemode - bcdedit /deletevalue {default} safeboot