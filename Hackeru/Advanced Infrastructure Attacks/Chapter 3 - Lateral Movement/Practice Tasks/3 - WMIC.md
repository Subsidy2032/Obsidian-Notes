1. Run cmd using administrator privileges
2. Create a calc.exe process on a remote machine using WMIC - wmic /node:[ip] /user:[user] /password:[password] process call create calc.exe
3. wmic /node:[ip] /user:[user] /password:[password] process call create notepad.exe
4. Terminate the calc process using WMIC - wmic /node:[ip] /user:[user] /password:[password] process where name="calc.exe" call terminate