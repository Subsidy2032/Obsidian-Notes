## Search Centric

Most applications and operating systems have search functionality, a user may documented their password somewhere on the system, or there might be a file that contains default credentials, we need to ask ourselves what does the user of the computer does on day to day basis, and which of those tasks may require credentials.

### Key Terms to Search
|               |              |             |
| ------------- | ------------ | ----------- |
| Passwords     | Passphrases  | Keys        |
| Username      | User account | Creds       |
| Users         | Passkeys     | Passphrases |
| configuration | dbcredential | dbpassword  |
| pwd           | Login        | Credentials |

## Search Tools

It's worth trying to use Windows search, by default it searches various OS settings, and the file system for files & applications containing the key term entered in the search bar.

[Lazagne](https://github.com/AlessandroZ/LaZagne) is a tool that searches through web browsers and other applications for insecurely stored credentials.

### Running Lazagne All
```cmd-session
C:\Users\bob\Desktop> start lazagne.exe all
```

### Using findstr
```cmd-session
C:\> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

## Additional Considarations

The key words and techniques we will use can depend for example on if it's a windows server machine or a desktop OS, we may be able to find credentials by navigating and listing directories.

### Some other places to keep in mind
- Passwords in Group Policy in the SYSVOL share
- Passwords in scripts in the SYSVOL share
- Password in scripts on IT shares
- Passwords in web.config files on dev machines and IT shares
- unattend.xml
- Passwords in the AD user or computer description fields
- KeePass databases --> pull hash, crack and get loads of access.
- Found on user systems and shares
- Files such as pass.txt, passwords.docx, passwords.xlsx found on user systems, shares, [Sharepoint](https://www.microsoft.com/en-us/microsoft-365/sharepoint/collaboration)
