#Windows 

## The file system:

Before NTFS - FAT16/FAT32 (File Allocation Table) and HPFS (High Performance File System)
FAT is still used in things like USB devices or MicroSD cards.

NTFS (New Technology File System) - Also known as a journaling file system, can repair folders/files on disk in case of failure using information from log files.

### Limitations addressed by NTFS:

- Supports files larger than 4GB
- Set specific permissions on folders and files
- Folder and file compression
- EFS (Encryption File System)

## Permissions:

![[ntfs-permissions1.png]]

## ADS (Alternate Data Streams):

- Each file has at least one data stream ($data), ADS allows more, Powershell allows to view ADS for files.
- Malware writers have used ADS to hide data.
- One of the uses is that when you download a file from the internet there are identifiers written to ADS to identify that the file was downloaded from the internet.

## The windows folder:

`C:\Windows`: The folder which contains the Windows operating center.

This is where the system environment variables come into play, the system environment variable for Windows directory is `%windir%`.

Per [Microsoft](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables?view=powershell-7.1), "_Environment variables store information about the operating system environment. This information includes details such as the operating system path, the number of processors used by the operating system, and the location of temporary folders_".

`System32`: A folder inside the Windows folder, hold important files that are critical for the operating system, Many of the tools we will cover in the Windows fundamentals series reside within this folder.

## Users

Administrator - Can make changes to the system: add users, delete users, modify groups, modify settings on the system, etc.

Standard User - Can only make changes to the files and folders attributed to him, can't perform system level system, such as install programs.

Some of the folders for all users:

- Desktop
- Documents
- Downloads
- Music
- Pictures

## UAC (User Account Control):

When a user with an account type of administrator logs in to the system, the current session does not run with elevated privileges, instead the user is prompted to confirm an operation when required by the operating system.

**Note:** UAC (by default) doesn't apply for the built in administrator account.
	
	
Control panel: Used for more complex settings and actions, you can start in the settings and end up in the control panel.

