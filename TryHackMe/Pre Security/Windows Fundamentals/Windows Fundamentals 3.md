#Windows 

`control /name Microsoft.WindowsUpdate` - Access Windows update from CMD.

# Virus & threat protection

## Current threats

### Scan options

- Quick scan: checks folders in your system where threats are commonly found.
- Full scan: Checks all files and running programs on your hard disk, can take longer than one hour.
- Custom scan: Choose which files and locations you wanna check.

### Threat history

- Last scan: The windows defender antivirus automatically scans your computer.
- Quarantined threats: Threats that has been isolated and prevented from running, will be periodically removed.
- Allowed threats: Identified as threats and allowed to run by you.

### Virus & threat protection settings

- Real-time protection: Locates and stops malware from installing or running on your device.
- Cloud-delivered protection: Increased and faster protection with access to the latest protection data in the cloud.
- Automatic sample submission: Send sample files to Microsoft to help protect.
- Controlled folder access: Protect files, folders and memory areas from authorized changes by unfriendly applications.
- Exclusions: Items not to scan.
- Notifications: Critical notifications about health and security of your device by Windows Defender Antivirus

### Ransomware protection

Controlled folder access: Requires real time protection to be enabled, also required for ransomware protection to work.
	
	
	
	
	
# Firewall & network protection

### Profiles

- Domain: For networks where the host system can authenticate to a domain controller.
- Private: User-assigned profile and is used in private or home networks.
- Public: Default, used in public networks such as hotspots at coffee shops or airports.
	
	
	
	
	
	
# App & browser control

- Windows Defender SmartScreen: Helps protects your device by checking for unrecognized apps and files from the web.
- Exploit protection: Built-in, to help protect against attacks.
	
	
	
	
	
	
	
# Device security

Core isolation:

- Memory integrity: Prevents attacks from inserting malicious code into high-security processes.

Security processor - Trusted platform module (TPM), provides additional encryption for your device.

BitLocker - Works best with TPM.
	
	
	
	
	
	
	
# Volume Shadow Copy Service

Per [Microsoft](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service), the Volume Shadow Copy Service (VSS) coordinates the required actions to create a consistent shadow copy (also known as a snapshot or a point-in-time copy) of the data that is to be backed up.

Stored on the System Volume Information Folder when the drive has protection enabled.

### Tasks you can do from advanced system settings

- Create a restore point
- Perform system restore
- Configure restore settings
- Delete restore points
