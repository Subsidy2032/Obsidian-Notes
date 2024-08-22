#Windows 

## System Configuration

MSConfig (System Configuration utility) - for advanced troubleshooting, mainly to diagnose startup issues.

#### System Configuration Tabs:

1. **General:** Devices and services to load up upon boot
2. **Boot:** Define various boot options
3. **Services:** List of all services configured on the system
4. **Startup:** Startup items configured by the task manager
5. **Tools:** Tools we can run to configure the operating system

## Computer Management (compmgmt):

#### System Tools:

*Task Scheduler:* Create and manage common tasks the computer will carry out automatically at specified times, for example during log in or log off

*Event Viewer:* To see event occurred on the computer, often for diagnosing problems and investigating actions executed on the computer

<u>Event Types:</u>

**Error:** Indicates a significant problem, such as loss of data or functionality

**Warning:** Does not indicate a significant problem, for example when disk space is low

**Information:** Describes successful operation of an application, driver or service

**Success Audit:** audited security access attempt that is successful, for example a user that successfully logged in to the system

**Failure audit:** audited security access attempt that is failed, for example a user that attempted to access a network drive and failed

<u>Standard Logs:</u>

**Application:** Events logged by an application, the application developer decides which events to log

**Security:** Events such as valid and invalid login attempts or creating, opening or deleting files

**System:** For example the failure of a driver or other system component to load during startup

**CustomLog:** Logged by an application that create a custom log, gives the ability to log or attach ACLs or control the size of the log without affecting other applications
	
	
	
*Shared Folders:* Where you will see a complete list of shares and folders others can connect to

**Sessions:** Users currently connected to the shares

**Open Files:** All folders/files connected users access
	
	
	
*Performance Monitor (perfmon):* view performance data in real time or from a log file, can help troubleshoot performance issue, local or remote

*Device Manager:* View and configure the hardware, for example disabling hardware attached to the computer

<u>Disk Management (in storage)</u>

- Set up a new drive
- Extend a partition
- Shrink a partition
- Assign or change a drive letter

*Services and Applications:* Gives you to do more than enabling or disabling a service, such as view the properties of a service

WMI Control configures and controls the **Windows Management Instrumentation** (WMI) service.

Per Wikipedia, "_WMI allows scripting languages (such as VBScript or Windows PowerShell) to manage Microsoft Windows personal computers and servers, both locally and remotely. Microsoft also provides a command-line interface to WMI called Windows Management Instrumentation Command-line (WMIC)._"

**Note**: The WMIC tool is deprecated in Windows 10, version 21H1. Windows PowerShell supersedes this tool for WMI.
	
	
	
	
	
*System Information(msinfo32):* Gathers information about the computer and displays a comprehensive view of your hardware, system components and software environment, which you can use to diagnose computer issues

<u>msinfo32 sections</u>

**System summary:** General technical specifications for the computer, such as processor brand and model

**Hardware Resources:** Not for the average computer user

**Components:** Information about the hardware devices installed on the computer, some sections do not show any information

**Software environment:** Information about software baked into the operating system and software you have installed and some other information

Per [Microsoft](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables?view=powershell-7.1), "_Environment variables store information about the operating system environment. This information includes details such as the operating system path, the number of processors used by the operating system, and the location of temporary folders._

**WINDIR variable:** Location of windows installation directory, programs can query this value

Another way to see environment variables:

`Control Panel > System and Security > System > Advanced system settings > Environment Variables` **OR** `Settings > System > About > system info > Advanced system settings > Environment Variables`

Per Microsoft, "_Resource Monitor displays per-process and aggregate CPU, memory, disk, and network usage information, in addition to providing details about which processes are using individual file handles and modules. Advanced filtering allows users to isolate the data related to one or more processes (either applications or services), start, stop, pause, and resume services, and close unresponsive applications from the user interface. It also includes a process analysis feature that can help identify deadlocked processes and file locking conflicts so that the user can attempt to resolve the conflict instead of closing an application and potentially losing data._"

*Windows Registry:* Central hierarchical database used to store information necessary to configure the system for one or more users, applications and hardware devices

<u>Information in windows registry</u>

- Profiles for each user
- Applications installed on the computer and types of documents that each can create
- Property sheet settings for folders and application icons
- What hardware exist on the system
- The ports that are being used

**Note:** Making changes to the registry can affect normal computer operations