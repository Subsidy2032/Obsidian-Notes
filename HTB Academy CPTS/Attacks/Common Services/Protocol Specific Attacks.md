## The Concept of Attacks
![[attack_concept2.webp]]

Source performs the specific request to a process where the vulnerability gets triggered. Each process has a specific set of privileges, and goal or destination to either compute new data or forward it. Destination does not always serve as source.

### Source

We can generalize source as the source of information used for the specific task or process, here are some of the most common examples of how information is passed to the processes:

|**Information Source**|**Description**|
|---|---|
|`Code`|This means that the already executed program code results are used as a source of information. These can come from different functions of a program.|
|`Libraries`|A library is a collection of program resources, including configuration data, documentation, help data, message templates, prebuilt code and subroutines, classes, values, or type specifications.|
|`Config`|Configurations are usually static or prescribed values that determine how the process processes information.|
|`APIs`|The application programming interface (API) is mainly used as the interface of programs for retrieving or providing information.|
|`User Input`|If a program has a function that allows the user to enter specific values used to process the information accordingly, this is the manual entry of information by a person.|

#### log4j

log4j ([CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2021-44228)) is a framework or library used to log application messages in Java and other programming languages. This library contains classes and functions that other programming languages can integrate. For this purpose, information is documented. The scope can be configured extensively, and it had become a standard within many open source and commercial software products. For example an attacker can insert JNDI lookup to HTTP's User-Agent as a command intended for log4j library, which will be processed instead of the actual User-Agent.

### Processes

The processes process the information from the source, according to the program code, most of the vulnerabilities lie in the program code executed by the process.

|**Process Components**|**Description**|
|---|---|
|`PID`|The Process-ID (PID) identifies the process being started or is already running. Running processes have already assigned privileges, and new ones are started accordingly.|
|`Input`|This refers to the input of information that could be assigned by a user or as a result of a programmed function.|
|`Data processing`|The hard-coded functions of a program dictate how the information received is processed.|
|`Variables`|The variables are used as placeholders for information that different functions can further process during the task.|
|`Logging`|During logging, certain events are documented and, in most cases, stored in a register or a file. This means that certain information remains in the system.|

#### log4j

The process of log4j is to log the User-Agent as a string in the designated location, the vulnerability is the misinterpretation of the string, that leads to execution instead of logging.

### Privileges

Privileges serve as a type of permission that determines what tasks and actions can be performed on the system. We can divide those privileges into the following areas:

|**Privileges**|**Description**|
|---|---|
|`System`|These privileges are the highest privileges that can be obtained, which allow any system modification. In Windows, this type of privilege is called `SYSTEM`, and in Linux, it is called `root`.|
|`User`|User privileges are permissions that have been assigned to a specific user. For security reasons, separate users are often set up for particular services during the installation of Linux distributions.|
|`Groups`|Groups are a categorization of at least one user who has certain permissions to perform specific actions.|
|`Policies`|Policies determine the execution of application-specific commands, which can also apply to individual or grouped users and their actions.|
|`Rules`|Rules are the permissions to perform actions handled from within the applications themselves.|

#### log4j

The log4j is so dangerous because the logs are stored in a high privileged area that no regular user should be able to access. Most applications with log4j implementation run with the privileges of Administrator.

### Destination

Every task has a purpose or a goal, the results are either stored somewhere or forwarded to another processing point. The destination is where the changes will be made.

|**Destination**|**Description**|
|---|---|
|`Local`|The local area is the system's environment in which the process occurred. Therefore, the results and outcomes of a task are either processed further by a process that includes changes to data sets or storage of the data.|
|`Network`|The network area is mainly a matter of forwarding the results of a process to a remote interface. This can be an IP address and its services or even entire networks. The results of such processes can also influence the route under certain circumstances.|

#### log4j

The User-Agent leads to JNDI lookup which is executed with administrator privileges and queries a remote server controlled by the attacker (the destination). This query requests a Java class created by the attacker and is manipulated for it's own purposes. The Java class is executed in the same process, leading to RCE.

![[log4jattack.webp]]
Source: https://www.govcert.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/

##### Initiation of the Attack
|**Step**|**Log4j**|**Concept of Attacks - Category**|
|---|---|---|
|`1.`|The attacker manipulates the user agent with a JNDI lookup command.|`Source`|
|`2.`|The process misinterprets the assigned user agent, leading to the execution of the command.|`Process`|
|`3.`|The JNDI lookup command is executed with administrator privileges due to logging permissions.|`Privileges`|
|`4.`|This JNDI lookup command points to the server created and prepared by the attacker, which contains a malicious Java class containing commands designed by the attacker.|`Destination`|

##### Trigger Remote Code Execution
|**Step**|**Log4j**|**Concept of Attacks - Category**|
|---|---|---|
|`5.`|After the malicious Java class is retrieved from the attacker's server, it is used as a source for further actions in the following process.|`Source`|
|`6.`|Next, the malicious code of the Java class is read in, which in many cases has led to remote access to the system.|`Process`|
|`7.`|The malicious code is executed with administrator privileges due to logging permissions.|`Privileges`|
|`8.`|The code leads back over the network to the attacker with the functions that allow the attacker to control the system remotely.|`Destination`|

## Service Misconfigurations

### Authentication

Newer application asks users to setup credentials upon installations, but it's still possible to find services with default credentials, especially on older applications.

An administrator might setup weak or no password for a service, thinking he will change that when the service is up and running.

After grabbing the service banner we should identify default credentials, or try some weak credentials if there isn't.

```shell-session
admin:admin
admin:password
admin:<blank>
root:12345678
administrator:Password
```

#### Anonymous Authentication

#### Misconfigured Access Rights

A user might have incorrect permissions, for example a user whose role is to upload files to the FTP server, might have the right to read every FTP document, which can allow as to access sensitive information.

Administrators need to plan their access rights strategy, and there are some alternatives such as [Role-based access control (RBAC)](https://en.wikipedia.org/wiki/Role-based_access_control), [Access control lists (ACL)](https://en.wikipedia.org/wiki/Access-control_list). If we want more detailed pros and cons of each method, we can read [Choosing the best access control strategy](https://authress.io/knowledge-base/role-based-access-control-rbac) by Warren Parad from Authress.

### Unnecessary Defaults

Leaving devices and software with their default configuration is not a good practice for security, we need to change the settings to reduce the attack surface.

With default services attackers can obtain credentials, or abuse weak settings with a simple google search.

[Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) are part of the [OWASP Top 10 list](https://owasp.org/Top10/). Let's take a look at those related to default values:

- Unnecessary features are enabled or installed (e.g., unnecessary ports, services, pages, accounts, or privileges).
- Default accounts and their passwords are still enabled and unchanged.
- Error handling reveals stack traces or other overly informative error messages to users.
- For upgraded systems, the latest security features are disabled or not configured securely.

### Preventing Misconfigurations

The most straightforward strategy to control risk is to lock down the most critical infrastructure and only allow desired behavior, this may include:

- Admin interfaces should be disabled.
- Debugging is turned off.
- Disable the use of default usernames and passwords.
- Set up the server to prevent unauthorized access, directory listing, and other issues.
- Run scans and audits regularly to help discover future misconfigurations or missing fixes.

The OWASP Top 10 provides a section on how to secure the installation processes:

- A repeatable hardening process makes it fast and easy to deploy another environment that is appropriately locked down. Development, QA, and production environments should all be configured identically, with different credentials used in each environment. In addition, this process should be automated to minimize the effort required to set up a new secure environment.
    
- A minimal platform without unnecessary features, components, documentation, and samples. Remove or do not install unused features and frameworks.
    
- A task to review and update the configurations appropriate to all security notes, updates, and patches as part of the patch management process (see A06:2021-Vulnerable and Outdated Components). Review cloud storage permissions (e.g., S3 bucket permissions).
    
- A segmented application architecture provides effective and secure separation between components or tenants, with segmentation, containerization, or cloud security groups (ACLs).
    
- Sending security directives to clients, e.g., security headers.
    
- An automated process to verify the effectiveness of the configurations and settings in all environments.

## Finding Sensitive Information

When attacking a service, we usually play a detective role, and we try to collect as much information as possible and carefully observe the details.

We might find another useful information inside a compromised service, to attack the same or another service with this information, which might in turn reveal another useful information, and so on.

A misconfigured service can let as access a piece of information that might not seem important, but can be useful at the end.

Sensitive information may include:

- Usernames.
- Email Addresses.
- Passwords.
- DNS records.
- IP Addresses.
- Source code.
- Configuration files.
- PII.

#### Understanding of what We Have to Look for

We need to first familiarize ourselves with the processes, procedures, business model, and purpose of our target. Then we can think about the information essential for them, and what kind of information is helpful for our attack.

There are two key elements to finding sensitive information:

1. We need to understand the service and how it works.
2. We need to know what we are looking for.