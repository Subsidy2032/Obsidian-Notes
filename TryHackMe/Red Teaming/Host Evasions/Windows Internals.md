## Processes

A process maintains and represents the execution of a program.

A few default applications that start processes:

- MsMpEng (Microsoft Defender)
- wininit (keyboard and mouse)
- lsass (credential storage)

Critical components of processes and their purpose:

|**Process Component **|**Purpose**|
|---|---|
|Private Virtual Address Space|Virtual memory addresses that the process is allocated.|
|Executable Program|Defines code and data stored in the virtual address space.|
|Open Handles|Defines handles to system resources accessible to the process.|
|Security Context|The access token defines the user, security groups, privileges, and other security information.|
|Process ID|Unique numerical identifier of the process.|
|Threads|Section of a process scheduled for execution.|

Process at the lower level where it resides in the virtual address space:

|**Component**|**Purpose**|
|---|---|
|Code|Code to be executed by the process.|
|Global Variables|Stored variables.|
|Process Heap|Defines the heap where data is stored.|
|Process Resources|Defines further resources of the process.|
|Environment Block|Data structure to define process information.|

Utilities that make observing processes easier:

- [Process Hacker 2](https://github.com/processhacker/processhacker)
- [Process Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [Procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)

## Threads

A thread is an executable unit employed by a process and scheduled based on device factors, which very based on CPU, memory specifications and others.

In simple words a thread is controlling the execution of a process.

It's most wildly used with other API calls rather than on its on to aid in code execution.

Thread values and data:

|**Component**|**Purpose**|
|---|---|
|Stack|All data relevant and specific to the thread (exceptions, procedure calls, etc.)|
|Thread Local Storage|Pointers for allocating storage to a unique data environment|
|Stack Argument|Unique value assigned to each thread|
|Context Structure|Holds machine register values maintained by the kernel|

## Virtual Memory

Virtual memories allows components to interact with memory as if it was a physical memory, without the risk of application collisions.

Each process is provided private virtual address space, a memory manager is used to translate virtual address to physical, this way there is less risk of causing damage.

The memory manager will also use pages or transfers to handle memory, in case of apps using more virtual memory than physical memory allocated, the memory manager will transfer or page virtual memory to the disk.

The theoretical maximum virtual address space is a 4 GB on a 32-bit x86 system.

This address space is split in half, the lower half (_0x00000000 - 0x7FFFFFFF_) is allocated to processes as mentioned above. The upper half (_0x80000000 - 0xFFFFFFFF_) is allocated to OS memory utilization. Administrators can alter this allocation layout for applications that require a larger address space through settings (_increaseUserVA_) or the [AWE (**A**ddress **W**indowing **E**xtensions)](https://docs.microsoft.com/en-us/windows/win32/memory/address-windowing-extensions).

The theoretical maximum virtual address space is 256 TB on a 64-bit modern system, it solves most issues that require settings or AWE.

## Dynamic Link Libraries

DLL is a library that contains code and data that can be used by more than one program at the same time.

When a DLL is loaded as a function, its assigned as dependency, since applications are depended on DLLs it can be the target of an attacker.

The DLL is created like an other project or application, with a header file.

When using load-time dynamic linking, explicit calls to the DLL functions are made, you can only achieve this kind with providing a header file and import library.

When loaded using run-time dynamic linking a separate function (`LoadLibrary` or `LoadLibraryEx`) is used to load the DLL at run time, than you will need to use `GetProcessAddress` to identify the exported DLL function to call.

Threat actors will more often use run-time dynamic linking, since transferring one DLL file is easier to manage.

## Portable Executable Format

The PE (Portable Executable) and COFF (Common Object File Format) file make the PE format.

PE data is most commonly seen in a hex dump of an executable file.

PE data structure:

- **DOS header:** defines the type of file.
- **DOS stub:** is a program run by default at a beginning of a file that prints a compatibility message, doesn't usually effect any functionality.
- **PE file header:** provides PE header information of the binary. Defines the format of the file, contains the signature and image file header and other information headers.
- **Image optional header:** An important part of the PE file header.
- **Data Dictionaries:** Part of the image optional header, they point to the image data directory structure.
- **Selection table:** Define the available sections and information in the image.

Headers define the format and function of the file, while sections define the contents and data of the file.

Section purposes:

|**Section**|**Purpose**|
|---|---|
|.text|Contains executable code and entry point|
|.data|Contains initialized data (strings, variables, etc.)|
|.rdata or .idata|Contains imports (Windows API) and DLLs.|
|.reloc|Contains relocation information|
|.rsrc|Contains application resources (images, etc.)|
|.debug|Contains debug information|

## Interacting with Windows Internals

The Windows API provides native functionality to interact with the Windows operating system and is the most accessible and researched option to interact with Windows internals, The API contains Win32 API and less commonly Win64 API.

Most Windows internal components require interacting with physical hardware and memory.

The Windows kernel will control all programs and process and bridge all software and hardware interaction.

An application normally can't by default interact with the kernel or modify physical hardware and requires an interface. This problem is solved trough the use of processor modes and access levels.

A Windows processor has a user and kernel mode, the processor will switch between those depending on access and requested mode.

The switch between the modes is often facilitated by system and API calls, in documentation this point is sometimes referred to as the switching point.

|**User mode**|**Kernel Mode**|
|---|---|
|No direct hardware access|Direct hardware access|
|Creates a process in a private virtual address space|Ran in a single shared virtual address space|
|Access to "owned memory locations"|Access to entire physical memory|

Applications that started in user mode (user land) will stay there until a system call is made or interfaced trough API.

The application will go trough the language runtime before going trough the API, the most common example is C# executing trough the CLR before interacting with the Win32 API and making system calls.

![[2e5b0c2fccd102d477752270054facb2.png]]

We will inject a message box into our local process for PoC of interacting with memory.

We can use `OpenProcess` to obtain the handle of the specified process.

The steps to write a message box to memory are:

1. Allocate local process memory for the message box, we can use `VirtualAlocEx`.
2. Write/copy the message box to allocated memory, we can use `WriteProcessMemory`.
3. Execute the message box from the local process memory, we can use `CreateRemoteThread`.