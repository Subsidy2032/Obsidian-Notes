A restricted shell is a type of shell that limits the user's ability to execute commands. The user may be able to only execute a specific set of commands or only execute commands in specific directories. Some common examples of restricted shells include the `rbash` shell in Linux and the "Restricted-access Shell" in Windows.

## RBASH

[Restricted Bourne shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html) (`rbash`) is a restricted version of the Bourne shell, a standard command line interpreter in Linux which limits the user's ability to use certain features of the BASH, such as changing directories, setting or modifying environment variables, and executing commands in other directories. It is often used to provide a safe and controlled environment for users who may accidentally or intentionally damage the system.

## RKSH

[Restricted Korn shell](https://www.ibm.com/docs/en/aix/7.2?topic=r-rksh-command) (`rksh`) is a restricted version of the Korn shell, another standard command line interpreter. The `rksh` shell limits the user's ability to use certain features of the Korn shell, such as executing commands in other directories, creating or modifying shell functions, and modifying the shell environment.

## RZSH

[Restricted Z shell](https://manpages.debian.org/experimental/zsh/rzsh.1.en.html) (`rzsh`) is a restricted version of the Z shell and is the most powerful and flexible command-line interpreter. The `rzsh` shell limits the user's ability to use certain features of the Z shell, such as running shell scripts, defining aliases, and modifying the shell environment.

In addition to preventing accidental or intentional damage, restricted shells can also control which resources and functions are available to users.

Imagine a company with a network of Linux servers hosting critical business applications and services. Many users, including employees, contractors, and external partners, access the network. To protect the security and integrity of the network, the organization's IT team decided to implement restricted shells for all users.

To do this, the IT team sets up several `rbash`, `rksh`, and `rzsh` shells on the network and assigns each user to a specific shell. each of those shells provides different level of flexibility.

Several methods can be used to escape from a restricted shell. Some of these methods involve exploiting vulnerabilities in the shell itself, while others involve using creative techniques to bypass the restrictions imposed by the shell.

## Escaping

In some cases, it may be possible to escape from a restricted shell by injecting commands into the command line or other inputs the shell accepts. For example, suppose the shell allows users to execute commands by passing them as arguments to a built-in command. In that case, it may be possible to escape from the shell by injecting additional commands into the argument.

### Command Injection

Let's say the restricted shell only allows us to execute `ls` with a set of arguments, such as `ls -l` or `ls -a`. We can use command injection to escape the shell.

For example, we could use the following command to inject a `pwd` command into the argument of the `ls` command:
```shell-session
$ ls -l `pwd` 
```

We will see the output of the `pwd` command, because it's not restricted by the shell, even though we can't use the `pwd` command directly.

### Command Substitution

Another escaping method is command substitution. This involves using the shell's command substitution syntax to execute commands. For example, if the shell allows to execute commands by enclosing them in backticks (\`). We may be able to use this to escape the shell.

### Command Chaining

We can try to use multiple commands in a single command line by a shell metacharacter, such as a semicolon (`;`) or a vertical bar (`|`). For example we can use it to execute 2 commands, one of which isn't restricted by the shell.

### Environment Variable

We can modify or create environment variables not restricted by the shell to execute commands. For example, if the shell uses an environment variable to specify the directory in which commands are executed, it may be possible to escape from the shell by modifying the value of the environment variable to specify a different directory.

### Shell Functions

We can define and call shell functions that execute commands not restricted by the shell to escape the shell. Let us say, the shell allows users to define and call shell functions, it may be possible to escape from the shell by defining a shell function that executes a command.