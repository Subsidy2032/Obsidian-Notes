## Password Profiling #1 - Default, Weak, Leaked, Combined, and Username Wordlists

##### Default Passwords

Website lists that provide default passwords for various products:

- [CIRT](https://cirt.net/passwords)
- [DefaultPassword](https://default-password.info/)
- [Datarecovery](https://datarecovery.com/rd/default-passwords/)

##### Weak Passwords

Wordlists containing weak passwords:

- [SkullSecurity](https://wiki.skullsecurity.org/index.php?title=Passwords): Includes the most well known collections of passwords.
- [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Passwords): Collections of all kinds of lists, not just passwords.

##### Leaked Passwords

[SecLists/Passwords/Leaked-Databases](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Leaked-Databases) - A database of leaked password, may contain hashes lists.

##### Combined Wordlists

`cat file1.txt file2.txt file3.txt > combined_list.txt` - Combine multiple files into a single wordlist.
`sort combined_list.txt | uniq -u > cleaned_combined_list.txt` - Remove duplicate words from the combined list.

##### Customized Wordlists

A company's website can contain things like names of employees, emails, products and services names which may be used in an employees password.

`cewl -w list.txt -d 5 -m 5 http://thm.labs` - Crawl a website to generate a word list, with depth level of 5 and minimum 5 characters.

##### Username Wordlists

[Username_generator](https://github.com/shroudri/username_generator): A tool to generate usernames based on full names wordlist.

## Password Profiling #2 - Keyspace Technique and CUPP

##### Keyspace Technique

With this technique we specify a range of characters, numbers and symbols in our wordlist, with `crunch` we can create an offline wordlist.

##### CUPP - Common User Passwords Profiler

[CUPP](https://github.com/Mebus/cupp) is a tool that generates custom wordlists based on provided information, it also supports 1337/leet mode.

## Offline Attacks - Dictionary and Brute-Force

##### Dictionary Attack

Dictionary attack is a technique of guessing password with previously generated or found list of known words and phrases.

##### Brute-Force Attack

This method is used to guess the victim's password by sending standard password combinations, for example testing all combinations from 0000 to 9999.

## Offline Attacks - Rule-Based

##### Rule-Based Attacks

This attack is used to generate a password given a known policies.

`/etc/john/john.conf` or `/opt/john/john.conf` is where the config file of John the ripper is located, you can look for `list.rules` to see all rules aviable.

##### Custom Rules

We can also write are on rules

## Password Spray Attack

Password Spraying attack uses one common weak password against many users, which could help avoid account lockout policy.

Some common pattern and format of weak passwords:

- The current season followed by the current year (SeasonYear). For example, **Fall2020**, **Spring2021**, etc.
- The current month followed by the current year (MonthYear). For example, **November2020**, **March2021**, etc.
- Using the company name along with random numbers (CompanyNameNumbers). For example, TryHackMe01, TryHackMe02.

For this attack we will need to enumerate the company for valid usernames or email address, and to take policies into account when guessing the password.

Password spraying attack tools:

- [RDPassSpray](https://github.com/xFreed0m/RDPassSpray) - A tool to perform a password spray attack against RDP.
- [Spraying Toolkit (atomizer.py)](https://github.com/byt3bl33d3r/SprayingToolkit) - For Outlook Web Access (OWA) portal.
- [MailSniper](https://github.com/dafthack/MailSniper) - For Outlook Web Access (OWA) portal.
- Metasploit (auxiliary/scanner/smb/smb_login) - For SMB.