## Personalized Wordlists

To collect information about the target, we could use their [Wikipedia page](https://en.wikipedia.org/wiki/Bill_Gates) or do a basic google search, this is discussed in detail in the [Hashcat](https://academy.hackthebox.com/module/details/20) module.

### CUPP

`Cupp` is very easy to use. We run it in interactive mode by specifying the `-i` argument, and answer the questions, as follows:
```shell-session
$ cupp -i

___________
   cupp.py!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]


[+] Insert the information about the victim to make a dictionary
[+] If you don't know all the info, just hit enter when asked! ;)

> First Name: William
> Surname: Gates
> Nickname: Bill
> Birthdate (DDMMYYYY): 28101955

> Partners) name: Melinda
> Partners) nickname: Ann
> Partners) birthdate (DDMMYYYY): 15081964

> Child's name: Jennifer
> Child's nickname: Jenn
> Child's birthdate (DDMMYYYY): 26041996

> Pet's name: Nila
> Company name: Microsoft

> Do you want to add some key words about the victim? Y/[N]: Phoebe,Rory
> Do you want to add special chars at the end of words? Y/[N]: y
> Do you want to add some random numbers at the end of words? Y/[N]:y
> Leet mode? (i.e. leet = 1337) Y/[N]: y

[+] Now making a dictionary...
[+] Sorting list and removing duplicates...
[+] Saving dictionary to william.txt, counting 43368 words.
[+] Now load your pistolero with william.txt and shoot! Good luck!
```

And as a result, we get our personalized password wordlist saved as `william.txt`.

### Password Policy

Lets say the password should meet the following conditions:

1. 8 characters or longer
2. contains special characters
3. contains numbers

Some tools would convert password policies to `Hashcat` or `John` rules, but `hydra` does not support rules for filtering passwords. So, we will simply use the following commands to do that for us:
```bash
sed -ri '/^.{,7}$/d' william.txt            # remove shorter than 8
sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt # remove no special chars
sed -ri '/[0-9]+/!d' william.txt            # remove no numbers
```

It can get our wordlist much much shorter.

### Mangling

We can add permutations of each word in that list, which will also take longer time.

Many great tools do word mangling and case permutation quickly and easily, like [rsmangler](https://github.com/digininja/RSMangler) or [The Mentalist](https://github.com/sc0tfree/mentalist.git).

It's best to first use no mangling, then add it if we fail.

### Custom Username Wordlist

We should also consider creating a personalized username wordlist based on the person's available details. For example, the person's username could be `b.gates` or `gates` or `bill`, and many other potential variations. There are several methods to create the list of potential usernames, the most basic of which is simply writing it manually.

One such tool we can use is [Username Anarchy](https://github.com/urbanadventurer/username-anarchy), which we can clone from GitHub, as follows:
```shell-session
$ git clone https://github.com/urbanadventurer/username-anarchy.git
```

In the simplest use we can just provide the first/last names as arguments:
```bash
./username-anarchy Bill Gates > bill.txt
```

## Service Authentication Brute Forcing

Check for open ports locally:
```shell-session
$ netstat -antp | grep -i list
```

Note 1: Sometimes administrators test their security measures and policies with different tools. In case, the administrator of this web server kept "hydra" installed. We can benefit from it and use it against the local system by attacking the FTP service locally or remotely.

Note 2: "rockyou-10.txt" can be found in "/opt/useful/SecLists/Passwords/Leaked-Databases/rockyou-10.txt", which contains 92 passwords in total. This is a shorter version of "rockyou.txt" which includes 14,344,391 passwords.

```shell-session
$ hydra -L <username list> -P <password list> -u -f <service>://<ip address>:<port> -t <number of concurrent threads>
```

With SSH it's recommended to use 4 threads, since it commonly limits the number of parallel connections and drop other connections.