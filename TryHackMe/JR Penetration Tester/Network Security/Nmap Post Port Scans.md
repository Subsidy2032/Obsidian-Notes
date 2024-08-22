## Service Detection

The `-sV` option will force Nmap to complete the 3 way handshake hence the `-sS` option isn't possible with the `-sV` option.

## OS Detection and Traceroute

The OS detection can be wrong a lot of the times, for example because there are no open ports or because of the use of virtualization.

Contrary to the `traceroute` command the `--traceroute` option in Nmap will start with a high TTL value and decrease it from there, will not get an IP address from systems that configured to not response with ICMP Time-to-Live exceeded messages.

## Nmap Scripting Engine (NSE)

The NSE is a Lua interpreter which allows Nmap to run scripts written in the Lua language, scripts are pieces of code that don't need to be compiled.

`/usr/share/nmap/scripts` - Nmap scripts location.

Script categories:

|Script Category|Description|
|---|---|
|`auth`|Authentication related scripts|
|`broadcast`|Discover hosts by sending broadcast messages|
|`brute`|Performs brute-force password auditing against logins|
|`default`|Default scripts, same as `-sC`|
|`discovery`|Retrieve accessible information, such as database tables and DNS names|
|`dos`|Detects servers vulnerable to Denial of Service (DoS)|
|`exploit`|Attempts to exploit various vulnerable services|
|`external`|Checks using a third-party service, such as Geoplugin and Virustotal|
|`fuzzer`|Launch fuzzing attacks|
|`intrusive`|Intrusive scripts such as brute-force attacks and exploitation|
|`malware`|Scans for backdoors|
|`safe`|Safe scripts that won’t crash the target|
|`version`|Retrieve service versions|
|`vuln`|Checks for vulnerabilities or exploit vulnerable services|

`--script "<script name>"` - Specify script by name.
`--script "<The start of the name>*"` - Specify script by pattern.

You can also download scripts from the internet.

## Saving the Output

`-oN <file name>` - Save in normal format, same as what you see on the screen directly after the scan.

`-oG <file name>` - The grepable format has it's name from the grep (Global Regular Expression Printer) command, it makes filtering for keywords or terms efficient.

`-oX <file name>` - Save in XML format, it's the most convenient to process the output in other programs.

`-oA <file name>` - Save the output in all 3 major formats.

`-oS <file name>` - Script kiddie format, very bad not recommended.

## Summary

|Option|Meaning|
|---|---|
|`-sV`|determine service/version info on open ports|
|`-sV --version-light`|try the most likely probes (2)|
|`-sV --version-all`|try all available probes (9)|
|`-O`|detect OS|
|`--traceroute`|run traceroute to target|
|`--script=SCRIPTS`|Nmap scripts to run|
|`-sC` or `--script=default`|run default scripts|
|`-A`|equivalent to `-sV -O -sC --traceroute`|
|`-oN`|save output in normal format|
|`-oG`|save output in grepable format|
|`-oX`|save output in XML format|
|`-oA`|save output in normal, XML and Grepable formats|
