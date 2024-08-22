GitHub [SecLists](https://github.com/danielmiessler/SecLists) repository is useful for fuzzing.

# Fuzzing

## Directory Fuzzing

```shell-session
ffuf -w <wordlist>:FUZZ -u http://<url or ip>/FUZZ
```

## Page Fuzzing

Find out the extension of web pages
```shell-session
Wildland4958@htb[/htb]$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://<url or ip>/<directory>/indexFUZZ
```

Fuzz for PHP pages:
```shell-session
ffuf -w <wordlist>:FUZZ -u http://<url or ip>/<directory>/FUZZ.php
```

## Recursive Fuzzing

-v is to output the full URL:
```shell-session
ffuf -w <wordlist>:FUZZ -u http://<url or ip>/FUZZ -recursion -recursion-depth <depth th fuzz> -e .<extension to search for> -v
```

## Sub-domain Fuzzing

Will find only public DNS records:
```shell-session
Wildland4958@htb[/htb]$ ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.<domain>/
```

## Vhost Fuzzing

VHost is a sub-domain in the same server with the same IP address.

```shell-session
Wildland4958@htb[/htb]$ ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://<domain>/ -H 'Host: FUZZ.<domain>'
```

The page size will be different in case of found VHosts.

## Filtering Results

Example filtering to filter out results with size of 900:
```shell-session
Wildland4958@htb[/htb]$ ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://<domain>:PORT/ -H 'Host: FUZZ.<domain>' -fs 900
```

## Parameter Fuzzing

### GET Request Fuzzing

```shell-session
Wildland4958@htb[/htb]$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://<url>?FUZZ=<key> -fs <response size to filter>
```

### POST Request Fuzzing

```shell-session
Wildland4958@htb[/htb]$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://<url> -X POST -d 'FUZZ=<key>' -H 'Content-Type: application/x-www-form-urlencoded (in case of php)' -fs <response size to filter>
```

### Value Fuzzing

Example for creating a useful wordlist for ids:
```shell-session
Wildland4958@htb[/htb]$ for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

```shell-session
Wildland4958@htb[/htb]$ ffuf -w <wordlist>:FUZZ -u <url> -X POST -d '<parameter>=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded (in case of php)' -fs <response size to filter>
```