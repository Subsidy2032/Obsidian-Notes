if the type validation controls on the back-end server were not securely coded, an attacker can utilize multiple techniques to bypass them and reach PHP file uploads.

## Blacklisting Extensions

An application may have some form of file type validation on the back-end, in addition to the front-end validations.

There are generally tow common forms of validating a file extension on the back-end:

1. Testing against a `blacklist` of types
2. Testing against a `whitelist` of types

The validation may also check the `file type` or the `file content`. `Testing the file extension against a blacklist of extension` is the weakest form of validation. For example, the following piece of code checks if the uploaded file extension is `PHP` and drops the request if it is:
```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$extension = pathinfo($fileName, PATHINFO_EXTENSION);
$blacklist = array('php', 'php7', 'phps');

if (in_array($extension, $blacklist)) {
    echo "File type not allowed";
    die();
}
```

The code is taking the file extension (`$extension`) from the uploaded file name (`$fileName`) and then comparing it against a list of blacklisted extensions (`$blacklist`). However, the list isn't comprehensive, there are many other extension that can be used to execute PHP code on the back-end.

**Tip:** The comparison above is also case-sensitive, and is only considering lowercase extensions. In Windows Servers, file names are case insensitive, so we may try uploading a `php` with a mixed-case (e.g. `pHp`), which may bypass the blacklist as well, and should still execute as a PHP script.

## Fuzzing Extensions

We can fuzz the upload functionality with a list of extensions and see which of them returns an error message. Any upload requests that do not return an error message, return a different message, or succeed in uploading the file, may indicate an allowed file extension.

`PayloadsAllTheThings` provides lists of extensions for [PHP](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) and [.NET](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP) web applications. We may also use `SecLists` list of common [Web Extensions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt).

![[file_uploads_burp_fuzz_extension.jpg]]

We will also un-tick the `URL Encoding` option to avoid encoding the (`.`) before the file extension.

![[file_uploads_burp_intruder_result.jpg]]

We can sort the results by `Length`, and we will see that all requests with the Content-Length (`193`) passed the extension validation, as they all responded with `File successfully uploaded`. In contrast, the rest responded with an error message saying `Extension not allowed`.

## Non-Blacklisted Extensions

We may need to try several extensions to get one that executes PHP code. `Not all extensions will work with all web server configurations`.

`.phtml` extension is often allowed for code execution rights in PHP web servers. We can now send the request to the repeater, change the file name to use the extension we want, and change the content to that of a PHP web shell.

![[file_uploads_php5_web_shell.jpg]]

The final step is to visit our upload file.