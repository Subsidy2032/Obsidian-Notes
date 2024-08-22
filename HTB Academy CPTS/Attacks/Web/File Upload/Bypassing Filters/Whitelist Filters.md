A whitelist is generally more secure than a blacklist. The web server would only allow the specified extensions, and the list would not need to be comprehensive in covering uncommon extensions.

A blacklist may be helpful in cases where the upload functionality needs to allow a wide variety of file types, while a whitelist is usually only used with upload functionalities where only a few file types are allowed. Both may also be used in tandem.

## Whitelisting Extensions

If we try to fuzz for other variations of PHP extensions (e.g. `php5`, `php7`, `phtml`), and the web server uses whitelisting, non of them should be successful.

The following is an example of a file extension whitelist test:
```php
$fileName = basename($_FILES["uploadFile"]["name"]);

if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

The issue with this code is the `regex`, which only checks if the file name `contains` the extension, and not if it's actually ends with it. Many developers make such mistakes due to a weak understanding of regex patterns.

## Double Extensions

A straightforward method of bypassing the regex test is through double extensions. We can add the allowed extension to the file name, and still end it with `.php` (e.g. `shell.jpg.php`).

Let's intercept a normal upload request, and modify the file name to (`shell.jpg.php`), and modify its content to that of a web shell:
![[file_uploads_double_ext_request.jpg]]

Now we should successfully execute commands, when visiting the uploaded file.

However, this may not always work, as some web applications may use a strict `regex` pattern, as mentioned earlier, like the following:
```php
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) { ...SNIP... }
```

Most exploitation techniques to bypass this pattern rely on misconfigurations or outdated systems.

## Reverse Double Extension

In some cases, the file upload functionality will not be vulnerable, but the web server configuration may lead to a vulnerability. For example, an organization may use an open-source web application, which has a file upload functionality. Even if it has a strict regex pattern that only matches the final extension in the file name, the organization may use the insecure configurations for the web server.

For example, the `/etc/apache2/mods-enabled/php7.4.conf` for the `Apache2` web server may include the following configuration:
```xml
<FilesMatch ".+\.ph(ar|p|tml)">
    SetHandler application/x-httpd-php
</FilesMatch>
```

This is how the web server determines which files to allow PHP code execution (whitelisting). But again it doesn't end with an (`$`), so any file that contains the above extensions will be allowed PHP code execution. For example, the file name (`shell.php.jpg`) should pass the earlier whitelist test as it ends with (`.jpg`), and it would be able to execute PHP code due to the above misconfiguration, as it contains (`.php`) in its name.

Let's try to intercept a normal image upload request, and use the above file name to pass the strict whitelist test:
![[file_uploads_reverse_double_ext_request.jpg]]

Now, we can visit the uploaded file, and attempt to execute a command.

## Character Injection

We can inject several characters before or after the final extension to cause the web application to misinterpret the filename and execute the uploaded file as a PHP script.

The following are some of the characters we may try injecting:

- `%20`
- `%0a`
- `%00`
- `%0d0a`
- `/`
- `.\`
- `.`
- `…`
- `:`

Each character has a specific use case that may trick the web application to misinterpret the file extension. For example, (`shell.php%00.jpg`) works with PHP servers with version `5.X` or earlier, as it causes the PHP web server to end the file name after the (`%00`), and store it as (`shell.php`), while still passing the whitelist. The same may be used with web applications hosted on a Windows server by injecting a colon (`:`) before the allowed file extension (e.g. `shell.aspx:.jpg`), which should also write the file as (`shell.aspx`).

We can write a small bash script that generates all permutations of the file name, where the above characters would be injected before and after both the `PHP` and `JPG` extensions, as follows:
```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```

With this custom wordlist, we can run a fuzzing scan with `Burp Intruder`.