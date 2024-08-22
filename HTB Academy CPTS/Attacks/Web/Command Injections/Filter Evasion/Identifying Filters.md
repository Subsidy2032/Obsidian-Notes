One type of injection mitigation is utilizing blacklisted characters and words on the back-end to detect and deny injection attempts. Yet another layer above it is utilizing Web Application Firewall (WAF), which may have broader scope and various methods of detecting various injection attack types.

## Filter/WAF Detection

Now the Host Checker application has a few mitigations up its sleeve. We can see that if we try the previous operators we tested, like (`;`, `&&`, `||`), we get the error message `invalid input`:
![[cmdinj_filters_1.jpg]]

The error message is in the field where the output is displayed, meaning that it was detected and prevented by the PHP web application itself. `If the error message displayed a different page, with information like our IP and our request, this may indicate that it was denied by a WAF`.

Other than the IP (which we know is not blacklisted), we sent:

1. A semi-colon character `;`
2. A space character
3. A `whoami` command

So, the web application either `detected a blacklisted character` or `detected a blacklisted command`, or both.

## Blacklisted Characters

Here is an example PHP code, to deny requests that contains characters from a blacklist:
```php
$blacklist = ['&', '|', ';', ...SNIP...];
foreach ($blacklist as $character) {
    if (strpos($_POST['ip'], $character) !== false) {
        echo "Invalid input";
    }
}
```

## Identifying Blacklisted Character

let us start by adding the semi-colon (`127.0.0.1;`):
![[cmdinj_filters_2.jpg]]

We still get `Invalid input`, we can try it with other characters to see if we don't get the message for one of them.