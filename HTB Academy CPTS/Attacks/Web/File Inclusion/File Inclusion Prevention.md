## File Inclusion Prevention

The most effective way to protect is to avoid passing any user-controlled inputs into any file inclusion functions or APIs. The server should dynamically load assets on the back-end without user interaction. We should generally consider each function that can read files.

In case it's not possible we should whitelist allowed user inputs and match each input to the file to be loaded, with a default value to all other inputs. If we are dealing with an existing web application, we can create a whitelist that contains all existing paths used in the front-end, and then utilize this list to match the user input. Such a whitelist can have many shapes, like a database table that matches IDs to files, a `case-match` script that matches names to files, or even a static json map with names and files that can be matched.

## Preventing Directory Traversal

The best way to prevent directory traversal is to use a function like `basename()` in PHP, which will read the path and only return the filename portion, the downside is that if the application will need to enter any other directories it will not be able to do so.

If we write are own functions to account for this problems, it can be hard to count for edge cases.

Example to recursively remove `../`:
```php
while(substr_count($input, '../', 0)) {
    $input = str_replace('../', '', $input);
};
```

## Web Server Configuration

We should globally disable the inclusion of remote files, In PHP this can be done by setting `allow_url_fopen` and `allow_url_include` to Off.

It's often possible to lock the websites to their web root directory, the best way is using a docker but if it's not an option some programming languages allowing to do this, for example by adding `open_basedir = /var/www` in php.ini file, certain potentially dangerous modules should also be disabled.

## Web Application Firewall (WAF)

WAF such as `ModSecurity` is a good way of protecting web applications in general, ModSecurity can minimize false positives with permissive mode which will only report things it would have blocked.