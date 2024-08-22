Exploiting HTTP Verb Tampering vulnerabilities is usually a relatively straightforward process. We just need to try alternate HTTP methods to see how they are handled by the web server and the web application. Automated vulnerability scanning tools consistently identify HTTP Verb Tampering vulnerabilities caused by insecure server configurations, but often miss those caused by insecure coding. This is because the first type can be easily identified once we bypass an authentication page, while the other needs active testing to see whether we can bypass the security filters in place.

## Identify

We have a file manager to which we can add new files:
![[web_attacks_verb_tampering_add.jpg]]

When clicking the `Reset` button, we see the functionality is restricted for authenticated users only:
![[web_attacks_verb_tampering_reset.jpg]]

We first need to see which pages are restricted, in this case `/admin/reset.php`. We can try visiting the `/admin` directory to see the directory is restricted, or only the `/admin/reset.php` page.

## Exploit

As the page uses a `GET` request, we can send a `POST` request to see whether the web page allows it:
![[web_attacks_verb_tampering_change_request.jpg]]

we still get prompted to log after clicking `Forward`:
![[web_attacks_verb_tampering_reset 1.jpg]]

We can try to use other methods, like the `HEAD` method, which is like `GET` request but returns only the headers. We may not get any output, but the `reset` function should still get executed, which is our main target.

To see whether the server accepts `HEAD` requests, we can send an `OPTIONS` request to it and see what HTTP methods are accepted, as follows:
```shell-session
$ curl -i -X OPTIONS http://SERVER_IP:PORT/

HTTP/1.1 200 OK
Date: 
Server: Apache/2.4.41 (Ubuntu)
Allow: POST,OPTIONS,HEAD,GET
Content-Length: 0
Content-Type: httpd/unix-directory
```

Lets try to use a `HEAD` request now, and see how the web server handles it:
![[web_attacks_verb_tampering_HEAD_request.jpg]]

After clicking `Forward` we no longer get a login prompt, in the main page we can see the files have been deleted, which means the `Reset` functionality is triggered.