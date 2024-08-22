The other and more common type of HTTP Verb Tampering vulnerability is caused by `Insecure Coding` errors made during the development of the web application.

## Identify

In the `File Manager` web application, if we try to create a new file name with special characters in its name (e.g. `test;`), we get the following message:
![[web_attacks_verb_malicious_request.jpg]]

It confirms the web application uses filters to identify and block injection attempts. With HTTP Verb Tampering we might be able to bypass the security filter altogether.

## Exploit

Let's try to change the request method to `GET`:
![[web_attacks_verb_tampering_GET_request.jpg]]

This time, we did not get the `Malicious Request Denied!` message, and our file was successfully created:
![[web_attacks_verb_tampering_injected_request.jpg]]

Lets try injecting a command to confirm we bypassed the security filter (`file1; touch file2;`):
![[web_attacks_verb_tampering_filter_bypass.jpg]]

Then we will use Burp to replace the method to `GET` again.

Once we send our request, we see that this time both `file1` and `file2` were created:
![[web_attacks_verb_tampering_after_filter_bypass.jpg]]
