## Automated Discovery

Almost all Web Application Vulnerability Scanners (like [Nessus](https://www.tenable.com/products/nessus), [Burp Pro](https://portswigger.net/burp/pro), or [ZAP](https://www.zaproxy.org/)) have various capabilities for detecting all three types of XSS vulnerabilities. Usually they do two types of scanning: A passive scan, which reviews the client-side code for a potential DOM-based vulnerabilities, and an active scan, which actively injects XSS payloads to the page source and attempt to trigger XSS.

Tools to detect XSS vulnerabilities usually work by identifying input fields, sending various types of XSS payloads, and then comparing the rendered page source to see if the same payload can be found in it. This is not always accurate, since the payload can still not lead to a successful execution due to various reasons, so we must always do a manual check.

Some of the common open-source tools that can assist us in XSS discovery are [XSS Strike](https://github.com/s0md3v/XSStrike), [Brute XSS](https://github.com/rajeshmajumdar/BruteXSS), and [XSSer](https://github.com/epsylon/xsser). We can try `XSS Strike` by cloning it to our VM with `git clone`:
```shell-session
$ git clone https://github.com/s0md3v/XSStrike.git
$ cd XSStrike
$ pip install -r requirements.txt
$ python xsstrike.py

XSStrike v3.1.4
...SNIP...
```

We can then run the script and provide it a URL with a parameter using `-u`:
```shell-session
$ python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test" 
```

## Manual Discovery

Basic XSS vulnerabilities can usually be found through testing various XSS payloads, but identifying advanced XSS vulnerabilities requires advanced code review skills.

### XSS Payloads

We can find a huge list of payloads to try online, like the one on [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md) or the one in [PayloadBox](https://github.com/payloadbox/xss-payload-list). We can try them manually one by one.

Note: XSS can be injected into any input in the HTML page, which is not exclusive to HTML input fields, but may also be in HTTP headers like the Cookie or User-Agent (i.e., when their values are displayed on the page).

Those payloads are made to work with a certain types of injection, so even for the most basic XSS vulnerability, most of them wouldn't work.

This is why it's more efficient to write a Python script to automate sending those payloads and then comparing the page source to see how our payloads were rendered. This is helpful in advanced cases where XSS tools cannot easily send and compare payloads.

## Code Review

Reviewing both the front-end and the back-end code can help us understand how the input is being handled. We then can write a custom payload that should work with high confidence.

We are unlikely to find any XSS vulnerabilities through payload lists or XSS tools for the more common web applications. This is because the developers of such web applications likely run their application through vulnerability assessment tools and then patch any identified vulnerabilities before release. For such cases, manual code review may reveal undetected XSS vulnerabilities, which may survive public releases of common web applications. These are also advanced techniques that are out of the scope of this module. Still, if you are interested in learning them, the [Secure Coding 101: JavaScript](https://academy.hackthebox.com/course/preview/secure-coding-101-javascript) and the [Whitebox Pentesting 101: Command Injection](https://academy.hackthebox.com/course/preview/whitebox-pentesting-101-command-injection) modules thoroughly cover this topic.