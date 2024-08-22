Attacking external-facing web applications may result in compromise of the businesses' internal network, which may eventually lead to stolen assets or disrupted services. It may potentially cause a financial disaster for the company. Even if a company has no external facing web applications, they likely utilize internal web applications, or external facing API endpoints, both of which are vulnerable to the same types of attacks and can be leveraged to achieve the same goals.

Here we will cover three web attacks that can be found in any web application, which may lead to compromise.

## Web Attacks

### HTTP Verb Tampering

An [HTTP Verb Tampering](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering) exploits web servers that accept many HTTP verbs and methods. We can send malicious requests using unexpected methods, which may lead to bypassing the  web application's authorization mechanism or even bypassing its security controls against other web attacks. This is one of many other HTTP attacks that can be used to exploit web server configurations by sending malicious HTTP requests.

### Insecure Direct Object Reference (IDOR)

[Insecure Direct Object References (IDOR)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References) is among the most common web vulnerabilities and can lead to accessing data that should not be accessible by attackers. The lack of a solid access control system on the back-end makes this attack common. As web applications store users' files and information, they may use sequential numbers or user IDs to identify each item. Suppose the web application lacks a robust access control mechanism and exposes direct references to files and resources. In that case, we may access other users' files and information by simply guessing or calculating their file IDs.

### XML External Entity (XXE) Injection

Many web applications process XML data as part of their functionality. suppose a web application use outdated XML libraries to parse and process XML input data from the front-end user. It may be possible to send malicious XML data to disclose local files stored on the back-end server. These files may be configuration files, which can store sensitive information like passwords, and even the source code of the web application. [XML External Entity (XXE) Injection](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing) attacks can even be leveraged to steal the hosting server's credentials, which would compromise the entire server and allow for remote code execution.