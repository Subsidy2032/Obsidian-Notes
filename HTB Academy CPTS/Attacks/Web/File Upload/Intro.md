File upload vulnerabilities are amongst the most common vulnerabilities found in web and mobile applications, as we can see in the latest [CVE Reports](https://www.cvedetails.com/vulnerability-list/cweid-434/vulnerabilities.html). We will also notice that most of these vulnerabilities are scored as `High` or `Critical` vulnerabilities, showing the level of risk caused by insecure file upload.

## Types of File Upload Attacks

The most common reason behind file upload vulnerability is weak file validation and verification. The worst kind of file upload vulnerability is `unauthenticated arbitrary file upload` vulnerability. Which means the application allows any unauthenticated user to upload any file type, it might as well let any user to execute code on the back-end server.

Many web developers employ various types of tests to validate the extension or content of the file. However, if these filters aren't secure, we may be able to bypass them.

The most common and critical attack caused by arbitrary file upload is `gaining remote command execution` over the back-end server with a web shell or a script that sends a reverse shell.

In some cases we may be able to upload only a specific file type. Even in these cases, we may be able to exploit the functionality if certain security protections were missing from the web application.

Example of these attacks include:

- Introducing other vulnerabilities like `XSS` or `XXE`.
- Causing a `Denial of Service (DoS)` on the back-end server.
- Overwriting critical system files and configurations.
- And many others.

Finally, a file upload vulnerability isn't only caused by writing insecure functions but is also often caused by the use of outdated libraries that may be vulnerable to those attacks.