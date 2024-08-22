A command injection vulnerability allows to execute system commands directly on the back-end hosting server. If a web application uses user-controlled input to execute system command on the back-end server to retrieve and return specific output, we may be able to inject a malicious payload to subvert the intended command and execute our commands.

## What are Injections

Injection vulnerabilities are considered the number 3 risk in [OWASP's Top 10 Web App Risks](https://owasp.org/www-project-top-ten/), given their high impact and how common they are. Injection occurs when user-controlled input is misinterpreted as part of the web query or code being executed, which may lead to subverting the intended outcome of the query to a different outcome that is useful to the attacker.

Some of the most common types of injection:

|Injection|Description|
|---|---|
|OS Command Injection|Occurs when user input is directly used as part of an OS command.|
|Code Injection|Occurs when user input is directly within a function that evaluates code.|
|SQL Injections|Occurs when user input is directly used as part of an SQL query.|
|Cross-Site Scripting/HTML Injection|Occurs when exact user input is displayed on a web page.|

There are many other types of injections other than the above, like `LDAP injection`, `NoSQL Injection`, `HTTP Header Injection`, `XPath Injection`, `IMAP Injection`, `ORM Injection`, and others. Whenever user input is used within a query without being properly sanitized, it may be possible to escape the boundaries of the user input string to the parent query and manipulate it to change its intended purpose. This is why as more web technologies are introduced to web applications, we will see new types of injections introduced to web applications.

## OS Command Injections

When it comes to OS command injections, the user input we control must directly or indirectly go into (or somehow affect) a web query that executes system commands. There are different function for different programming languages to execute commands directly on the back-end server. It can be used for stuff like installing plugins or executing certain applications.

### PHP Example

For example, a web application written in `PHP` may use the `exec`, `system`, `shell_exec`, `passthru`, or `popen` functions to execute commands directly on the back-end server, each having a slightly different use case. The following code is an example of PHP code that is vulnerable to command injections:
```php
<?php
if (isset($_GET['filename'])) {
    system("touch /tmp/" . $_GET['filename'] . ".pdf");
}
?>
```

Here we have a functionality of creating a PDF file in the `/tmp` directory. However as the user input from the `filename` parameter is used directly with the touch command (without being sanitized or escaped first), the web application is vulnerable to OS command injection.

### NodeJS Example

With `NodeJS`, a developer may use `child_process.exec` or `child_process.spawn` for the same purpose. The following example performs a similar functionality to what we discussed above:
```javascript
app.get("/createfile", function(req, res){
    child_process.exec(`touch /tmp/${req.query.filename}.txt`);
})
```

Here the code is vulnerable to command injection as well, since there is no sanitization before using the parameter. Both `PHP` and `NodeJS` web applications can be exploited using the same command injection methods.

Command Injection vulnerabilities are not unique to web applications but can also affect other binaries and thick clients if they pass unsanitized user input to a function that executes system commands, which can also be exploited with the same command injection methods.