The `HTTP` protocol works by accepting various HTTP methods as `verbs` at the beginning of an HTTP request, based on the web server's configuration.

While the two most common methods are `GET` and `POST`, any client can send any other method in their HTTP request. In case both the web application and the back-end web server are configured to only accept `GET` and `POST` requests. Sending a different request will cause a web server error page to be displayed, which is not a severe vulnerability in itself (other than providing a bad user experience and potentially leading to information disclosure). Otherwise if the web server configuration are not restricted to only the required methods, and the web application isn't developed to handle other types of HTTP requests (e.g. `HEAD`, `PUT`), then we may be able to exploit this insecure configuration to gain access to functionalities we don't have access to, or even bypass certain security controls.

## HTTP Verb Tampering

HTTP has [9 different verbs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods) that can be accepted as HTTP methods by web servers. Other than `GET` and `POST`, the following are some of the commonly used HTTP verbs:

|Verb|Description|
|---|---|
|`HEAD`|Identical to a GET request, but its response only contains the `headers`, without the response body|
|`PUT`|Writes the request payload to the specified location|
|`DELETE`|Deletes the resource at the specified location|
|`OPTIONS`|Shows different options accepted by a web server, like accepted HTTP verbs|
|`PATCH`|Apply partial modifications to the resource at the specified location|

What makes HTTP Verb Tampering attacks more common (and hence more critical), is that they are caused by a misconfiguration in either the back-end web server or the web application, either of which can cause the vulnerability.

## Insecure Configurations

The first type of HTTP Verb Tampering vulnerability is caused by insecure web server configurations. A web server's authentication may be limited to specific HTTP methods, leaving others accessible without authentication. For example, a system admin may use the following configuration to require authentication on a particular web page:
```xml
<Limit GET POST>
    Require valid-user
</Limit>
```

With can use an HTTP method other then `GET` and `POST` to bypass the authentication mechanism altogether.

## Insecure Coding

Insecure coding practices cause the other type of HTTP Verb Tampering vulnerabilities (though some may not consider this Verb Tampering). This can occur when a web developer applies specific filters to mitigate particular vulnerabilities while not covering all HTTP methods with that filter. For example, if a web page was found to be vulnerable to a SQL Injection vulnerability, and the back-end developer mitigated the SQL Injection vulnerability by the following applying input sanitization filters:
```php
$pattern = "/^[A-Za-z\s]+$/";

if(preg_match($pattern, $_GET["code"])) {
    $query = "Select * from ports where port_code like '%" . $_REQUEST["code"] . "%'";
    ...SNIP...
}
```

This sanitization filter is only being tested on the `GET` parameter. However, when the query is executed, the `$_REQUEST[]"code"]` parameters are being used, which may also contain `POST` parameters, `leading to an inconsistency in the use of HTTP Verbs`. We can use a `POST` request to perform SQL injection, leaving the `GET` parameters empty (with no bad characters).

The second type of vulnerability is much more common, as it due to mistakes made in coding, while the first one is usually avoided by secure web server configurations, as documentation often cautions against it.