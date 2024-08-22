#Networking 

## URL(Uniform resource Locator):
Example URL: ![[34ad66d8b90aaaa35f9536d3b152ea97.png]]

Scheme: The protocol to use

User: If the service requires authentication

Host/Domain: The domain name or IP address

Port: The port to connect to

Path: The location of the resource or file name

Query String: Extra information added to the requested path

Fragment: Location required on the actual page

## Making a request:

```http
GET / HTTP/1.1
Host: tryhackme.com
User-Agent: Mozilla/5.0 Firefox/87.0
Referer: https://tryhackme.com/
```

Line 1: A request of the home page using HTTP protocol version 1.1

Line 2: The website we want

Line 3: Telling the web server we are using Firefox version 87

Line 4: The web server that referred us to this one

Line 5: Requests always end with a blank line to inform the web server the request has finished

#### Methods:
GET Request: Getting information from the web server

POST Request: Submitting data to the web server and potentially making new records

PUT Request: Submitting data to the web server to update information

DELETE Request: Deleting information/records from the web server

## Response:

```http

HTTP/1.1 200 OK
Server: nginx/1.15.8
Date: Fri, 09 Apr 2021 13:34:03 GMT
Content-Type: text/html
Content-Length: 98

<html>
<head>
    <title>TryHackMe</title>
</head>
<body>
    Welcome To TryHackMe.com
</body>
</html>
```

Line 1: The server is using HTTP protocol version 1.1 and returned a response code of 200 OK

Line 2: The webserver software and version number

Line 3: The current date, time and time zone of the server

Line 4: What sort of information is gonna be sent

Line 5: The length of the response

Line 6: Blank line to confirm the end of the HTTP response

Line 7-14: The information that has been requested

## Status codes:
<u> **100-199 - Information Response** </u>
When the first part of the request is accepted and the server should continue sending the client the rest of the request

<u>**200-299 - Success**</u>
The request was successful

<u>**300-399 - Redirection**</u>
Redirecting the client's request to another resource, could be a different webpage or different website

<u>**400-499 - Client Errors**</u>
There is an error with the request

<u>**500-599 - Server Errors**</u>
Error on the server side, usually indicating quite major problem with the server handling the request

### Common HTTP status codes:
**200 - OK** - The request was completed successfully

**201 - Created** - A resource has been created

**301 - Permanent Redirect** - Redirects the client's browser to a new webpage or tells the browser that the webpage has been moved somewhere else

**302 - Temporary Redirect** - Only a temporary a change and may change again in the near future

**400 - Bad Request** - When something is either wrong or missing in the request

**401 - Not Authorized** - You are not currently allowed to see this resource until you authorized with the web application, most commonly with a username and password

**403 - Forbidden** - You don't have permission to view this resource whether you are logged in or not

**405 - Method Not Allowed** - The resource does not allow this method request, for example when the server is expecting another method

**404 - Page Not Found** - The page/resource does not exist

**500 - Internal Service Error** - The server encountered an error with your request that it doesn't know how to encounter properly

**503 - Service Unavailable** - The server can't handle your request because it's overloaded or down for maintenance

## Headers:

### <u>Common Request Headers: </u>

**Host** - The website you want, you will get the default one if this header isn't added

**User-Agent** - Telling the web server the browser software and version, helps format the website properly for your web browser and some HTML, CSS and JavaScript elements are only available in certain browsers

**Content-length** - Amount of data to expect in the web request, so the server can ensure it's not missing data

**Accept-Encoding** - Types of compression the browser supports, so the data can be made smaller for transmitting over the internet

**Cookie** - To help remember you information

### <u>Common Response Headers: </u>

**Set-Cookie** - Information to store that gets sent back to the server on each request

**Cache-Control** - For how long to store the content of the response in the browser's cache until it requests it again

**Content-Type** - Tells the client which type of data is being returned, this way the browser knows how to process the data

**Content-Encoding** - What method is used to compress the data