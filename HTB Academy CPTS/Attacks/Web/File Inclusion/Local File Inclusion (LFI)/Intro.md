Used in dynamic pages when parameters are used to specify which resource is shown in the page, can be abused to display the local file on the hosting server.

Mostly found on templating engines, which shows common static parts on all the web pages and only some dynamic parts, for example `/index.php?page=about`.

Some functions will only read the files while some will execute them, Furthermore, some of them allow specifying remote URLs, while others only work with files local to the back-end server.

# Vulnerable code examples

## PHP

```php
if (isset($_GET['language'])) {
    include($_GET['language']);
}
```

The language parameter is directly passed to include, so any path specified will be displayed on the page.

Some other vulnerable functions: `include_once()`, `require()`, `require_once()`, `file_get_contents()`.

## NodeJS

```javascript
if(req.query.language) {
    fs.readFile(path.join(__dirname, req.query.language), function (err, data) {
        res.write(data);
    });
}
```

Parameters passed with the URL will be displayed in the response.

Another example with the render() function which is used to determine which directory it should pull the `about.html` page from:
```js
app.get("/about/:language", function(req, res) {
    res.render(`/${req.params.language}/about.html`);
});
```

In this example the render() function takes the parameter directly from the url path and not a get parameter.

## Java

```jsp
<c:if test="${not empty param.language}">
    <jsp:include file="<%= request.getParameter('language') %>" />
</c:if>
```

The include function may take a file or a URL as its argument, then it will render the object into the front-end templates.

The import function may also be used for this:
```jsp
<c:import url= "<%= request.getParameter('language') %>"/>
```

## .NET

The path may be retrieved from a GET parameter for dynamic content loading:
```cs
@if (!string.IsNullOrEmpty(HttpContext.Request.Query['language'])) {
    <% Response.WriteFile("<% HttpContext.Request.Query['language'] %>"); %> 
}
```

Used to specify the file as part of the front-end template:
```cs
@Html.Partial(HttpContext.Request.Query['language'])
```

To render local files or remote URLs, and may also execute them:
```cs
<!--#include file="<% HttpContext.Request.Query['language'] %>"-->
```

## Read vs Execute

| **Function**                 | **Read Content** | **Execute** | **Remote URL** |
| ---------------------------- | :--------------: | :---------: | :------------: |
| **PHP**                      |                  |             |                |
| `include()`/`include_once()` |        ✅         |      ✅      |       ✅        |
| `require()`/`require_once()` |        ✅         |      ✅      |       ❌        |
| `file_get_contents()`        |        ✅         |      ❌      |       ✅        |
| `fopen()`/`file()`           |        ✅         |      ❌      |       ❌        |
| **NodeJS**                   |                  |             |                |
| `fs.readFile()`              |        ✅         |      ❌      |       ❌        |
| `fs.sendFile()`              |        ✅         |      ❌      |       ❌        |
| `res.render()`               |        ✅         |      ✅      |       ❌        |
| **Java**                     |                  |             |                |
| `include`                    |        ✅         |      ❌      |       ❌        |
| `import`                     |        ✅         |      ✅      |       ✅        |
| **.NET**                     |                  |             |                |
| `@Html.Partial()`            |        ✅         |      ❌      |       ❌        |
| `@Html.RemotePartial()`      |        ✅         |      ❌      |       ✅        |
| `Response.WriteFile()`       |        ✅         |      ❌      |       ❌        |
| `include`                    |        ✅         |      ✅      |       ✅        |