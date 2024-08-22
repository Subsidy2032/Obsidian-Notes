## Hydra Modules

To cause as little network traffic as possible, it is recommended to try the top 10 most popular administrators' credentials, such as `admin:admin`.

If none of these credentials grant us access, we could next resort to another widespread attack method called password spraying.

### List Supported Hydra Services
```shell-session
$ hydra -h | grep "Supported services" | tr ":" "\n" | tr " " "\n" | column -e
```

### Fail/Success String
|**Type**|**Boolean Value**|**Flag**|
|---|---|---|
|`Fail`|FALSE|`F=html_content`|
|`Success`|TRUE|`S=html_content`|

Sometimes we will not no what strings we have after logging in, and there also wouldn't be any error messages upon unsuccessful login. In this case we can use something like the login button which for sure wouldn't appear after logging in.

For example if there is the following line in the source code:
```html
<form name='login' autocomplete='off' class='form' action='' method='post'>
```

We can use this:
```bash
"/login.php:[user parameter]=^USER^&[password parameter]=^PASS^:F=<form name='login'"
```

### Login Form Attacks

If we attacks administration panels, we can first try usernames such as `admin`, `administrator`, `wpadmin`, `root`, `adm` for the brute force attacks.

```shell-session
$ hydra -l <username> -P <password list> -f <ip address> -s <port> http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```

