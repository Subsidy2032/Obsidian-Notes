## Intercepting Responses

we can enable response interception by going to (`Proxy>Options`) and enabling `Intercept Response` under `Intercept Server Responses`.

After that, we can enable request interception once more and refresh the page with [`CTRL+SHIFT+R`] in our browser (to force a full refresh). When we go back to Burp, we should see the intercepted request, and we can click on `forward`. Once we forward the request, we'll see our intercepted response.

To show all hidden fields or buttons. we can enable it under `Proxy>Options>Response Modification`, then select one of the options, like `Unhide hidden form fields`.

## Automatic Request Modification

### Burp Match and Replace

We can go to (`Proxy>Options>Match and Replace`) and click on `Add` in Burp. As the below screenshot shows, we will set the following options:
![[burp_match_replace_user_agent_1.jpg]]

|   |   |
|---|---|
|`Type`: `Request header`|Since the change we want to make will be in the request header and not in its body.|
|`Match`: `^User-Agent.*$`|The regex pattern that matches the entire line with `User-Agent` in it.|
|`Replace`: `User-Agent: HackTheBox Agent 1.0`|This is the value that will replace the line we matched above.|
|`Regex match`: True|We don't know the exact User-Agent string we want to replace, so we'll use regex to match any value that matches the pattern we specified above.|

Once we enter the above options and click `Ok`, our new Match and Replace option will be added and enabled and will start automatically replacing the `User-Agent` header in our requests with our new User-Agent.