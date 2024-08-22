## Intercepting Web Requests

We can click on this button to turn the Request Interception on or off, or we can use the shortcut [`CTRL+B`] to toggle it on or off:
![[zap_intercept_htb_on.jpg]]

ZAP also has a powerful feature called `Heads Up Display (HUD)`, which allows us to control most of the main ZAP features from right within the pre-configured browser:
![[zap_enable_HUD.jpg]]

## Intercepting Responses

when our requests are intercepted by ZAP, we can click on `Step`, and it will send the request and automatically intercept the response.

While in many instances we may need to intercept the response to make custom changes, if all we wanted was to enable disabled input fields or show hidden input fields, then we can click on the third button on the left (the light bulb icon), and it will enable/show these fields without us having to intercept the response or refresh the page.

Another similar feature is the `Comments` button, which will indicate the positions where there are HTML comments that are usually only visible in the source code. We can click on the `+` button on the left pane and select `Comments` to add the `Comments` button, and once we click on it, the `Comments` indicators should be shown.

## Automatic Request Modification

### ZAP Replacer

ZAP has a feature called `Replacer`, which we can access by pressing [`CTRL+R`] or clicking on `Replacer` in ZAP's options menu:
![[zap_match_replace_user_agent_1.jpg]]

ZAP also has the `Request Header String` that we can use with a Regex pattern.

ZAP also provides the option to set the `Initiators`, which we can access by clicking on the other tab in the windows shown above. Initiators enable us to select where our `Replacer` option will be applied. We will keep the default option of `Apply to all HTTP(S) messages` to apply everywhere.

## ZAP Fuzzer

right-click on a request and then selecting (`Attack>Fuzz`), will open the `Fuzzer` window.

### Payloads

We can select from 8 different payload types. The following are some of them:

- `File`: This allows us to select a payload wordlist from a file.
- `File Fuzzers`: This allows us to select wordlists from built-in databases of wordlists.
- `Numberzz`: Generates sequences of numbers with custom increments.

One of the advantages of ZAP Fuzzer is having built-in wordlists we can choose from with the second option so that we do not have to provide our own wordlist.

### Processors

We may also want to perform some processing on each word in our payload wordlist. The following are some of the payload processors we can use:

- Base64 Decode/Encode
- MD5 Hash
- Postfix String
- Prefix String
- SHA-1/256/512 Hash
- URL Decode/Encode
- Script

### Options

Depth first: attempt all words from the wordlist on a single payload position before moving to the next.

breadth first: run every word from the wordlist on all payload positions before moving to the next word.

