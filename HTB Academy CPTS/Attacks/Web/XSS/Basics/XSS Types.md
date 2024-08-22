## Stored XSS

`Stored XSS` or `Persistent XSS` is the most critical type of XSS vulnerability. This is a persistent attack the get stored in the back-end database.

Any user that visits the page will be the victim of the attack. Furthermore, stored XSS may need be easily removable, and the payload may need removing from the back-end database.

If we have an input field with the input being displayed on the page, we can look for XSS vulnerability.

### XSS Testing Payloads

We can test whether the page is vulnerable to XSS with the following basic XSS payload:
```html
<script>alert(window.origin)</script>
```

![[xss_stored_xss_alert.jpg]]

If the website is vulnerable the alert would pop, and we should see our payload in the source code.
```html
<div></div><ul class="list-unstyled" id="todo"><ul><script>alert(window.origin)</script>
</ul></ul>
```

**Tip:** Many modern web applications utilize cross-domain IFrames to handle user input, so that even if the web form is vulnerable to XSS, it would not be a vulnerability on the main web application. This is why we are showing the value of `window.origin` in the alert box, instead of a static value like `1`. In this case, the alert box would reveal the URL it is being executed on, and will confirm which form is the vulnerable one, in case an IFrame was being used.

Some modern web browser may block the `alert()` JavaScript function in specific locations. One other XSS payload to try is `<plaintext>`, which will stop rendering the HTML code that comes after it and display it as plain text. Another easy-to-spot payload is `<script>print()</script>` that will pop up the browser print dialog, which is unlikely to be blocked by any browsers.

If upon refreshing the page, we keep getting the alert, it confirms a `Stored/Persistent XSS` vulnerability. Any user who visits the page will trigger the XSS payload as well.

## Reflected XSS

Reflected XSS is Non-Persistent XSS vulnerability, which gets processed by the backend server. Non-persistent XSS vulnerabilities are temporary and are not persistent through page refreshes. So only the target use is effected, and no other users.

Reflected XSS vulnerabilities occur when our input reaches the back-end server and gets returned to us without being filtered or sanitized. In many cases (like error messages or confirmation messages) our entire input might get returned to us. We can attempt to use XSS payloads to see whether they execute. Usually those are temporary messages.

For example here the input returns to us as part of the error message:
![[xss_reflected_1.jpg]]

Here is what the source code will look like, after injecting `<script>alert(window.origin)</script>`:
```html
<div></div><ul class="list-unstyled" id="todo"><div style="padding-left:25px">Task '<script>alert(window.origin)</script>' could not be added.</div></ul>
```

Since our payload is wrapped with a `<script>` tag it will not be rendered by the browser.

To target our victim with this non-persistent technique, we could copy the URL (if it's a GET request) and send it to the victim.

## DOM XSS

DOM XSS is also Non-Persistent XSS vulnerability, and is completely processed on the client-side through JavaScript. It occurs when JavaScript is used to change the page source through the Document Object Model (DOM).

Example:
![[xss_dom_1.jpg]]

Looking at the `Network` tab in the Firefox Developer Tools, we would notice that no HTTP requests are being made when clicking add.

We see that the input parameter in the URL is using a hashtag `#` for the item we added, which means that this is a client side parameter that is completely processed on the browser. It never reaches the backend.

Furthermore, we will not be able to find our `test` string anywhere in the page source. The reason is that JavaScript code is updating the page when we click the add button, which is after the page source is retrieved by our browser, and if we refresh the page it will not be retained. We can still view the rendered page source with the Web Inspector tool by clicking [`CTRL+SHIFT+C`]:
![[xss_dom_inspector.jpg]]

### Source & Sink

Let's understand the difference between the source and the sink of the object displayed on the page. The source is the JavaScript object that takes the user input, and it can be any input parameter or field.

The sink is the function that writes the user input to a DOM object on the page. If the sink function doesn't properly sanitize user input, it would be vulnerable to XSS attack. Some of the commonly used JavaScript functions to write to DOM objects are:

- `document.write()`
- `DOM.innerHTML`
- `DOM.outerHTML`

Furthermore, some of the `jQuery` library functions that write to DOM objects are:

- `add()`
- `after()`
- `append()`

We can look at the source code of the above page, the source is being taken from the `task=` parameter:
```javascript
var pos = document.URL.indexOf("task=");
var task = document.URL.substring(pos + 5, document.URL.length);
```

The page uses innerHTML function to write the task variable in the `todo` DOM:
```javascript
document.getElementById("todo").innerHTML = "<b>Next Task:</b> " + decodeURIComponent(task);
```

### DOM Attacks

The `innerHTML` function does not allow the use of `<script>` tags within it as a security feature. Still we can use many other XSS payloads, like the following:
```html
<img src="" onerror=alert(window.origin)>
```

The image will not be found, thus the value of `onerror` will be executed.

To target a user with this vulnerability, we can copy the URL and share it with them, upon visit the JavaScript code should get executed. We may need to use various payloads depending on the security of the web application and the browser.