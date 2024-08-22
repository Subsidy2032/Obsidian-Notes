Even dealing with a limited (i.e., non-arbitrary) file upload form, which only allows us to upload specific file types, we may still be able to perform some attacks on the web application.

Certain file types, like `SVG`, `HTML`, `XML`, and even some image and document files, may allow us to introduce new vulnerabilities to the web application by uploading malicious versions of these files. This is why fuzzing allowed file extensions is an important exercise for any file upload attack. It enables us to explore what attacks may be achievable on the web server.

## XSS

Many file types may allow us to introduce a `Stored XSS` vulnerability by uploading maliciously crafted versions of them.

For example if we can upload HTML file. It's possible to implement JavaScript code within them to carry XSS or CSRF attack on whoever visits the uploaded HTML page. A target may visit the link, since it's a site they trust.

Another example of XSS attacks is web applications that display an image's metadata after its upload. We can include XSS payload in one of the metadata parameters that accept raw text, like the `Comment` or `Artist` parameters, as follows:
```shell-session
$ exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
Wildland4958@htb[/htb]$ exiftool HTB.jpg
...SNIP...
Comment                         :  "><img src=1 onerror=alert(window.origin)>
```

When the image's metadata is displayed, our JavaScript code should be triggered to carry the XSS attack. Furthermore, if we change the image's MIME-Type to `text/html`, some web applications may show it as an HTML document instead of an image, in which case the XSS payload would be triggered event if the metadata wasn't directly displayed.

Finally, XSS attacks can also be carried with `SVG` images, along with several other attacks. `Scalable Vector Graphics (SVG)` images are XML-based, and they describe 2D vector graphics, which the browser renders into an image. For this reason, we can modify their XML data to include an XSS payload. For example, we can write the following to `HTB.svg`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```

Once we upload the image to the web application, the XSS payload will be triggered whenever the image is displayed.

## XXE

With SVG images, we can also include malicious XML data to leak the source code of the web application, and other internal documents within the server. The following example can be used for an SVG image that leaks the content of (`/etc/passwd`):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

When the SVG image is viewed, the XML document would get processed and we should get the info of (`/etc/passwd`) printed on the page or shown in the page source. We can use the same payload, if the application allows the upload of XML documents.

We can also read the web application's source files. In the source code we can find vulnerabilities to exploit through White Box Penetration Testing. For file upload exploitation, it might allow us to `locate the upload directory, identify allowed extensions, or find the file naming scheme`.

To use XXE to read source code in PHP web applications, we can use the following payload in our SVG image:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

Once the SVG image is displayed, we should get the base64 encoded content of `index.php`, which we can decode to read the source code.

Many other documents, like `PDF`, `Word Documents`, `PowerPoint Documents`, among many others use XML as well. XML is used with those documents to specify the format and structure. Suppose a web application used a document viewer that is vulnerable to XXE and allowed uploading any of those documents. We can modify the XML data to include the malicious XXE elements, and we would be able to carry a blind XXE attack on the back-end web server.

SSRF is also achievable through those file types. XXE vulnerability can be utilized to enumerate the internally available services or even call private API to perform private actions. For more about SSRF, you may refer to the [Server-side Attacks](https://academy.hackthebox.com/module/details/145) module.

## DOS

Many file upload vulnerabilities can lead to DoS attacks. As an example, we can use the previous XXE payloads to achieve DoS attacks.

Furthermore, we can utilize a `Decompression Bomb` with file types that use data compression, like `ZIP` archives. If a web application automatically unzips a ZIP archive, it is possible to upload a malicious archive containing nested ZIP archives within it, which can eventually lead to many Petabytes of data, resulting in a crash on the back-end server.

Another possible DoS attack is a `Pixel Flood` attack with some image files that utilize image compression, like `JPG` or `PNG`. We can create any `JPG` image file with any image size (e.g. `500x500`), and then manually modify its compression data to say it has a size of (`0xffff x 0xffff`), which results in an image with a perceived size of 4 Gigapixels. When the web application attempts to display the image, it will attempt to allocate all of its memory to this image, resulting in a crash on the back-end server.

In addition to these attacks, we may try a few other methods to cause a DoS on the back-end server. One way is uploading an overly large file, as some upload forms may not limit the upload file size or check for it before uploading it, which may fill up the server's hard drive and cause it to crash or slow down considerably.

If the upload function is vulnerable to directory traversal, we may also attempt uploading files to a different directory (e.g. `../../../etc/passwd`), which may also cause the server to crash.