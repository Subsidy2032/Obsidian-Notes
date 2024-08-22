Only testing the file extension isn't enough to prevent file upload attacks.

This is why many modern web servers and web applications also test the content of the uploaded file. content filters usually specify a single category (e.g., images, videos, documents), which is why they don't typically use blacklists or whitelists. This is because web servers provide functions to check for the file content type, and it usually falls under a specific category.

There are two common methods for validating the file content: `Content-Type Header` or `File Content`. Let's see how we can identify each filter and how to bypass both of them.

## Content-Type

The following is an example of how a PHP web application tests the Content-Type header to validate the file type:
```php
$type = $_FILES['uploadFile']['type'];

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```

Our browsers automatically set the Content-Type header when selecting a file through the file selector dialog, usually derived from the file extension. This is a client side operation, and we can manipulate it to change the perceived file type and potentially bypass the type filter.

We may start by fuzzing the Content-Type header with SecLists' [Content-Type Wordlist](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/web/content-type.txt) through Burp Intruder, to see which types are allowed. If we have an indication (like an error message) of which file types are allowed, we can limit our scan to this type. For example if we know only images are allowed:
```shell-session
$ wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Miscellaneous/web/content-type.txt
$ cat content-type.txt | grep 'image/' > image-content-types.txt
```

Let's just pick an image type (e.g. `image/jpg`), then intercept our upload request and change the Content-Type header to it:
![[file_uploads_bypass_content_type_request.jpg]]

We now can get a web shell.

**Note:** A file upload HTTP request has two Content-Type headers, one for the attached file (at the bottom), and one for the full request (at the top). We usually need to modify the file's Content-Type header, but in some cases the request will only contain the main Content-Type header (e.g. if the uploaded content was sent as `POST` data), in which case we will need to modify the main Content-Type header.

## MIME-Type

The second and more common type of file content validation is testing the uploaded file's `MIME-Type`. `Multipurpose Internet Mail Extensions (MIME)` is an internet standard that determines the type of a file through its general format and bytes structure.

This is usually done by inspecting the first few bytes of the file's content, which contain the [File Signature](https://en.wikipedia.org/wiki/List_of_file_signatures) or [Magic Bytes](https://opensource.apple.com/source/file/file-23/file/magic/magic.mime). For example, if a file starts with (`GIF87a` or `GIF89a`), this indicates that it is a `GIF` image, while a file starting with plaintext is usually considered a `Text` file. If we change the first bytes of any file to the GIF magic bytes, its MIME type would be changed to a GIF image, regardless of its remaining content or extension.

**Tip:** Many other image types have non-printable bytes for their file signatures, while a `GIF` image starts with ASCII printable bytes (as shown above), so it is the easiest to imitate. Furthermore, as the string `GIF8` is common between both GIF signatures, it is usually enough to imitate a GIF image.

The `file` command on Unix systems finds the file type through the MIME type. If we create a basic file with text in it, it would be considered as a text file, as follows:
```shell-session
$ echo "this is a text file" > text.jpg 
$ file text.jpg 
text.jpg: ASCII text
```

If we write `GIF8` to the beginning of the file, it will be considered as a `GIF` image instead, even though its extension is still `.jpg`:
```shell-session
$ echo "GIF8" > text.jpg 
$file text.jpg
text.jpg: GIF image data
```

This standard to determine file types, is usually more accurate than testing the file extension. The following example shows how a PHP web application can test the MIME type of an uploaded file:
```php
$type = mime_content_type($_FILES['uploadFile']['tmp_name']);

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```

Lets try to add `GIF8` before our PHP code:
![[file_uploads_bypass_mime_type_request.jpg]]

We can now try to visit our uploaded file, and try to execute commands.

**Note:** We see that the command output starts with `GIF8` , as this was the first line in our PHP script to imitate the GIF magic bytes, and is now outputted as a plaintext before our PHP code is executed.

