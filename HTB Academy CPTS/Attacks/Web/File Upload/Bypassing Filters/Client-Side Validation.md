We can easily bypass a file format validation that is happening on the client-side, by directly interacting with the server, skipping the front-end validation altogether. We may also modify the front-end code through our browser dev tools to disable any validation in place.

## Client-Side Validation

The dialog is limited to image formats only, so we can't see our PHP files:
![[file_uploads_select_file_types.jpg]]

We can select `All Files` to select our PHP script anyway, but we will get an error message:
![[file_uploads_select_denied.jpg]]

This indicates some form of file type validation. The page never refreshes or sends any HTTP requests after selecting our file, so the validation appears to be on the client-side. So, we should be able to have complete control over these client-side validations.

While the web server is responsible for sending the front-end code, the rendering and execution of the front-end code happen within our browser.

To bypass these protections, we can either `modify the upload request to the back-end server`, or we can `manipulate the front-end code to disable these type validations`.

## Back-end Request Modification

When uploading a normal image, we can see it gets reflected as our profile image, and persists through refreshes.

If we capture the upload request with `Burp`, we see the following request being sent by the web application:
![[file_uploads_image_upload_request.jpg]]

We can modify the above request to `/upload.php` to meet our needs without having the front-end type validation restrictions. If the back-end server does not validate the uploaded file type, then we should theoretically be able to send any file type/content, and it would be uploaded to the server.

We can modify the `filename="HTB.png"` to `filename="shell.php"` and the file content at the end of the request. So we would be uploading a PHP web shell.

So, let's capture another image upload request, and then modify it accordingly:
![[file_uploads_modified_upload_request.jpg]]

**Note:** We may also modify the `Content-Type` of the uploaded file, though this should not play an important role at this stage, so we'll keep it unmodified.

## Disabling Front-end Validation

We can manipulate our front-end code. As these functions are being completely processed within our web browser, we have complete control over them. So we can modify those scripts or disable them entirely. Then, we may use the upload functionality to upload any file type without needing to utilize `Burp` to capture and modify our requests.

To start, we can click [`CTRL+SHIFT+C`] to toggle the browser's `Page Inspector`, and then click on the profile image, which is where we trigger the file selector for the upload form:
![[file_uploads_element_inspector.jpg]]

This will highlight the following HTML file input on line `18`:
```html
<input type="file" name="uploadFile" id="uploadFile" onchange="checkFile(this)" accept=".jpg,.jpeg,.png">
```

Here, we see that the file input specifies (`.jpg,.jpeg,.png`) as the allowed file types within the file selection dialog. However, we can easily modify this and select `All Files` as we did before, so it is unnecessary to change this part of the page.

We can get the details of the `checkFile` function, by going to the `Console` by clicking [`CTRL+SHIFT+K`], and then typing the function name:
```javascript
function checkFile(File) {
...SNIP...
    if (extension !== 'jpg' && extension !== 'jpeg' && extension !== 'png') {
        $('#error_message').text("Only images are allowed!");
        File.form.reset();
        $("#submit").attr("disabled", true);
    ...SNIP...
    }
}
```

In case the file extension is not an image, it prints an error message and disables the upload button. We can add `PHP` as one of the allowed extensions or modify the function to remove the extension check.

Luckily, we do not need to get into writing and modifying JavaScript code. We can remove this function from the HTML code since its primary use appears to be file type validation, and removing it should not break anything.

To do so, we can go back to our inspector, click on the profile image again, double-click on the function name (`checkFile`) on line `18`, and delete it:
![[file_uploads_removed_js_function.jpg]]

**Tip:** You may also do the same to remove `accept=".jpg,.jpeg,.png"`, which should make selecting the `PHP` shell easier in the file selection dialog, though this is not mandatory, as mentioned earlier.

With the `checkFile` function removed from the file input, we should be able to select our `PHP` web shell through the file selection dialog and upload it normally with no validations.

**Note:** The modification we made to the source code is temporary and will not persist through page refreshes, as we are only changing it on the client-side. However, our only need is to bypass the client-side validation, so it should be enough for this purpose.

Once we upload our web shell using either of the above methods and then refresh the page, we can use the `Page Inspector` once more with [`CTRL+SHIFT+C`], click on the profile image, and we should see the URL of our uploaded web shell:
```html
<img src="/profile_images/shell.php" class="profile-image" id="profile-image">
```

We can now interact with the web shell:
http://SERVER_IP:PORT/profile_images/shell.php?cmd=id

**Note:** The steps shown apply to Firefox, as other browsers may have slightly different methods for applying local changes to the source, like the use of `overrides` in Chrome.

