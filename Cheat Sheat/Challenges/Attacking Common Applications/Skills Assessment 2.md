## Nmap Scan
![[Pasted image 20240523153904.png]]

Add blog.inlanefreight.local to the hosts file, then found the Wordpress instance.

## GitLab

Found Public Repository in the GitLab Instance:
![[Pasted image 20240523154343.png]]

We found a possible virtual host:
![[Pasted image 20240523164628.png]]

After changing the hosts file we found this site:
![[Pasted image 20240523164702.png]]

Now it's time to get access to a privileged user, so we can maybe find other interesting repositories.

## Enumerating usernames
![[Pasted image 20240523161701.png]]

Found to usernames with the [tool](https://www.exploit-db.com/exploits/49821), root and tester.

Got access with `tester:Welcome1`:
![[Pasted image 20240523161835.png]]

We can see another interesting repository, Nagios Postgresql.

Found Credentials in the repository, in the INSTALL file:
![[Pasted image 20240523164445.png]]

nagiosadmin:oilaKglm7M09@CPL&^lC

Now lets go back to the Nagios application.

## Nagios

After logging in we can see the version at the bottom of the page: `Ngios XI 5.7.5`.

Found a public [exploit](https://www.exploit-db.com/exploits/49422) with a quick google search.

Executing the exploit:
![[Pasted image 20240523165713.png]]

Got the shell with the netcat listener:
![[Pasted image 20240523165738.png]]

Got the flag:
![[Pasted image 20240523165828.png]]

afe377683dce373ec2bf7eaf1e0107eb