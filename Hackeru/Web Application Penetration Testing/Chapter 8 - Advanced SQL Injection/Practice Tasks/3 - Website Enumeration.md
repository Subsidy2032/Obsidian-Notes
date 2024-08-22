Brute force the website directories only for php files - dirb [url] /usr/share/wordlists/dirb/big.txt -X .php

in gobuster - gobuster dir -u [url] -t 5 -w [wordlistfile] -x .php