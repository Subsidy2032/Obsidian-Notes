1. Close all terminals accapt the one with the dockerd deamon
2. Disable the previous socker container:
	docker network prune
	docker container prune
3. disable all previous docker containers - docker kill $(docker ps -q)
4. Navigate to the advanced1 directory and start the advanced lab:
	cd /ssrf/ssrf-lab/advanced1
	docker-compose up
5. Navigate to the web-app of the advanced lab - http://127.0.0.1:8000
6. Try to access to the internal network of the web-app - http://10.0.0.3
7. Bypass the IP filtration by writing the IP address in hexadecimal format - http://0x0a000003
8. Abuse the URL parsing of an python-flask web server with urllib and urllib2 - http://google.com &@ 10.0.0.3