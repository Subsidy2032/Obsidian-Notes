1. Turn off the network adapter
2. Enable docker deamon - dockerd
3. In a new terminal navigate to the basics directory - cd ssrf/ssrf-lab/basics/
4. Build docker - docker build . -t ssrf-basic
5. Start the docker and run the ssrf environment - docker rum -p 8001:80 ssrf-basic:latest
6. Navigate to http://127.0.0.1:8001 to access the vulnerable web-app
7. Use protocol file in order to manipulate the web-hook and preform a file disclosure attack of passwd file - file:///etc/passwd