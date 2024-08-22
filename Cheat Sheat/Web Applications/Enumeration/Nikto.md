Basic Scanning: `nikto -h [ip address]`

Scan specific ports: `nikto -h [ip address] -p [ports]`

List all plugins: `nikto --list-plugins`

Use a plugin: `nikto -h [ip address] -Plugin [plugin]`

### Tuning

`nikto -h [ip address] -Tuning [option]`

|   |   |   |
|---|---|---|
|Category Name|Description|Tuning Option|
|File Upload|Search for anything on the web server that may permit us to upload a file. This could be used to upload a reverse shell for an application to execute.|0|
|Misconfigurations / Default Files|Search for common files that are sensitive (and shouldn't be accessible such as configuration files) on the web server.|2|
|Information Disclosure|Gather information about the web server or application (i.e. verison numbers, HTTP headers, or any information that may be useful to leverage in our attack later)|3|
|Injection|Search for possible locations in which we can perform some kind of injection attack such as XSS or HTML|4|
|Command Execution|Search for anything that permits us to execute OS commands (such as to spawn a shell)|8|
|SQL Injection|Look for applications that have URL parameters that are vulnerable to SQL Injection|9|