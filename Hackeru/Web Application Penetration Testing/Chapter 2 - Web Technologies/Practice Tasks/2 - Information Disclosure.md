Disable version disclosure on the Apache server, by adding the following commands to the apache2.conf file(location in [[1 - Apache Installation]]):
1. ServerTokens Prod 
2. ServerSignature Off

Disable directory listing on the server via the .htaccess file(location in [[1 - Apache Installation]]) - Options -Indexes

Disable the server-status page:
1. a2dismod status
2. systemctl rastart apache2


