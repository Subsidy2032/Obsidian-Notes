Create a self signed certificate for the server - openssl req -x509 -nodes -days 365 
-newkey rsa:2048 -keyout /etc/ssl/private/apache-certificate.key -out /etc/ssl/certs/apache-certificate.crt

Enable ssl module - a2enmod ssl

Enable the same-origin policy for the server via the htaccess file(location in [[1 - Apache Installation]]) - Header append X-FRAME-OPTIONS "SAMEORIGIN"

Enable the XSS-Protection header via the htaccess file(location in [[1 - Apache Installation]]) - Header set X-XSS-PROTECTION "1; mode=block"

Restart the apache2 service to apply the changes:
1. service apache2 restart
2. systemctl rastart apache2
	



