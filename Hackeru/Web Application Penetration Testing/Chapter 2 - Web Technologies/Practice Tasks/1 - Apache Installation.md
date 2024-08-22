Install Apache2 - apt install apache2

Start the Apache service - service apache2 start

check the Apache service status - service apache2 status

To customize the Apache vonfiguration, a specific file must be created - touch /var/www/html/.htaccess

AllowOverride - Change value to all in the Apache configuratin file(/etc/apache2/apache2.conf)

Redirect to file in 404(page not found erorr) - ErrorDocument 404 /[file]
	
Restart the Sache service to save the changes - service apache2 restart
	

