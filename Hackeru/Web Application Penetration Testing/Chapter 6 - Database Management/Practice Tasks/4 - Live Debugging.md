Use SHOW query to view the current setting of the log file and its mane - SHOW VARIABLES LIKE 'general_log%';

Switce it to ON - SET GLOBAL general_log='ON';

Change the log file - SET GLOBAL general_log_file = '/var/log/mysql/mysql.log';

Open the general_log_file on debug mode with tail command - tail -f -n 1 mysql.log

