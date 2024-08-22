Start the MtSQL service - service mysql start

Connect to the service as root - mysql -p

List all the databases - SHOW DATABASES;

Choose a database - USE <DB_name>;

List all the tables in a specific database - SHOW tables;

list and describe all columns - DESCRIBE <Table_Name>;

Create database - CREATE DATABASE <db_name>;

Generating table whitehacker with the following columns: id, username, password, country and role:

CREATE TABLE whhitehacker(
id INT(4) AUTO_INCREMENT PRIMARY KEY,
username VARCHAR(30) NOT NULL,
password VARCHAR(16) NOT NULL,
country VARCHAR(30),
role VARCHAR(30));

Options:

INT(4) - This will set the column to get just integers and limit the numbers up to 4

AUTO_INCREMENT - This set the column tomake automatic increments

PRIMARY KEY - this will set the column as a unique identifier of that row

VARCHAR(30) - This will set the column to get strings and limit the number of characters up to 30

NOT NULL - set the column to ensure that the values stored ara not null

UNSIGNED - Only positive

Add worker to the table - INSERT INTO <Table_Name> (username, password, coumtry, role) VALUES ("Tom", 123456, "Israel", "Analyst");