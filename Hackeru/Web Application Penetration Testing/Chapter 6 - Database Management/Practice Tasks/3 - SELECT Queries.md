Show a certain column using the WHERE statment - SELECT * FROM blackhacker WHERE id=2;

Using Or - SELECT * FROM blackhacker WHERE role="-1" OR 1=1;

Retrieve data in a specific order - SELECT * FROM blakhacker ORDER BY <column_name>;

Use UNION ALL - SELECT usermame, password, country, role FROM blackhacker UNION ALL SELCT usermame, password, country, role FROM whitehacker;

Save the output to a file - SELECT * FROM <table_name> INTO OUTFILE <'file_name'>