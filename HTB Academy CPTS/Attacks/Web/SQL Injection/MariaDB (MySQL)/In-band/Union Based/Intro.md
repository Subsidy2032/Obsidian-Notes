## Use of SQL in Web Applications

Using SQL within PHP web application:
```php
$conn = new mysqli("localhost", "root", "password", "users");
$query = "select * from logins";
$result = $conn->query($query);
```

Printing the result:
```php
while($row = $result->fetch_assoc() ){
	echo $row["name"]."<br>";
}
```

Example of using user input to search for users:
```php
$searchInput =  $_POST['findUser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query);
```

Injection accurs when the application misinterprets user input as actual code rather than a string, we can escape the input by injecting special character like `'`.

Example of injecting SQL command to the previous input:
```php
'%1'; DROP TABLE users;'
```

The final query will be:
```sql
select * from logins where username like '%1'; DROP TABLE users;'
```

Note that adding another query after `;` isn't actually possible with MySQL.

The previous query will result in an error, because of the last trailing character which isn't closed, so we would use methods like comments and extra `'` to bypass this.

## Union

Example of using union to combine tables:
```shell-session
mysql> SELECT * FROM ports;

+----------+-----------+
| code     | city      |
+----------+-----------+
| CN SHA   | Shanghai  |
| SG SIN   | Singapore |
| ZZ-21    | Shenzhen  |
+----------+-----------+
3 rows in set (0.00 sec)

mysql> SELECT * FROM ships;

+----------+-----------+
| Ship     | city      |
+----------+-----------+
| Morrison | New York  |
+----------+-----------+
1 rows in set (0.00 sec)

mysql> SELECT * FROM ports UNION SELECT * FROM ships;

+----------+-----------+
| code     | city      |
+----------+-----------+
| CN SHA   | Shanghai  |
| SG SIN   | Singapore |
| Morrison | New York  |
| ZZ-21    | Shenzhen  |
+----------+-----------+
4 rows in set (0.00 sec)
```

The number of selected columns should be even, and the data types of each column should be the same.

For uneven number of columns, for example if the products table has 2 columns:
```sql
SELECT * from products where product_id = '1' UNION SELECT username, 2 from passwords
```

We should use data for the same column from the same type the column is, we can use NULL which is working with all data types.

## Types of SQL Injection

![[types_of_sqli.jpg]]

In-band: Where the intended and the new query will be printed on the front end, it has 2 types Union Based and Error Based.

With Union Based we may have to specify the exact location, i.e. column which we can read so the query will direct the output to be printed there. As for Error Based, it is used when we can get the SQL or PHP errors in the front-end, so we may cause an error that will return the outplut.

Blind SQL Injection is when we don't get the output printed so we retrieve it character by character, it has 2 types, Boolean Based and Time Based.

With Boolean Based we control if the page returns any results at all, for example we only get response if the statement is true. With Time Based we delay the response if the statement is true, using the `sleep()` function.

In some cases we might not have access to the output at all, so we will direct it to a remote location, i.e. DNS record and than attempt to retrieve it from there, this is known as Out-of-band SQL Injection.