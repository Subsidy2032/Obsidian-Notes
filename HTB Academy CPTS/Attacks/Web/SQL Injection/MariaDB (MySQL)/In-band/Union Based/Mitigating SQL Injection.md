## Input Sanitization

Snippet of code for authentication:
```php
<SNIP>
  $username = $_POST['username'];
  $password = $_POST['password'];

  $query = "SELECT * FROM logins WHERE username='". $username. "' AND password = '" . $password . "';" ;
  echo "Executing query: " . $query . "<br /><br />";

  if (!mysqli_query($conn ,$query))
  {
          die('Error: ' . mysqli_error($conn));
  }

  $result = mysqli_query($conn, $query);
  $row = mysqli_fetch_array($result);
<SNIP>
```

Instead of passing the username and password directly to the query we should sanitize user input, there are multiple libraries that provide functions for that purpose, one function is [mysqli_real_escape_string()](https://www.php.net/manual/en/mysqli.real-escape-string.php), which escapes characters like `'` and `"` so they don't hold any special meaning.

```php
<SNIP>
$username = mysqli_real_escape_string($conn, $_POST['username']);
$password = mysqli_real_escape_string($conn, $_POST['password']);

$query = "SELECT * FROM logins WHERE username='". $username. "' AND password = '" . $password . "';" ;
echo "Executing query: " . $query . "<br /><br />";
<SNIP>
```

[pg_escape_string()](https://www.php.net/manual/en/function.pg-escape-string.php) is a similar example which is used to escape PostgreSQL queries.

## Input Validation

Example code for searching:
```php
<?php
if (isset($_GET["port_code"])) {
	$q = "Select * from ports where port_code ilike '%" . $_GET["port_code"] . "%'";
	$result = pg_query($conn,$q);
    
	if (!$result)
	{
   		die("</table></div><p style='font-size: 15px;'>" . pg_last_error($conn). "</p>");
	}
<SNIP>
?>
```

We should make sure the user enters data in the form he supposed to.

Example of restricting the user to only enter letters or spaces for the code above:
```php
<SNIP>
$pattern = "/^[A-Za-z\s]+$/";
$code = $_GET["port_code"];

if(!preg_match($pattern, $code)) {
  die("</table></div><p style='font-size: 15px;'>Invalid input! Please try again.</p>");
}

$q = "Select * from ports where port_code ilike '%" . $code . "%'";
<SNIP>
```

## User Privileges

DBMS allows the creation of users with fine-grained permissions, so we should ensure that any user querying the database has minimum permissions, users with administrative privileges shouldn't be used with web applications.

```shell-session
MariaDB [(none)]> CREATE USER 'reader'@'localhost';

Query OK, 0 rows affected (0.002 sec)


MariaDB [(none)]> GRANT SELECT ON ilfreight.ports TO 'reader'@'localhost' IDENTIFIED BY 'p@ssw0Rd!!';

Query OK, 0 rows affected (0.000 sec)
```

The user reader will only have SELECT privileges on the ports table.

Verifying the permissions:
```shell-session
Wildland4958@htb[/htb]$ mysql -u reader -p

MariaDB [(none)]> use ilfreight;
MariaDB [ilfreight]> SHOW TABLES;

+---------------------+
| Tables_in_ilfreight |
+---------------------+
| ports               |
+---------------------+
1 row in set (0.000 sec)


MariaDB [ilfreight]> SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;

+--------------------+
| SCHEMA_NAME        |
+--------------------+
| information_schema |
| ilfreight          |
+--------------------+
2 rows in set (0.000 sec)


MariaDB [ilfreight]> SELECT * FROM ilfreight.credentials;
ERROR 1142 (42000): SELECT command denied to user 'reader'@'localhost' for table 'credentials'
```

## Web Application Firewall

WAFs are used to detect malicious input and reject any HTTP requests containing them, they can be open-source (ModSecurity) or premium (Cloudflare). Most of them have default rules configured, for example any string containing INFORMATION_SCHEMA will be rejected.

## Parametrized Queries

Parametrized queries contain placeholders for the input data, which is than escaped and passed on by the drivers. We fill the place holders with PHP functions.

Example of using [mysqli_stmt_bind_param()](https://www.php.net/manual/en/mysqli-stmt.bind-param.php), and placing `?` as place holders:
```php
<SNIP>
  $username = $_POST['username'];
  $password = $_POST['password'];

  $query = "SELECT * FROM logins WHERE username=? AND password = ?" ;
  $stmt = mysqli_prepare($conn, $query);
  mysqli_stmt_bind_param($stmt, 'ss', $username, $password);
  mysqli_stmt_execute($stmt);
  $result = mysqli_stmt_get_result($stmt);

  $row = mysqli_fetch_array($result);
  mysqli_stmt_close($stmt);
<SNIP>
```