# ThinkPHP5.0.x SQL Injection

Author: H3rmesk1t

Data: 2021.08.09

# Vulnerability Description
Although the `ThinkPHP 5.0.x framework uses parameterized query method to operate the database, in the `insert` and `update` methods, the passed parameters are controllable and are not strictly filtered, which ultimately leads to SQL injection vulnerabilities.
# Initial configuration
- Here we use `ThinkPHP5.0.14` as an example, [click here to download](http://www.thinkphp.cn/download/1107.html)
- In the downloaded source code, you need to modify the content of `Application\index\controller\Index.php`

```php
<?php
namespace app\index\controller;
use think\Db;

class Index
{
    public function index()
    {
        $name = input("get.name/a");
        Db::table("users")->where(["id"=>1])->insert(["username"=>$name]);
        return '<style type="text/css">*{ padding: 0; margin: 0; } .think_default_text{ padding: 4px 48px;} a{color:#2E5CD5;cursor: pointer;text-decoration: none} a:hover{text-decoration:underline; } body{ background: #fff; font-family: "Century Gothic","Microsoft yahei"; color: #333;font-size:18px} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.6em; font-size: 42px }</style><div style="padding: 24px 48px;"<h1>:)</h1><pThinkPHP V5<br/><span style="font-size:30px">Ten years of hard work - A high-performance framework designed for API development</span></p><span style="font-size:22px;">[ V5.0 version is exclusively sponsored by <a href="http://www.qiniu.com" target="qiniu">Qiu Cloud</a]</span></div><script type="text/javascript" src="http://tajs.qq.com/stats?sId=9347272" charset="UTF-8"></script><script type="text/javascript" src="http://ad.topthink.com/Public/static/client.js"></script><thinkad id="ad_bd568ce7058a1091"></thinkad>';
    }
}
```

Configure database-related files and enable thinkphp debugging function

![Insert the picture description here](https://img-blog.csdnimg.cn/390fa95b211f44de8894013f8d5c7507.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

![Insert the picture description here](https://img-blog.csdnimg.cn/1ed1cde777ce474d8df1b1a50e688c24.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Vulnerability Exploit

Payload:
```nash
http://127.0.0.1/cms/public/index.php/index/index/index?name[0]=inc&name[1]=updatexml(1,concat(0x7,user(),0x7e),1)&name[2]=1
or
http://127.0.0.1/cms/public/index.php/index/index/index?name[0]=dec&name[1]=updatexml(1,concat(0x7,user(),0x7e),1)&name[2]=1
```

![Insert the picture description here](https://img-blog.csdnimg.cn/bd5215d598004de2b117678593b05e3c.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Vulnerability Analysis
## ThinkPHP5.0.x directory structure

````less
thinkphp application deployment directory
├─application application directory (can be set)
│ ├─common Public module directory (can be changed)
│ ├─index module directory (can be changed)
│ │ ├─config.php module configuration file
│ │ ├─common.php module function file
│ │ ├─controller controller directory
│ │ ├─model model directory
│ │ ├─view View Directory
│ │ └─ ... More library catalogs
│ ├─command.php command line tool configuration file
│ ├─common.php Application public (function) file
│ ├─config.php application (public) configuration file
│ ├─database.php database configuration file
│ ├─tags.php Application behavior extension definition file
│ └─route.php routing configuration file
├─extend Extended Class Library Directory (definable)
├─public WEB deployment directory (external access directory)
│ ├─static static resource storage directory (css,js,image)
│ ├─index.php application entry file
│ ├─router.php Quick test file
│ └─.htaccess is used for rewriting of apache
├─runtime application runtime directory (writable, setable)
├─vendor Third-party library directory (Composer)
├─thinkphp framework system directory
│ ├─lang Language Pack Directory
│ ├─library framework core class library directory
│ │ ├─think Think class library package directory
│ └─traits system Traits directory
│ ├─tpl system template directory
│ ├─.htaccess is used for rewriting of apache
│ ├─.travis.yml CI definition file
│ ├─base.php basic definition file
│ ├─composer.json composer definition file
│ ├─console.php console entry file
│ ├─convention.php convention configuration file
│ ├─helper.php helper function file (optional)
│ ├─LICENSE.txt Authorization Document
│ ├─phpunit.xml unit test configuration file
│ ├─README.md README file
│ └─start.php framework boot file
├─build.php Automatically generate definition files (reference)
├─composer.json composer definition file
├─LICENSE.txt Authorization Document
├─README.md README file
├─think
Command line entry file
```
## Payload Instructions
Payload: `http://127.0.0.1/cms/public/index.php/index/index/index?name[0]=inc&name[1]=updatexml(1,concat(0x7,user(),0x7e),1)&name[2]=1`
````ha
http://localhost/thinkphp/ public/ index.php/ index/ index/ index/ index/ index
       Domain Name Website Directory External Access Directory Entry File Front Desk Controller Method Name
```
## Application\index\controller\Index.php Supplementary Code Description

```php
$name = input("get.name/a");
input() is a helper function of the TP framework. get.name/a means to get the name variable passed in by get and cast it to an array type
```

```php
Db::table("users")->where(["id"=>1])->insert(["username"=>$name]);
The TP framework uses PDO to query the database
```
## Local code audit

First, the parameters are obtained through the helper function `input` of the TP framework. The name variable is as follows

![Insert the picture description here](https://img-blog.csdnimg.cn/a40079999bc945c88e1c3b0789c88f62.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Follow up on the `where` method in `thinkphp/library/think/db/Query.php`, then follow up on the `insert` method, find `$sql = $this->builder->insert($data, $options, $replace);`, and follow up

![Insert the picture description here](https://img-blog.csdnimg.cn/a3e9fa12a7ec41c7b4385048f1229346.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Follow up to `thinkphp/library/think/db/Builder.php`, find `$data = $this->parseData($data, $options);`, follow up

![Insert the picture description here](https://img-blog.csdnimg.cn/4576f60006e34634a1d4c21d25e03386.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Follow up on the `parseData` method, you can see that `$val` is an array, and according to the `$val[0]` value is inc, enter the `parseKey` method through the switch statement

![Insert the picture description here](https://img-blog.csdnimg.cn/325df7e466f64041941961e11cea3960.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Follow up on the parseKey method of `thinkphp/library/think/db/builder/Mysql.php`. There is no more filtering and checking for the incoming `$key`, and the final return is still `1 and (updatexml(1,concat(0x7,user(),0x7e),1))`

![Insert the picture description here](https://img-blog.csdnimg.cn/bfcafb742dc64f599be387989ec03ec7.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Return to the `parseData` method, `floatval($val[2])` returns `1`, which is exactly why Payload passes in `username[2]=1`, and then splices it with the previous result of the `parseKey` method and returns it to the result.


![Insert the picture description here](https://img-blog.csdnimg.cn/7281229d1a9b40a28b9a0fa5801abd22.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Go back to the `insert` method of `thinkphp/library/think/db/Builder.php`, you can see that the returned `$sql` successfully caused sql injection.

![Insert the picture description here](https://img-blog.csdnimg.cn/3d249e779c284385bb93b91e92ab4927.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

# Vulnerability Fix

- Reference official commit: [https://github.com/top-think/framework/commit/363fd4d90312f2cfa427535b7ea01a097ca8db1b](https://github.com/top-think/framework/commit/363fd4d90312f2cfa427535b7ea01a097ca8db1b)
- The value of `$val[1]` was reconfirmed before performing dec and inc operations

![Insert the picture description here](https://img-blog.csdnimg.cn/c5228fad76194f18b24b91b8e911ec8c.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)