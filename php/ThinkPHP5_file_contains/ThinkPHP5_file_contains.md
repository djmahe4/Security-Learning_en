# ThinkPHP5 file contains

Author: H3rmesk1t

Data: 2021.08.16

# Vulnerability Summary
- This vulnerability exists in the ThinkPHP template engine. There is a variable overwrite problem when loading template parsing variables. Moreover, the program does not filter the data well, which ultimately leads to the occurrence of file containing vulnerabilities.
- Vulnerability impact version: 5.0.0<=ThinkPHP<=5.0.21, 5.1.3<=ThinkPHP5<=5.1.25
# Initial configuration
- Get the test environment code

```bash
composer create-project --prefer-dist topthink/think=5.0.18 tpH3rmesk1t
```
![Insert the picture description here](https://img-blog.csdnimg.cn/ca08f62525a14813aaae9f8fd5035a2b.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

- Set the `require` field of the `composer.json` file to the following

```bash
"require": {
    "php": ">=5.6.0",
    "topthink/framework": "5.0.18"
},
```

Then execute `composer update` and set the `application/index/controller/Index.php` file code as follows

![Insert the picture description here](https://img-blog.csdnimg.cn/94875f2b53d54bec92789f706ad15e6b.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

```php
<?php
namespace app\index\controller;
use think\Controller;
class Index extends Controller
{
    public function index()
    {
        $this->assign(request()->get());
        return $this->fetch(); // Current module/Default view directory/Current controller (lowercase)/Current operation (lowercase).html
    }
}
```

Create an application/index/view/index/index.html file with random content (if there is no such template file, the program will report an error during rendering)

![Insert the picture description here](https://img-blog.csdnimg.cn/7fdb582b76c74e81be0a0bf509f0a824.png#pic_center)
# Vulnerability Exploit

Put the picture horse demo.jpg in the public directory (simulate the upload image operation) and access

```bash
http://127.0.0.1/cms/public/index.php/index/index?cacheFile=demo.jpg
```

![Insert the picture description here](https://img-blog.csdnimg.cn/f829190d237a4b8291ef776f1b861f0b.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Vulnerability Analysis

First, the user-controllable data is not filtered, and the template variable is assigned directly through the `assign` method of the `Controller` class, and the controllable data is stored in the `data` property of the `think\View` class.

![Insert the picture description here](https://img-blog.csdnimg.cn/f755c082abd24a6f9be4795ebb8fc5fe.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Then the program starts calling the `fetch` method to load the template output. Here, if we do not specify the template name, it will use the default file as the template. The template path bits are: `Current module/default view directory/current controller (lowercase)/current operation (lowercase).html`. If the default path template does not exist, the program will report an error and follow up to `thinkphp/library/think/View.php`

![Insert the picture description here](https://img-blog.csdnimg.cn/39a3076073684bc2a2037ff2e0fc5494.png#pic_center)

![Insert the picture description here](https://img-blog.csdnimg.cn/b68253b1d486465a9fabc9b8468f0d95.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/9d6755110aa4436996e391d33b094df2.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

We follow up on the `fetch` method of the `Template` class, and we can find that the controllable variable `$vars` is assigned to `$this->data` and finally pass it in the `File` class `read` method. After using the `extract` function, the `$cacheFile` variable is directly included. This is the key reason for the vulnerability, because the parameter `$vars` in the `extract` function can be controlled by the user, and the `$cacheFile` variable can be directly overwritten through the `extract` function

![Insert the picture description here](https://img-blog.csdnimg.cn/55bb98ce05314698999f85c76ed5599a.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/b2b729e5cc8642158a15235c4da0e1eb.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Complete method call, from bottom to top

![Insert the picture description here](https://img-blog.csdnimg.cn/c8df6e31e3f94a32895df609c5261e3e.png#pic_center)


# Vulnerability Fix

The official fix is: first store the `$cacheFile` variable in `$this->cacheFile`. After using the `extract` function, the final variable of include is `$this->cacheFile`, which avoids the variable value after include is overwritten.

![Insert the picture description here](https://img-blog.csdnimg.cn/1de15b226d7a44408aa085921ef11b59.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Attack summary

Refer to Master Mochazz's audit flow
Procedure

![Insert the picture description here](https://img-blog.csdnimg.cn/1a7a51e928e641ffb3c2d5529fd8bc45.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)