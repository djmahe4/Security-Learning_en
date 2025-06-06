# 内网渗透测试基础

## 内网工作环境

### 工作组

工作组（`Work Group`）是计算机网络的一个概念，也是最常见和最普通的资源管理模式，就是将不同的计算机按照功能或部门分别置于不同的组。

### 域

域（`Domain`）是一种比工作组更高级的计算机资源管理模式，既可以用于计算机数量较少的小规模网络环境，也可以用于计算机数量众多的大型网络环境。

在域环境中，所有用户账户、用户组、计算机、打印机和其他安全主体都在一个或多个域控制器中进行身份验证。当与用户需要访问域中的资源时，必须通过域控制器集中进行身份验证。而通过身份验证的域用户对域中的资源拥有什么样的访问权限取决于域用户在域中的身份。

- 单域：指网络环境中只有一个域。

![Untitled](%E5%86%85%E7%BD%91%E6%B8%97%E9%80%8F%E6%B5%8B%E8%AF%95%E5%9F%BA%E7%A1%80%20749199f90fc14676a9be7c290558218a/Untitled.png)

- 父域和子域：在有些情况下，为了满足某些管理需求，需要在一个域中划分出多个域。其中，被划分的域称为父域，划分出来的各部分域称为子域。例如，在一个大型组织的各部门位于不同的地理位置，这种情况下就可以把不同位置的部分分别放在不同的子域，然后各部门通过自己的域来管理相对应的资源，并且每个子域都能拥有自己的安全策略。

![Untitled](%E5%86%85%E7%BD%91%E6%B8%97%E9%80%8F%E6%B5%8B%E8%AF%95%E5%9F%BA%E7%A1%80%20749199f90fc14676a9be7c290558218a/Untitled%201.png)

- 域树：域树是多个域通过建立信任关系组成的一个域集合。在域树中，域管理员只能管理本域，不能访问或者管理其他域。如何两个域之间需要相互访问，就需要建立信任关系（`Trust Relation`）。

![Untitled](%E5%86%85%E7%BD%91%E6%B8%97%E9%80%8F%E6%B5%8B%E8%AF%95%E5%9F%BA%E7%A1%80%20749199f90fc14676a9be7c290558218a/Untitled%202.png)

- 域林：域林是指由一个或多个没有形成连续名字空间的域树组成域树集合。

![Untitled](%E5%86%85%E7%BD%91%E6%B8%97%E9%80%8F%E6%B5%8B%E8%AF%95%E5%9F%BA%E7%A1%80%20749199f90fc14676a9be7c290558218a/Untitled%203.png)

### 域控制器

域控制器（`Domain Controller`，`DC`）是域环境核心的服务器计算机，用于在域中响应安全身份认证请求，负责允许或拒绝发出请求的主机访问域内环境，以及对用户进行身份验证、存储用户账户信息并执行域的安全策略等。

域控制器包含一个活动目录数据库，其中存储着整个域的账户、密码、计算机等信息。

一个域环境可以拥有一台或多台域控制器，每台域控制器各自存储一份所在域的活动目录的可写副本，对活动目录的任何修改都可以从源域控制器同步复制到域、域树或域林的其他控制器上。即使其中的一台域控制器瘫痪，另一台域控制器可以继续工作，以保证环境的正常运行。

## 活动目录

活动目录（`Active Directory`，`AD`）是指安装在域控制器上，为整个域环境提供集中式目录管理服务的组件。活动目录存储了有关域环境中各种对象的信息，如域、用户、用户组、计算机、组织单位、共享资源、安全策略等。目录数据存储在域控制器的`Ntds.dit`文件中。活动目录主要提供了以下功能：

- 计算机集中管理：集中管理所有加入域的服务器及客户端计算机，统一下发组策略。
- 用户集中管理：集中管理域用户、组织通讯录、用户组，对用户进行统一的身份认证、资源授权等。
- 资源集中管理：集中管理域中的打印机、文件共享服务等网络资源。
- 环境集中管理：集中的配置域中计算机的工作环境，如统一计算机桌面、统一网络连接配置，统一计算机安全配置等。
- 应用集中管理：对域中的计算机统一推送软件、安全补丁、防病毒系统，安装网络打印机等。

### Ntds.dit文件

该文件路径为域控制器的`%SystemRoot%\ntds\ntds.dit`，其中包括但不限于有关域用户、用户密码的哈希散列值、用户组、组成员身份和组策略的信息。`Ntds.dit`文件使用存储在系统`SYSTEM`文件的密钥对这些哈希值进行解密。

在非域环境（工作组环境）中，用户的登录凭证等信息存储在本地`SAM`文件中。

### 目录服务和LDAP

活动目录是一种目录服务数据库，目录数据库将所有数据组织成一个有层次的树状结构，其中的每个节点是一个对象，有关这个对象的所有信息作为这个对象的属性被存储，用户可以根据对象名称去查找这个对象的有关信息。

`LDAP`（`Lightweight Directory Access Protocol`，轻量级目录访问协议）是用来访问目录数据库的一个协议。

常见的基本概念：

- 目录树：在一个目录数据库中，整个目录中的信息集可以表示为一个目录信息数。树中的每一个节点是一个条目。
- 条目：目录数据库中的每个条目就是一条记录。每个条目有自己唯一绝对可辨识名称（`DN`）。
- `DN`（`Distinguished Name`，绝对可辨识名称）：指向一个`LDAP`对象的完整路径。`DN`由对象本体开始，向上延伸到域顶级的`DNS`命名空间。`CN`代表通用名（`Common Name`），`OU`代表组织单位（`Organizational Unit`），`DC`代表域组件（`Domain Component`）。例如，`CN=DC1, OU=Domain Controllers, DC=shentou, DC=com`的含义是`DC1`对象在`shentou.com`域的`Domain Controllers`组织单元中。
- `RDN`（`Relative Distinguished Name`，相对可辨识名称）：用于指向一个`LDAP`对象的相对路径。
- 属性：用于描述数据库中每个条目的具体信息。

### 活动目录分区

活动目录可以支持数以千万计的对象。为了扩大这些对象，微软将活动目录数据库划分为多个分区，以方便进行复制和管理。每个逻辑分区在域林中的域控制器之间分别复制、更改。这些分区被称为上下文命名（`Naming Context`，`NC`）。

活动目录预定义了域分区、配置分区和架构分区三个分区。

- 域分区（`Domain NC`）用于存储与该域有关的对象信息，这些信息是特定于该域的，如该域中的计算机、用户、组、组织单位等信息。在域林中，每个域的域控制器各自拥有一份属于自己的域分区，只会被复制到本域的所有域控制器中。
- 配置分区（`Configuration NC`）存储整个域林的主要配置信息，包括有关站点、服务、分区和整个活动目录结构的信息。整个域林共享一份相同的配置分区，会被复制到域林中所有域的控制器上。
- 架构分区（`Schema NC`）存储整个域林的架构信息，包括活动目录中的所有类，对象和属性的定义数据。整个域林共享一份相同的架构分区，会被复制到域林中所有域的控制器中。

### 活动目录的查询

- `LDAP`的按位查询
    
    在`LDAP`中，有些属性是位属性，它们由一个个位标志构成，不同的位可由不同的数值表示，属性的值为各位值的总和。此时不能再对某属性进行查询，而需要对属性的标志位进行查询。这就是`LDAP`的按位查询。
    
    ```powershell
    <属性名称>:<BitFilterRule-ID>:=<十进制的位值>
    
    # 其中<BitFilterRule-ID>指的就是位查询规则对应的ID
    ```
    
- 使用`AdFind`查询活动目录
    
    `AdFind`是一款`C++`语言编写的域中信息查询的工具，可以在域中任何一台主机使用，语法格式如下：
    
    ```powershell
    Adfind.exe [switches] [-b basedn] [-f filter] [attr list]
    
    # -b 指定一个BaseDN作为查询的根
    # -f 为LDAP过滤条件
    # attr list为需要显示的属性
    ```
    
    例如，查询`shentou.com`域中所有的`computer`对象，并过滤对象的`name`和`operatingSystem`属性，命令如下：
    
    ```powershell
    Adfind.exe -b "dc=shentou, dc=com" -f "objectClass=computer" name operatingSystem
    ```
    
    `AdFind`常用查询命令：
    
    - 查询`shentou.com`域中所有`computer`对象并显示所有属性：`Adfind.exe -b "dc=shentou, dc=com" -f "objectCla
ss=computer"`
    - 查询`shentou.com`域中所有`computer`对象并过滤对象的`name`和`operatingSystem`属性：`Adfind.exe -b "dc=shentou, dc=com" -f "objectClass=computer" name operatingSystem`
    - 查询指定主机的相关信息：`Adfind.exe -sc c:<Name/SamAccountName>`
    - 查询当前域中主机的数量：`Adfind.exe -sc adobjcnt:computer`
    - 查询当前域中被禁用的主机：`Adfind.exe -sc computers_disabled`
    - 查询当前域中不需要密码的主机：`Adfind.exe -sc computers_pwdnotreqd`
    - 查询当前域中在线的计算机：`Adfind.exe -sc computers_active`
    - 查询`shentou.com`域中所有`user`对象并过滤对象的`cn`属性：`Adfind.exe -b "dc=shentou, dc=com" -f "objectClass=user" cn`
    - 查询当前登录的用户用户信息和`Token`：`Adfind.exe -sc whoami`
    - 查询指定用户的相关信息：`Adfind.exe -sc u:<Name/SamAccountName>`
    - 查询当前域中所有用户：`AdFind.exe -users name`
    - 查询当前域中用户的数量：`Adfind.exe -sc adobjcnt:user`
    - 查询当前域中被禁用用户：`Adfind.exe -sc users_disbaled`
    - 查询当前域中密码永不过期的用户：`Adfind.exe -sc users_noexpire`
    - 查询当前域中不需要密码的用户：`Adfind.exe -sc users_pwdnotreqd`
    - 查询当前域中所有域控制器：`Adfind.exe -sc dclist`
    - 查询当前域中所有只读域控制器：`Adfind.exe -sc dclist:rodc`
    - 查询当前域中所有可读写域控制器：`Adfind.exe -sc dclist:!rodc`
    - 查询所有的组策略对象并显示所有属性：`Adfind.exe -sc gpodmp`
    - 查询域信任关系：`Adfind.exe -f "objectClass=trusteddomain"`
    - 查询`shentou.com`域中具有高权限的`SPN`：`Adfind.exe -b "dc=shentou, dc=com" -f "&(servicePrincipalName=*)(admincount=1)" servicePrincipalName`
    - 查询当前域中域管账户：`AdFind.exe -default -f "(&(|(&(objectCategory=person)(objectClass=user))(objectCategory=group))(adminCount=1))" -dn`
    - 查询当前域中配置非约束委派的用户：`AdFind.exe -b "DC=tubai,DC=com" -f "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=524288))" cn distinguishedName`
    - 查询当前域中配置非约束委派的主机：`AdFind.exe -b "DC=tubai,DC=com" -f "(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288))"`

## 域用户与机器用户

### 域用户

域用户，顾名思义，就是域环境中的用户，在域控制器中被创建，并且其所用信息都保存在活动目录中。域用户帐户位于域的全局组`Domain User`中，而计算机本地用户账户位于本地`User`组中。因此，域用户可以在域中的任何一台计算机上登录。执行以下命令，可以查看域中所有的域用户：

```powershell
net user /domain
```

### 机器用户

机器用户其实是一种特殊的域用户。在域环境中，计算机上的本地用户`SYSTEM`对应域中的机器用户，在域中的用户名就是`机器名+$`。例如，`Win7-PC1`在域中登录的用户名就是`Win7-PC1$`。执行以下命令，可以查看域中所有的机器用户：

```powershell
net group "Domain Computers" /domain
```

当获取到一台域中主机的控制权后，当没有发现域中用户凭据时，可以利用系统提权的方式，将当前用户提权到`SYSTEM`，以机器账户权限进行域内的操作。

## 域用户组的分类和权限

在域环境中，为了方便对用户权限进行管理，需要将具有相同权限的用户划分为一组，这样只要对这个用户组赋予了一定的权限，那么该组内的用户就获得了相同的权限。

### 组的用途

组（`Group`）是用户账户的集合，按照用途，可以分为通讯组和安全组。

通讯组就是一个通讯群组。例如，将某个部门所有员工拉进同一个通讯组，当给这个通讯组发送消息时，组内所有成员都可以收到。

安全组则是用户权限的集合。例如，管理员在日常的网络管理中，不必向每个用户账号都设置单独的访问权限，只需要创建一个组，对该组赋予权限，再将需要该权限的用户拉进改组即可。

### 安全组的权限

根据组的作用范围，安全组可以分为域本地组、通用组和全局组。

- 域本地组
    
    域本地组（`Domain Local Group`），主要用于访问同一个域中的资源。除了本组的用户，域本地组还可以包含域林中的任何一个域和通用组、全局组的用户，但是无法包含其他域中的域本地组。域本地组只能访问本域中的资源，无法访问其他不同域中的资源。
    
    ```powershell
    # 查询所有的域本地组
    Adfind.exe -b "dc=shentou, dc=com" -bit -f "(&(objectClass=group)(groupType:AND:=4))" cn -dn
    ```
    
    常见的系统内置的域本地组及其权限：
    
    - `Administrators`：管理员组，该组的成员可以不受限制地访问域中资源。
    - `Print Operators`：打印机操作员组，该组的成员可以管理网络中的打印机，还可以在本地登录和关闭域控制器。
    - `Backup Operators`：备份操作员组，该组的成员可以在域控制器中执行备份和还原操作，还可以在本地登录和关闭域控制器。
    - `Remote Desktop Users`：远程登录组，只有该组的成员才有远程登录服务的权限。
    - `Account Operators`：账号操作员组，该组的成员可以创建和管理域中用户和组，为其设置权限，也可以在本地登录域控制器。
    - `Server Operators`：服务器操作员组，该组的成员可以管理域服务器。
- 通用组
    
    通用组（`Universal Group`）可以作用于域林的所有域，其成员可以包括域林中任何域的用户账户、全局组和其他通用组，但是无法包含域本地组。通用组可以在域林中的任何域中被指派访问权限，以便于访问所有域中的资源。
    
    ```powershell
    # 查询所有通用组
    Adfind.exe -b "dc=shentou, dc=com" -bit -f "(&(objectClass=group)(groupType:AND:=8))" cn -dn
    ```
    
    常见的系统内置通用组及其权限：
    
    - `Enterprise Admins`：组织系统管理员组，该组是域林的根域中的一个组。该组的成员在域林的每个域中都是`Administrators`组的成员，因此对所有的域控制器都有完全的控制权。
    - `Schema Admins`：架构管理员组，该组是域林根域中的一个组。该组的成员可以修改活动目录，如在架构分区中新增类或属性。
- 全局组
    
    全局组（`Global Group`）可以作用于域林的所有域，是介于域本地组和通用组的组。全局组只能包含本域的用户。
    
    ```powershell
    # 查询所有的全局组
    Adfind.exe -b dc=hack, dc=com -bit -f "(&(ObjectClass=group)(groupType:AND:=2))" cn -dn
    ```
    
    常见的系统内置全局组及其权限：
    
    - `Domain Admins`：域管理员组，该组的成员在所有加入域的服务器上拥有完整的管理员权限。
    - `D
omain Users`：域用户组，该组的成员是所有的域用户。在默认情况下，任何新建的用户都是该组的成员。
    - `Domain Computers`：域成员主机组，该组的成员是域中所有的域成员主机，任何新建的计算机账户都是该组的成员。
    - `Domain Controllers`：域控制器组，该组的成员包含域中所有的控制器。
    - `Domain Guests`：域访客用户组，该组成员默认为域访客用户。
    - `Group Policy Creator Owners`：新建组策略对象组，该组的成员可以修改域的组策略。

## 访问控制

访问控制是指`Windows`操作系统使用内置授权和访问控制技术，确定经过身份验证的用户是否具有访问资源的正确权限，以控制主体（`Principal`）操作（读取、写入、删除、更改）对象（`Object`）的行为是否具有合法权限。

在`Windows`中，访问主体通常是指安全主体。安全主体是任何可通过操作系统进行身份认证的实体，如用户账户、计算机账户、在用户或计算机账户的安全上下文中运行的线程或进程，以及这些账户的安全组等。被访问的对象通常指安全对象，可能是文件、文件夹、打印机、注册表项、共享服务、活动目录域服务对象等。当经过身份验证的安全主体想访问安全对象时，`Windows`会为安全主体创建一个访问令牌（`Access Token`），其中包含验证过程返回的`SID`和本地安全策略分配给用户的用户权限列表。当安全对象被创建时，`Windows`会为其创建一个安全描述符（`Security Descriptor`）。`Windows`的访问控制正是将安全主体的访问令牌中的信息与安全对象的安全描述符中的访问控制项进行比较做出访问决策的。

### Windows访问控制模型

`Windows`访问控制模型（`Access Control Model`）主要由访问令牌（`Access Token`）和安全描述符（`Security Descriptor`）两部分构成，分别由访问者和被访问者持有。通过比较访问令牌和安全描述符的内容，`Windows`可以对访问者是否拥有访问资源对象的能力进行判定。

- 访问令牌
    
    当用户登录时，`Windows`将对用户进行身份验证，如果验证通过，就会为用户创建一个访问令牌，包括登录过程返回的`SID`、由本地安全策略分配给用户和用户所属安全组的特权列表。此后，代表该用户执行的每个进程都有此访问令牌的副本，每当线程或进程与安全对象交互或尝试执行需要特权的系统任务，`Windows`都会使用此访问令牌标识并确定关联的用户。
    
    访问令牌包括以下内容：
    
    - 标识用户账户的`SID`（`Security ID`，安全标识）
    - 标识用户所属的组的`SID`
    - 标识当前登录会话的`SID`
    - 用户或用户所处的用户组持有的特权列表
    - 标识对象所有者的`SID`
    - 标识对象所有者组的`SID`
    - 标识用户主安全组的`SID`
    - 用户创建安全对象而不指定安全描述符时系统使用的默认`DACL`（`Discretionary Access Control List`，自主访问控制列表）
    - 访问令牌的来源
    - 访问令牌的类型，主令牌还是模拟令牌
    - 限制`SID`的可选列表
    - 当前模拟等级
    - 其他信息
- 安全描述符
    
    安全描述符（`Security Descriptor`）是一种与每个安全对象相关联的数据结构，其中包含与安全对象相关联的安全信息，如谁拥有对象、谁可以访问对象、以何种方式访问、审查哪些类型的访问信息等。当安全对象被创建时，操作系统会为其创建一个安全描述符。安全描述符主要有`SID`和`ACL`（`Access Control List`，访问控制列表）组成。
    

### 访问控制列表

访问控制列表（`ACL`）时访问控制项（`Acess Control Entry`，`ACE`）的列表。访问控制列表中的每个访问控制项指定了一系列访问权限。`ACL`分为`DACL`和`SACL`两种。

- DACL
    
    `DACL`（自主访问控制列表）是安全对象的访问控制策略，其中定义了该安全对象的访问控制策略，用于指定允许或拒绝特定安全主体对该安全对象的访问。`DACL`是由一条条的访问控制项（`ACE`）条目构成的，每条`ACE`定义了哪些用户或组对该用户拥有怎样的访问权限。
    
- SACL
    
    `SACL`（`System Access Control List`，系统访问控制列表）是安全主体对安全对象的访问行为的审计策略。`SACL`也由一条条的`ACE`条目构成，每条`ACE`定义了对哪些安全主体的哪些访问行为进行日志记录，如对指定用户的访问成功、失败行为进行审计记录日志。安全主体的访问行为满足这条`ACE`时就会被记录。
    
- 查看与修改访问控制列表
    
    `Icacls`是一种命令行工具，使用`icalcs`命令可以查看或修改指定文件上的访问控制列表（`ACL`），并将存储的`DACL`应用于指定目录的文件。
    
    ```powershell
    # 查看指定文件的ACL
    icacls C:\Windows\System32
    icacls C:\Users\H3rmesk1t\Desktop\Test
    ```
    
    ![Untitled](%E5%86%85%E7%BD%91%E6%B8%97%E9%80%8F%E6%B5%8B%E8%AF%95%E5%9F%BA%E7%A1%80%20749199f90fc14676a9be7c290558218a/Untitled%204.png)
    
    `icacls`可以查询到的各种权限说明如下：
    
    - 简单权限序列：`N`，无访问权限；`F`，完全访问权限；`M`，修改权限；`RX`，读取和执行权限；`R`，只读权限；`W`，只写权限；`D`，删除权限。
    - 在`()`中以`,`分隔的特定权限列表：`DE`，删除；`RC`，读取控制；`WDAC`，写入`DAC`；`WO`，写入所有者；`S`，同步；`AS`，访问系统安全性；`MA`，允许的最大值；`GR`，一般性读取；`GW`，一般性写入；`GE`，一般性执行；`GA`，全为一般性；`RD`，读取数据/列出目录；`WD`，写入数据/添加文件；`AD`，附加数据/添加子目录；REA，读取扩展属性；`WEA`，写入扩展属性；`X`，执行/遍历；`DC`，删除子项；`RA`，读取属性；`WA`，写入属性。
    - 继承权限可以优先于每种格式，但只应用于目录：`OI`，对象继承；`CI`，容器继承；`IO`，仅继承；`NP`，不传播继承；`I`，从父容器继承的权限。
    
    常用命令如下：
    
    ```powershell
    # 将指定目录及子目录的所有文件的ACL备份到AclFile.txt中, /T为递归遍历所有子目录
    icacls C:\Users\H3rmesk1t\Desktop\Test\* /save AclFile.txt /T
    
    # 将AclFile.txt内所有备份的文件ACL还原到指定目录及其子目录
    icacls C:\Users\H3rmesk1t\Desktop\Test\ /restore AclFile.txt
    
    # 给用户Hacker添加指定文件或目录（及其子目录）的完全访问权限
    icacls C:\Users\H3rmesk1t\Desktop\Test\ /grant Hacker:(OI)(CI)(F) /t
    
    # 删除用户Hacker对指定文件夹或目录（及其子目录）的完全访问权限
    icacls C:\Users\H3rmesk1t\Desktop\Test\ /remove /t
    ```