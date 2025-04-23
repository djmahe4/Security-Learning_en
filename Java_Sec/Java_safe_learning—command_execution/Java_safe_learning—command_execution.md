# Java Security Learning—Command Execution

Author: H3rmesk1t

# Relation

The main methods for executing commands in `Java` include `java.lang.Runtime#exec()`, `java.lang.ProcessBuilder#start()` and `java.lang.ProcessImpl#start()`. The call relationship between them is shown in the figure below.

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=NjcyYTZiZTQ1ZmQ4NTFmZGViMmMzMGI2NmMzYWQ0NmNfZXVuM0hBWjFQdHJEZkxYMVF2UnhtYWhTeWFsQzBEWGZfVG9rZW46Ym94Y25KTWQ2aVV2QTBkRWcxRWp0ZGtsVUxiXzE2NjU5ODY1OTI6MTY2NTk5MDE5Ml9WNA)

# Runtime

The most common way to execute commands in `Java` is to use `java.lang.Runtime#exec` method to execute local system commands.

```Java
package com.security;

import org.apache.commons.io.IOUtils;

import java.io.InputStream;

public class RuntimeExecDemo {

    public static void main(String[] args) throws Exception {

        InputStream inputStream = Runtime.getRuntime().exec("whoami").getInputStream();
        System.out.println(IOUtils.toString(inputStream, "gbk"));
    }
}
```

At some moments, for some special reasons, the keywords related to `Runtime` may not appear, and this can be implemented in the form of reflection.

```Java
package com.security.CommandExecution;

import org.apache.commons.io.IOUtils;

import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.Arrays;

public class RuntimeReflectDemo {

    public static void main(String[] args) throws Exception {

        String className = "java.lang.Runtime";
        byte[] classNameBytes = className.getBytes(); // [106, 97, 118, 97, 46, 108, 97, 110, 103, 46, 82, 117, 110, 116, 105, 109, 101]
        System.out.println(Arrays.toString(classNameBytes));

        String methodName = "getRuntime";
        byte[] methodNameBytes = methodName.getBytes(); // [103, 101, 116, 82, 117, 110, 116, 105, 109, 101]
        System.out.println(Arrays.toString(methodNameBytes));

        String methodName2 = "exec";
        byte[] methodNameBytes2 = methodName2.getBytes(); // [101, 120, 101, 99]
        System.out.println(Arrays.toString(methodNameBytes2));

        String methodName3 = "getInputStream";
        byte[] methodNameBytes3 = methodName3.getBytes(); // [103, 101, 116, 73, 110, 112, 117, 116, 83, 116, 114, 101, 97, 109]
        System.out.println(Arrays.toString(methodNameBytes3));

        String payload = "whoami";
        //Reflect java.lang.Runtime class to get class object
        Class<?> clazz = Class.forName(new String(new byte[]{106, 97, 118, 97, 46, 108, 97, 110, 103, 46, 82, 117, 110, 116, 105, 109, 101}));
        // Reflection to get the getRuntime method of Runtime class
        Method method1 = clazz.getMethod(new String(new byte[]{103, 101, 116, 82, 117, 110, 116, 105, 109, 101}));
        // Reflection to get the exec method of Runtime class
        Method method2 = clazz.getMethod(new String(new byte[]{101, 120, 101, 99}), String.class);
        //Reflection calls Runtime.getRuntime().exec() method
        Object obj = method2.invoke(method1.invoke(null, new Object[]{}), new Object[]{payload});
        //Reflection to get the getInputStream method of the Process class
        Method method3 = obj.getClass().getMethod(new String(new byte[]{103, 101, 116, 73, 110, 112, 117, 116, 83, 116, 114, 101, 97, 109}));
        method3.setAccessible(true);

        InputStream inputStream = (InputStream) method3.invoke(obj, new Object[]{});
        System.out.println(IOUtils.toString(inputStream, "gbk"));

    }
}
```

The call chain of the `Runtime.exec()` method under `Windows` is roughly as follows. You can see that it matches the call relationship chain mentioned above:

```Java
<init>:320, ProcessImpl (java.lang)
start:137, ProcessImpl (java.lang)
start:1029, ProcessBuilder (java.lang)
exec:620, Runtime (java.lang)
exec:450, Runtime (java.lang)
exec:347, Runtime (java.lang)
main:11, RuntimeDemo (com.security.CommandExecution)
```

# ProcessBuilder

The `ProcessBuilder` class is used to create operating system processes. Each ProcessBuilder instance manages a set of process attributes, and its start method uses these attributes to create processes. Since `java.lang.Runtime#exec()` will be called to `java.lang.ProcessBuilder#start()` later, and `ProcessBuilder#start()` is of public` type, you can also use it to execute commands directly.

```Java
package com.security.CommandExecution;

import org.apache.commons.io.IOUtils;

import java.io.InputStream;

public class ProcessBuilderDemo {

    public static void main(String[] args) {

        try {
            InputStream inputStream = new ProcessBuilder("ipconfig", "/all").start().getInputStream();
            System.out.println(IOUtils.to
String(inputStream, "gbk"));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

# ProcessImpl

The `java.lang.ProcessImpl` class cannot be called directly, but the `ProcessImpl#start()` can be indirectly called through reflection to achieve the purpose of command execution.

```Java
package com.security.CommandExecution;

import org.apache.commons.io.IOUtils;

import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.Map;

public class ProcessImplDemo {

    public static void main(String[] args) {

        try {
            String[] exp = {"cmd", "/c", "ipconfig", "/all"};
            Class<?> clazz = Class.forName("java.lang.ProcessImpl");
            Method method = clazz.getDeclaredMethod("start", String[].class, Map.class, String.class, ProcessBuilder.Redirect[].class, boolean.class);
            method.setAccessible(true);

            InputStream inputStream = ((Process) method.invoke(null, exp, null, ".", null, true)).getInputStream();
            System.out.println(IOUtils.toString(inputStream, "gbk"));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

# ScriptEngine

The `javax.script.ScriptEngine` class is a `java` built-in for parsing and executing `JS` code. There is an eval method in the `ScriptEngine` interface that can execute `Java` code. But it should be noted that it needs to be effective in an environment with corresponding `engine`.

```Java
package com.security.CommandExecution;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

public class ScriptEngineDemo {

    public static void main(String[] args) throws ScriptException {

        String exp = "function demo() {return java.lang.Runtime};d=demo();d.getRuntime().exec(\"calc\")";
        // String exp = "var test=Java.type(\"java.lang.Runtime\"); print(test.getRuntime().exec(\"calc\"))";
        // String exp = "var CollectionsAndFiles = new JavaImporter(java.lang); with (CollectionsAndFiles){var x= Runtime.getRuntime().exec(\"calc\")}";
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("js");
        engine.eval(exp);
    }
}
```

# JShell

Starting from `Java 9, a function called `jshell` is a `REPL (Read-Eval-Print Loop)` command line tool, providing an interactive command line interface. In `jshell`, we no longer need to write classes or execute Java code snippets. Developers can happily write test code on the command line like `python` and `php`.

```Java
package com.security.CommandExecution;

import jdk.jshell.JShell;

public class JShellDemo {

    public static void main(String[] args) {

        try {
            JShell.builder().build().eval(new String(Runtime.getRuntime().exec("calc").getInputStream().readAllBytes()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

#Others

## Windows

In `Windows`, when writing files and other operations are to be performed, the command prefix should be added with `cmd ``/``c`. In the following example code when executing `echo "h3rmesk1t" > 1.txt`, you can see that the execution cannot be successful.

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=ZTU5M2VkYjQwYmIxMmMyNjEwZGFlMWFiNDgyYWIxZWRfdHhacFlURUllWTFCOWRxTjE4Z2VUaGUwd2dXNmFKWHJfVG9rZW46Ym94Y252QzEydjVDU2pSSHYxOWFXaFNrUXBiXzE2NjU5ODY1OTI6MTY2NTk5MDE5Ml9WNA)

Follow up at the breakpoint and enter `java.lang.Runtime#exec(String command)` first.

```Java
public Process exec(String command) throws IOException {
    return exec(command, null, null);
}
```

Continue to follow up and enter `java.lang.Runtime#exec(String command, String[] envp, File dir)`. Here we will first determine whether the incommand is empty. When it is not empty, it will be passed into the `StringTokenizer` class.

```Java
public Process exec(String command, String[] envp, File dir)
    throws IOException {
    if (command.length() == 0)
        throw new IllegalArgumentException("Empty command");

    StringTokenizer st = new StringTokenizer(command);
    String[] cmdarray = new String[st.countTokens()];
    for (int i = 0; st.hasMoreTokens(); i++)
        cmdarray[i] = st.nextToken();
    return exec(cmdarray, envp, dir);
}
```

Follow up on the `StringTokenizer` class, where the passed string will be divided according to `\t\n\r\f` and spaces.

```Java
public StringTokenizer(String str) {
    this(str, " \t\n\r\f", false);
}
```

You can see that before further calling `java.lang.Runtime#exec(String[] cmdarray, String[] envp, File dir)`, the string of the command to be executed is changed to `["echo", ""h3rmesk1t"", ">", "C:\Users\95235\Downloads\1.txt"]`.

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/downlo
ad/asynccode/?code=MjdhYmQzOTE4OTdmM2NlYWI0YTQxNzVjNzRmYmYyN2VfUUxhWTM4ampaM0dvZUdwVExUQzFKb1VzTVQ4eDhSWHhfVG9rZW46Ym94Y25HZFNlbHF4TGhDRHpvZ0hhN3ZPSUxjXzE2NjU5ODY1OTI6MTY2NTk5MDE5Ml9WNA)

Then pass in `ProcessBuilder`, and finally come to `ProcessImpl`, the underlying layers of `Runtime` and `ProcessBuilder` are actually `ProcessImpl`. The reason why the echo command cannot be executed is because Java cannot find this thing and has no environment variables, so just add `cmd /c`.

![img](https://o5szcykwgn.feishu.cn/space/api/box/stream/download/asynccode/?code=ZDhhZmY5ODJlZDc1NGU5YTBlMDcxM2UzZTgwMzgzZjhfVmZaUHhPM2NvSmJSQWN6OEZwNVowaEdOWWt3NVpSU1dfVG9rZW46Ym94Y255NGt5VHVkaXBOcjN2VHFxTHZnOHNlXzE2NjU5ODY1OTI6MTY2NTk5MDE5Ml9WNA)

## Linux

There are similar problems in the Linux environment, such as `/bin/sh -c echo 1 > 1.txt`, although the file will be created, the file has no content, because `/bin/sh -c` requires a string as a parameter to execute. When the subsequent string is a string, according to the above analysis, after passing through the `StringTokenizer` class, the entire command becomes `{"/bin/sh","-c","echo","echo","1",">","1.txt""}`.

Therefore, in the `Linux` environment, the command can be executed in the form of array or `Base64` encoding.

```Java
Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", "echo 1 > 1.txt"});

/bin/bash -c {echo,base64-encode-string}|{base64,-d}|{bash,-i}
```