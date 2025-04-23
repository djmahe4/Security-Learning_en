# Java Security Learning—OGNL Expression Injection

Author: H3rmesk1t

Data: 2022.03.18

# OGNL Introduction
[OGNL](https://commons.apache.org/proper/commons-ognl/) stands for Object-Graph Navigation Language; it is an expression language for getting and setting properties of Java objects, plus other extras such as list projection and selection and lambda expressions. You use the same expression for both getting and setting the value of a property.

The Ognl class contains convenience methods for evaluating OGNL expressions. You can do this in two stages, parsing an expression into an internal form and then using that internal form to either set or get the value of a property; or you can do it in a single stage, and get or set a property using the String form of the expression directly.

# OGNL Three Elements
 - Expression: Expression is the core content of the entire `OGNL`, and all `OGNL` operations are parsed for expressions. The `OGNL` operation is told through expressions what to do. Therefore, an expression is actually a string with syntactic meaning, and the entire string will specify the type and content of the operation. The `OGNL` expression supports a large number of expressions, such as "chain access objects", expression calculations, and even `Lambda` expressions.
 - `Root` object: The `OGNL`'s `Root` object can be understood as an operation object of `OGNL`. When an expression is specified, you need to specify which specific object the expression is targeted. This specific object is the `Root` object, which means that if there is an `OGNL` expression, you need to calculate the `OGNL` expression for the `Root` object and return the result.
 - Context environment: With a `Root` object and expression, you can use `OGNL` to perform simple operations, such as assigning and taking values ​​to the `Root` object. However, in fact, all operations will run in a specific data environment inside OGNL. This data environment is the context environment (Context). The context environment of `OGNL` is a `Map` structure, called `OgnlContext`. The `Root` object will also be added to the context environment. In short, the context is a `MAP` structure, which implements the interface of `java.utils.Map`.

In `Struct2`, the `Context` of `OGNL`, and the `ValueStack` contained in it is the `Root` of `OGNL`.

## ActionContext
`ActionContext` is a context object, corresponding to `OGNL`'s `Context`, an object that uses `MAP` as a structure and uses key-value pair relationships to describe properties and values ​​in an object. Simply put, it can be understood as a small database of `action`. The data used in the entire `action` life cycle (thread) is in this `ActionContext`.

<div align=center><img src="./images/1.png"></div>

In addition to the three common scopes `request`, `session`, and `application`, there are three scopes:
 - `attr`: Save all attributes of the above three scopes. If there are duplicates, the attributes in the `request` field are used as the basis;
 - `paramters`: Save the parameters of form submission;
 - `VALUE_STACK`: Value stack, which saves the `valueStack` object, that is, the value in `valueStack` can be accessed through `ActionContext`.

## ValueStack
ValueStack is where the OGNL expression accesses data. All data required for a request is encapsulated in a value stack.

In projects using `Struts2`, `Struts2` will create a new value stack for each request, that is, the value stack and the request are one-to-one corresponding relationships. This one-to-one corresponding relationship enables the value stack to provide public data access services for each request thread-safely.

The value stack can be used as a data transit station to pass data between the foreground and the background. The most common one is to use the tag of Struts2 with the OGNL expression. The value stack is actually an interface. When using OGNL in Struts2, the OgnlValueStack class that implements the interface is actually used. This class is the basis of OGNL. The value stack runs through the entire life cycle of Action. Each object instance of the Action class has a ValueStack object, and the current Action object and other related objects are saved in the ValueStack object. To obtain the data stored in the value stack, you should first obtain the value stack. There are two ways to obtain the value stack.

### Get value stack in request
The storage method of the `ValueStack` object in the range of `request` is `request.setAttribute("struts.valueStack",valuestack)`. You can extract the information of the value stack from `request` in the following ways:

```java
//Get the ValueStack object and get it through the request object
ValueStack valueStack = (ValueStack)ServletActionContext.getRequest().getAttribute(ServletActionContext.STRUTS_VALUESTACK_KEY);
```

### Get value stack in ActionContext
When using the `Struts2` framework, you can use the `OGNL` operation `Context` object to access data from the `ValueStack`, that is, you can get the `ValueStack` object from the `Context` object. In fact, the `Context` object in the `Struts2` framework is `ActionContext`.

The way to get the `ValueStack` object in `ActionContext` is as follows:

```java
// Get the valueStack object through ActionContext.
ValueStack valueStack = ActionContext.getContext().getValueStack();
```

The `ActionContext` object is created in the `StrutsPrepareAndExcuteFilter#doFilter` method. The information of the obtained `ValueStack` object can be found in the `createActionContext` method used to create the `ActionContext` object in the source code. There is also a piece of code in the method:

```java
ctx = new ActionContext(stack.getContext());
```

From the above code, we can see that the `Context` object in the `ValueStack` object is passed as a parameter to the `ActionContext` object, which means that the `ActionContext` object holds a reference to the `ValueStack` object, so the `ValueStack` object can be obtained through the `ActionContext` object.

# OGNL Basic Syntax
`OGNL` supports various complex expressions, but the most basic expression prototype is to connect the reference values ​​of the object from left to right with points. The result returned by each expression calculation becomes the current object. The subsequent part is then calculated on the current object until all expressions are calculated and the final object is returned. `OGNL` continues to expand this basic principle, so that it supports access to object trees, arrays, containers, and even projection selection in `SQL`.

## Basic object tree access
Access to the object tree is done by using dot numbers to concatenate references to objects, for example:

```java
xxxx
xxxx.xxxxx
xxxx.xxxx.xxxxxx.xxxxxxx
```

## Container variable access
Access to container variables is performed by adding an expression to `#`, for example:

```java
#xxxx
#xxxx.xxxx
#xxxx.xxxx.xxxx.xxxxx
```

## Operator symbol
The operators that can be used in the `OGNL` expression are basically the same as those in `Java`. In addition to using operators such as `+`, `-`, `*`, `/`, `++`, `--`, `==`, `!=`, `=`, `=`, etc., you can also use `mod`, `in`, `not in`, etc.

## Containers, arrays, objects
`OGNL` supports sequential access to containers such as arrays and `ArrayList`, for example: `group.users[0]`. At the same time, `OGNL` supports key-value search for `Map`, for example: `#session['mySessionPropKey']`. Not only that,
`OGNL` also supports container-constructed expressions, for example: `{"green", "red", "blue"}` construct a `List`, `#{"key1" : "value1", "key2" : "value2", "key3" : "value3"}` construct a `Map`. You can also create a new object through the constructor of any class object, for example: `new Java.net.URL("xxxxx/")`.

## Access to static methods or variables
To reference static methods and fields of a class, they are expressed in the same way as `@class@member` or `@class@method(args)`, for example: `@com.javaeye.core.Resource@ENABLE`, `@com.javaeye.core.Resource@getAllResources`.

## Method call
It is directly used to call method similar to `Java`, and even parameters can be passed, such as: `user.getName()`, `group.users.size()`, `group.containsUser(#requestUser)`.

## Projection and selection
`OGNL` supports projection and selection similar to databases.

Projection is to select the same attributes of each element in the collection to form a new set, similar to the field operation of a relational database. The projection operation syntax is `collection.{XXX}`, where `XXX` is the public attribute of each element in this collection. For example: `group.userList.{username}` will get a list of all `users` names in a certain `group`.

Selection is to filter collection elements that meet the `selection` condition, similar to the record operation of a relational database. The syntax of the selection operation is: `collection.{X YYY}`, where `X` is a selection operator, followed by a logical expression for selection. There are three types of selection operators:
 - `?`Select all elements that meet the criteria.
 - `^`Select the first element that satisfies the condition.
 - `$`Select the last element that satisfies the condition.

For example: `group.userList.{? #txxx.xxx != null}` will get a list of `name` of `user` whose `name` is not empty in a `group`.

# OGNL Syntax Tree
There are two forms of the `OGNL` syntax tree. Each bracket corresponds to a branch on the syntax tree, and parses and executes from the rightmost leaf node:
 - (expression)(constant) = value
 - (constant)((expression1)(expression2))

# Others
## . Symbols
All `OGNL` expressions complete the evaluation operation based on the context of the current object. The results of the previous part of the chain will be used as the context of the subsequent evaluation, for example:

```java
name.toCharArray()[0].numbericValue.toString()
```

 - Extract the `name` property of the root (`root`) object.
 - Call the `toCharArray` method of the result string returned in the previous step.
 - Extract the first character of the returned result array.
 - Get the `numbericValue` property of a character, which is a `Character` object, and the `Character` class has a `getNumeericValue` method.
 - Call the `toString` method of the result `Integer` object.

## %, #, $
### # Talisman
The `#` symbol has three main uses:
 - Access the non-root object properties, that is, accessing the `OGNL` context and the `Action` context. Since the `Struts2` median stack is regarded as the root object, you need to add the `#` prefix when accessing other non-root objects. `#` is equivalent to `ActionContext.getContext()`;
 - Used for filtering and projecting (`projecting`) collections, for example: `books.{? #this.price<100}`;
 - Used to construct `Map`, for example `#{'foo1':'bar1', 'foo2':'bar2'}`.

### % symbol
The purpose of the `%` symbol is to tell the execution environment that the OGNL expression in `%{}` when the attribute of the flag is of a string type and calculate the value of the expression.

### $ symbol
The main function of the `$` symbol is to introduce `OGNL` expressions in related configuration files, so that they can parse `OGNL` expressions in configuration files.

## ., #, @ the difference
 - Use `@` when obtaining static functions and variables.
 - Use the `.` sign to obtain non-static functions.
 - Use `#` to obtain non-static variables.

# Difference between OGNL and EL
 1. The `OGNL` expression is the default expression language for `Struts2`, so it is only valid for `Struts2` tags; however `EL` can also be used in `HTML`.
 2. The `Struts2` tag uses the `OGNL` expression language, so most of them go to the top of the value stack to find the value, and then go to the scope if it cannot be found; on the contrary, `EL` is all searched in the `Map` collection scope.

# API that can parse OGNL
The API that can parse `OGNL` is shown in the following table:

|Class name |Method name |
|:---:|:---:|
|com.opensymphony.xwork2.util.TextParseUtil|translateVariables, translateVariablesCollection|
|com.opensymphony.xwork2.util.TextParser|evaluate|
|com.opensymphony.xwork2.util.OgnlTextParser|evaluate|
|com.opensymphony.xwork2.ognl.OgnlUtil|setProperties, setProperty, setValue, getValue, callMethod, compile|
|org.apache.struts2.util.VelocityStrutsUtil|evaluate|
|org.apache.struts2.util.StrutsUtil|isTrue, findString, findValue, getText, translateVariables, makeSelectList|
|org.apache.struts2.views.jsp.ui.OgnlTool|findValue|
|com.opensymphony.xwork2.util.ValueStack|findString, findValue, setValue, setParameter|
|com.opensymphony.xwork2.ognl.OgnlValueStack|findString, findValue, setValue, setParameter, trySetValue|
|ognl.Ognl|parseExpression, getValue, setValue|

Some classes that may be involved during the call:

|Involved class name|Method name|
|:---:|:---:|
|com.opensymphony.xwork2.ognl.OgnlReflectionProvider|getGetMethod, getSetMethod, getField, setProperties, setProperty, getValue, setValue|
|com.opensymphony.xwork2.util.reflection.ReflectionProvider|getGetMethod, getSetMethod, getField, setProperties, setProperty, getValue, setValue|

# OGNL expression injection vulnerability
## Vulnerability Principle
The above mentioned that OGNL can access static methods, properties, object methods, etc., including the class `java.lang.Runtime` that can perform malicious operations such as command execution. When the OGNL expression is externally controllable, the attacker can construct malicious OGNL expressions to let the program perform malicious operations. This is the `OGNL` expression injection vulnerability.

## POC
You can see that both `getValue` and `setValue` can successfully parse malicious `OGNL` expressions.


```java
package h3rmek1t.javawebsecurity;

import ognl.Ognl;
import ognl.OgnlContext;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/3/19 1:34 am
 */
public class ognlExploit {

    public static void main(String[] args) throws Exception {

        // Create an OGNL context object.
        OgnlContext ognlContext = new OgnlContext();

        // Trigger getValue.
        Ognl.getValue("@java.lang.Runtime@getRuntime().exec('open -a Calculator')", ognlContext, ognlContext.getRoot());

        // Trigger setValue.
        Ognl.setValue(Runtime.getRuntime().exec("open -a Calcula
tor"), ognlContext, ognlContext.getRoot());
    }
}
```

<div align=center><img src="./images/2.png"></div>

<div align=center><img src="./images/3.png"></div>

## Process Analysis
Set a breakpoint at `Ognl.getValue`, follow up on the `Ognl#getValue` method, and call the `Ognl#parseExpression` method, which parses the string of type passed in `String` to the `ASTChain` type that the `OGNL` expression can understand.

<div align=center><img src="./images/4.png"></div>

Then convert the `tree` parameter of the passed `ASTChain` type into `Node` type (`ASTChain` inherits from `SimpleNode` and `SimpleNode` is inherited from `Node`), and then call its `getValue` function to continue parsing.

<div align=center><img src="./images/5.png"></div>

Follow up on `SimpleNode#evaluateGetValueBody`, and you can see that it will continue to call the `getValueBody` method.

<div align=center><img src="./images/6.png"></div>

Then follow up with `ASTMethod#getValueBody`, where the expression of each node in `ASTChain` will be parsed loopfully. There are two child nodes here. First, the first node, namely `@java.lang.Runtime@getRuntime()`, the OGNL expression, and then the `OgnlRuntime#callMethod` will be called.

<div align=center><img src="./images/7.png"></div>

Follow up on `OgnlRuntime#callMethod`, and then call `ObjectMethodAccessor#callMethod`. After obtaining the `getRuntime` method of the `java.lang.Runtime` class, the `OgnlRuntime#callAppropriateMethod` method will be further called for parsing.

<div align=center><img src="./images/8.png"></div>

<div align=center><img src="./images/9.png"></div>

Follow up on `OgnlRuntime#callAppropriateMethod`, here we call the class method in the `OGNL` expression by calling the `invokeMethod` function.

<div align=center><img src="./images/10.png"></div>

Follow up on the `invokeMethod` function, `Method.invoke` will be called, that is, the `java.lang.Runtime.getRuntime` method is called through the reflection mechanism.

<div align=center><img src="./images/11.png"></div>

<div align=center><img src="./images/12.png"></div>

Simply put, the `getValue` parsing process of the `OGNL` expression is to first divide the entire `OGNL` expression into several child node trees according to the syntax tree, and then loop through and parse the `OGNL` expression on each child node tree. In which arbitrary class method calls are implemented through `Method.invoke`, that is, reflection, and the class methods obtained by the parsing of each node are connected together to achieve complete expression parsing and obtain complete class method calls.

# Payload
```java
// Get the variables in the Context.
 #user
 #user.name

// Use Runtime to execute system commands.
@java.lang.Runtime@getRuntime().exec("open -a Calculator")


// Use Processbuilder to execute system commands.
(new java.lang.ProcessBuilder(new java.lang.String[]{"open", "-a", "Calculator"})).start()

// Get the current path.
@java.lang.System@getProperty("user.dir")
```

# refer to
 - [OGNL Expression Injection Vulnerability Summary](https://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/)