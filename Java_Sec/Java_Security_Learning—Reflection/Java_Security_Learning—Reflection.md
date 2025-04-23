# Java Security Learning - Reflection

Author: H3rmesk1t

# Preface
> I have a rough understanding of Java's reflection mechanism before, and here I will further summarize the knowledge points of reflection in Java security

# Java reflection mechanism definition
> The Java reflection mechanism is in the running state. For any class, you can know all the properties and methods in this class.
> For any object, any method and property of it can be called
> This dynamically acquired information and the function of methods that dynamically call objects is called the reflection mechanism of the Java language

> It should be noted that Java's deserialization problems are based on reflection mechanism

# Java reflection mechanism function
> 1. Determine the class to which any object belongs at runtime
> 2. Construct objects of any class at runtime
> 3. Determine the member variables and methods of any class at runtime
> 4. Call any method at runtime
> 5. Generate dynamic proxy

# Java reflection mechanism application scenario
> 1. Reverse Code
> 2. A framework combined with annotation
> 3. Simple reflection mechanism application framework
> 4. Dynamically generate class framework

# Several common ways to use reflection
> Get class: forName()
> Instantiate the object of the class: newInstance()
> Get the function: getMethod()
> Execute function: invoke()

# Method to get Class object
```java
1.
Class demo1 = ReflectDemo.class;

2.
ReflectDemo reflectDemo = new ReflectDemo();
Class demo2 = reflectDemo.getClass();

3.
Class demo3 = Class.forName("reflectdemo.ReflectDemo");

4.
Class demo4 = ClassLoader.getSystemClassLoader().loadClass("reflectdemo.ReflectDemo");
```

# Get member variable Field
```java
import java.lang.reflect.Field

Field[] getFields(): Get all public modified member variables
Field[] getDeclaredFields(): Get all member variables, regardless of modifiers
Field getField(String name): Gets the public modified member variable of the specified name
Field getDeclaredField(String name): Get the specified member variable
```

# Get member method Method
```java
//The first parameter gets the name of the method, and the second parameter gets the parameter type that identifies the method
Method getMethod(String name, class <?>... parameterTypes) //Return the public method declared by this class
Method getDeclaredMethod(String name, class <?>... parameterTypes) //Return all methods declared by this class

Method[] getMethods() //Get all public methods, including the public methods declared by the class itself, the public methods in the parent class, and the implemented interface methods.
Method[] getDeclaredMethods() // Get all methods in this class
```

# Get the constructor
```java
Constructor<?>[] getConstructors() : Returns only the public constructor
Constructor<?>[] getDeclaredConstructors() : Returns all constructors
Constructor<> getConstructor(class<?>... parameterTypes) : A public constructor that matches the matching and parameter matching
Constructor<> getDeclaredConstructor(class<?>... parameterTypes): a constructor that matches and matches the parameter type.
```

# Create class objects using Java reflection mechanism
> Instantiated objects can be generated through reflection. Generally, the `newInstance()` method of the Class object is used to create class objects. The only way to use is to create the `newInstance()` method in the class object obtained by the `forName()` method

```java
Class demo = Class.forName("com.reflect.MethodDemo"); //Create Class object
Object test = demo.newInstance();
```

# Create classes and execute methods using Java reflection mechanism
```java
import java.lang.reflect.Method;

public class ReflectDemo {
    public void reflectMethod() {
        System.out.println("Successful reflection");
    }
    public static void main(String[] args) {
        try {
            Class demo = Class.forName("com.reflect.ReflectDemo"); //Create Class object
            Object test = demo.newInstance(); //Create an instance object
            Method method = demo.getMethod("reflectMethod"); //Create reflectMethod method
            method.invoke(test); //Calling the instance object method
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

# Command execution
> In addition to system classes, you need to use import first when you want to get a class, and using forName does not require this step. This is very advantageous when attacking, and you can load any class; at the same time, forName can get the internal class

> Sometimes, after obtaining the class through forName, using newInstance to call the parameterless constructor of this class will fail, for the reasons:

```java
1. The class used does not have a parameterless constructor
2. The class constructor used is private

For example: You cannot use the following Payload to directly execute commands, because the constructor of the Runtime class is private
Class demo = Class.forName("java.lang.Runtime");
demo.getMethod("exec", String.class).invoke(demo.newInstance(), "whoami");
```

> But there is still a way to get this class, which involves singleton pattern
> For example, for web applications, database connection only needs to be established once, instead of establishing a new connection every time the database is used. At this time, as a developer, you can set the constructor of the class used by the database connection to private, and then write a static method to obtain. The method to obtain this class is getInstance

```java
public class TrainDB {
	private static TrainDB instance = new TrainDB();
	public static TrainDB getInstance() {
		return instance;
	}
    private TrainDB() {
		// Code to establish the connection...
    }
```

> Refer to the above method, the Runtime class is a singleton pattern. The Runtime object can only be obtained through `Runtime.getRuntime()`. Payload is as follows

```java
Class demo = Class.forName("java.lang.Runtime");
demo.getMethod("exec", String.class).invoke(demo.getMethod("getRuntime").invoke(demo.newInstance(), "whoami"));
```

> Runtime.exec has 6 overloads, the first overload, it has only one parameter and type is String, so use `getMethod("exec", String.class)` to get the `Runtime.exec` method
> The function of invoke is to execute the method, its first parameter is:
> 1. If this method is a normal method, then the first parameter is the class object
> 2. If this method is a static method, then the first parameter is the class

> The normal execution method is `[1].method([2], [3], [4]…)`, which is `method.invoke([1], [2], [3], [4]…)` in reflection
> So break down the Payload executed by the above command

```java
Class demo = Class.forName("java.lang.Runtime");
Method execMethod = demo.getMethod("exec", String.class);
Method getRuntimeMethod = demo.getMethod("getRuntime");
Object runtime
= getRuntimeMethod.invoke(demo);
execMethod.invoke(runtime, "calc.exe");
```

<img src="./images/1.png" alt="">

# No constructor method and no singleton pattern static method to reflect instantiate the class
> Here we need to introduce a new reflection method `getConstructor`. Similar to `getMethod`, the parameters received by this method are the constructor list type. Since the constructor also supports overloading, the parameter list type must be used to uniquely determine a constructor. After obtaining the constructor class, use newInstance to execute it.

```java
The constructor of ProcessBuilder

public ProcessBuilder(List<String> command)
public ProcessBuilder(String... command)
```

> For example, another commonly used way of executing commands is `ProcessBuilder`, using reflection to get its constructor, and then calling `start()` to execute the command

```java
Class demo = Class.forName("java.lang.ProcessBuilder");
((ProcessBuilder) demo.getConstructor(List.class).newInstance(Arrays.asList("whoami"))).start();
```

> The first form of constructor is used above, so when `getConstructor` is passed `List.class`
> However, the previous Payload uses cast type conversion in Java. Sometimes when exploiting vulnerabilities (in the context of expressions), there is no such syntax, so reflection still needs to be used to complete this step.

```java
Class demo = Class.forName("java.lang.ProcessBuilder");
demo.getMethod("start").invoke(demo.getConstructor(List.class).newInstance(Arrays.asList(whoami)));
```

> Get the start method through `getMethod("start")`, and then execute invoke. The first parameter of invoke is `ProcessBuilder Object`. If you want to use the constructor `public ProcessBuilder(String… command)`, it involves the variable-length parameter `(varargs)` in Java. That is, when defining the function, you can use the syntax of `...` to express "the number of parameters of this function is variable". For variable-length parameters, Java will actually compile it into an array when compiling. The following two writing methods are equivalent at the bottom (that cannot be overloaded)

```java
public void hello(String[] names) {}
public void hello(String...names) {}
```

> For reflection, if the objective function to be retrieved contains variable length parameters, it can be processed as an array, so you can pass the class `String[].class` of the string array to `getConstructor` to get the second constructor of `ProcessBuilder`

```java
Class demo = Class.forName("java.lang.ProcessBuilder");
demo.getConstructor(String[].class);
```

> When calling `newInstance`, because this function itself receives a variable length parameter, the variable length parameter passed to `ProcessBuilder` is also a variable length parameter, and the two are superimposed into a two-dimensional array, so the entire Payload is as follows

```java
Class clazz = Class.forName("java.lang.ProcessBuilder");
((ProcessBuilder)clazz.getConstructor(String[].class).newInstance(new String[][]{{"whoami"}})).start();
```

# getDeclared series reflection
> getMethod series methods obtain all public methods in the current class, including methods inherited from the parent class
> getDeclaredMethod series methods obtain the "declared" method in the current class. They are actually written in this class, including private methods, but not methods inherited from the parent class.

> For example, I said before that the constructor of Runtime class is private, and you need to use `Runtime.getRuntime()` to get the object. Now you can also use `getDeclaredConstructor` to get this private constructor to instantiate the object, and then execute the command

```java
Class demo = Class.forName("java.lang.Runtime");
Constructor test = demo.getDeclaredConstructor();
test.setAccessible(true);
demo.getMethod("exec", String.class).invoke(test.newInstance(), "whoami");
```