# Java Security Learning—Javassist

Author: H3rmesk1t

## Definition

> `Java` bytecode is stored in the `.class` file in binary form. Each `.class` file contains a `Java` class or interface. `Javaassist` is a class library used to process `Java` bytecode. It can add new methods to a compiled class, or modify existing methods, and does not require in-depth understanding of bytecode. At the same time, it can also generate a new class object, which can be completely manual.

## Create class file
> Create object's class demo code

```java
package CommonsCollections2;

import javassist.*;

/**
 * @Author: H3rmesk1t
 * @Data: 2021/11/26 3:09 pm
 */
public class JavassistCreateDemo {
    /**
     * Create a Demo object
     */
    public static void main(String[] args) {
        try {
            createDemo();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void createDemo() throws Exception {
        ClassPool classPool = ClassPool.getDefault();

        // Create an empty class
        CtClass ctClass = classPool.makeClass("com.commons-collections.CommonsCollections2.javassist.Demo");
        // Add a field name way
        CtField ctField = new CtField(classPool.get("java.lang.String"), "way", ctClass);
        // Set the access level to private
        ctField.setModifiers(Modifier.PRIVATE);
        // Set initial information
        ctClass.addField(ctField, CtField.Initializer.constant("Misc"));

        // Generate getter and setter methods
        ctClass.addMethod(CtNewMethod.setter("setWay", ctField));
        ctClass.addMethod(CtNewMethod.getter("getWay", ctField));

        // Set the parameterless constructor
        CtConstructor ctConstructor = new CtConstructor(new CtClass[]{}, ctClass);
        ctConstructor.setBody("{way = \"Misc\";}");
        ctClass.addConstructor(ctConstructor);

        // Set a parameter constructor
        CtConstructor ctConstructor1 = new CtConstructor(new CtClass[]{classPool.get("java.lang.String")}, ctClass);
        ctConstructor1.setBody("{$0.way = $1;}");
        ctClass.addConstructor(ctConstructor1);

        // Create printWayName method
        CtMethod ctMethod = new CtMethod(CtClass.voidType, "printWayName", new CtClass[]{}, ctClass);
        ctMethod.setModifiers(Modifier.PUBLIC);
        ctMethod.setBody("{System.out.println(way);}");
        ctClass.addMethod(ctMethod);

        // Compile the content of the construct
        ctClass.writeFile("/Users/h3rmesk1t/Desktop/commons-collections/src/main/java/CommonsCollections2");
    }
}
```
> The generated Demo.class file content

```java
//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.commons-collections.CommonsCollections2.javassist;

public class Demo {
    private String way = "Misc";

    public void setWay(String var1) {
        this.way = var1;
    }

    public String getWay() {
        return this.way;
    }

    public Demo() {
        this.way = "Misc";
    }

    public Demo(String var1) {
        this.way = var1;
    }

    public void printWayName() {
        System.out.println(this.way);
    }
}
```
> In `Javassist`, the class `Javaassit.CtClass` represents the `class` file. A `CtClass` object can process a `class` file. ClassPool` is a container for the `CtClass` object. It reads the class file as needed to construct the `CtClass` object and saves the `CtClass` object for later use. It should be noted that `ClassPool` will maintain all `CtClass created by it in memory. When the `CtClass` is too much, it will occupy a lot of memory. The solution given in `API` is to consciously call the `detach()` method of `CtClass` to free up memory.

> ClassPool:
> 1. `getDefault`: Returns the default `ClassPool` is singleton mode, and the `ClassPool` is generally created through this method
> 2. `appendClassPath`, `insertClassPath`: Add a `ClassPath` to the end of the class search path or insert it to the starting position. Usually, the additional class search path is written through this method to solve the problem that the class cannot be found in multiple class loader environments
> 3. `toClass`: Load the modified `CtClass` into the context class loader of the current thread. The `toClass` method of `CtClass` is implemented by calling this method. It should be noted that once the method is called, it cannot continue to modify the already loaded `class`
> 4. `get`, `getCtClass`: Get the `CtClass` object of this class based on the classpath name for subsequent editing

> CtClass:
> 1. `freeze`: Freeze a class so that it is not modifyable
> 2. `isFrozen`: determines whether a class has been frozen
> 3. `prune`: Delete unnecessary properties of the class to reduce memory usage. It should be noted that many methods cannot be used normally after calling this method.
> 4. `defrost`: Unfreeze a class so that it can be modified. If you know in advance that a class will be `defrost`, then the call to the `prune` method is prohibited.
> 5. `detach`: Remove the `class` from `ClassPool`
> 6. `writeFile`: Generate `.class` file based on `CtClass`
> 7. `toClass`: Load the `CtClass` through the class loader


> CtMethod:
> 1. `insertBefore`: Insert code at the start position of the method
> 2. `insterAfter`: Insert code before all `return` statements of the method to ensure that the statement can be executed unless an `exception` is encountered
> 3. `insertAt`: Insert code at the specified location
> 4. `setBody`: Set the content of the method to the code to be written. When the method is modified by `abstract`, the modifier is removed
> 5. `make`: Create a new method

## Call the generated class object
### Reflection call

> Change part of the code written to the file with the following code
```java
Object demo = ctClass.toClass().getInterfaces();
Method setWay = de
mo.getClass().getMethod("setWay", String.class);
setWay.invoke(demo, "Web");
Method execute = demo.getClass().getMethod("printWayName");
execute.invoke(demo);
```

### Read .class file call

```java
ClassPool classPoll = ClassPool.getDefault();
// Set the classpath
pool.appendClassPath("/Users/h3rmesk1t/Desktop/commons-collections/src/main/java/");
CtClass ctClass = classPoll.get("com.commons-collections.CommonsCollections2.javassist.Demo");
Object demo = ctClass.toClass().newInstance();
// ...... The following is used the same as through reflection
```

### Interface call
> Create a new `DemoI` ​​interface class

```java
package CommonsCollections2;

public interface DemoI {
    void setWay(String name);
    String getWay();
    void printWayName();
}
```
> Implementation Part
```java
ClassPool classPool = ClassPool.getDefault();
pool.appendClassPath("/Users/h3rmesk1t/Desktop/commons-collections/src/main/java/");

CtClass codeClassI = classPool.get("CommonsCollections2.PersonI");
CtClass ctClass = classPool.get("CommonsCollections2.Person");
ctClass.setInterfaces(new CtClass[]{codeClassI});

DemoI demo = (DemoI)ctClass.toClass().newInstance();
System.out.println(demo.getWay());
demo.setWay("xiaolv");
demo.printWay();
```

## Modify existing classes
> The usage scenarios that you encounter should be to modify existing classes, such as common log sections, and permission sections are all used to implement this function.

> For example, the following class object

```java
public class PersonService {

    public void getPerson(){
        System.out.println("get Person");
    }
    public void personFly(){
        System.out.println("oh my god,I can fly");
    }
}
```

> Implement some code modification

```java
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.Modifier;

import java.lang.reflect.Method;

public class UpdatePerson {

    public static void update() throws Exception {
        ClassPool pool = ClassPool.getDefault();
        CtClass cc = pool.get("com.rickiyang.learn.javassist.PersonService");

        CtMethod personFly = cc.getDeclaredMethod("personFly");
        personFly.insertBefore("System.out.println(\"Prepare parachute before takeoff\");");
        personFly.insertAfter("System.out.println(\"Successfully landed...\");");


        //A new method
        CtMethod ctMethod = new CtMethod(CtClass.voidType, "joinFriend", new CtClass[]{}, cc);
        ctMethod.setModifiers(Modifier.PUBLIC);
        ctMethod.setBody("{System.out.println(\"i want to be your friend\");}");
        cc.addMethod(ctMethod);

        Object person = cc.toClass().newInstance();
        // Call the personFly method
        Method personFlyMethod = person.getClass().getMethod("personFly");
        personFlyMethod.invoke(person);
        //Calling the joinFriend method
        Method execute = person.getClass().getMethod("joinFriend");
        execute.invoke(person);
    }

    public static void main(String[] args) {
        try {
            update();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```