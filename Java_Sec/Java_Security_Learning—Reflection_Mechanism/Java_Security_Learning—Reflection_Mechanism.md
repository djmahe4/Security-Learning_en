# Java Security Learning—Reflection Mechanism

Author: H3rmesk1t

#Definition
> The Java reflection mechanism can ignore class methods and variables to access permission modifiers (such as protected, private, etc.), and can call any method of any class, access and modify member variable values

# Definition of reflection
> Reflection is one of the characteristics of Java. The existence of reflection enables running Java to obtain its own information and can manipulate internal properties of classes or objects.
> Through reflection, you can obtain member and member information of each type of program or assembly at runtime; the same is true for Java's reflection mechanism. In the running state, through Java's reflection mechanism, you can judge any methods and properties of an object.

# Basic application of reflection
## Get class object
### forName() method
> When you want to use methods in Class class to get class objects, you need to use the forName() method, just have the class name. This method is usually used in configuration JDBC

<img src="./images/1.png" alt="">

### .class method
> Any data type has static properties, so you can use `.class` to directly get its corresponding Class object. When using this method, you need to use static members in the class explicitly.

<img src="./images/2.png" alt="">

### getClass() method
> You can get bytecode through the `getCLass()` method in the Object class. When using this method, you must clarify the specific class and then create the object.

<img src="./images/3.png" alt="">

### getSystemClassLoad().loadClass() method
> The `getSystemClassLoad().loadClass()` method is similar to the `forName()` method, as long as it has a class name; however, the static method JVM of `forName()` loads the class and executes the code in `static()`, while `getSystemClassLoad().loadClass()` does not execute the code in `ststic()`
> For example, in JDBC, the `forName()` method is used to make the JVM search and load the established class into memory. At this time, passing `com.mysql.jdbc.Driver` as a parameter is to let the JVM search for the `com.mysql.jdbc` path and load it into memory.

<img src="./images/4.png" alt="">

## Get class method
> There are mainly the following methods to obtain a Class object

### getDeclaredMethods method
> This method returns all methods declared by the class or interface, including public, private, and default methods, but does not include inherited methods.

<img src="./images/5.png" alt="">

### getMethods method
> The getMethods method returns all public methods of a class, including the public methods of its inherited class

<img src="./images/6.png" alt="">

### getMethod method
> The getMethod method can only return a specific method, such as returning the exec() method in the Runtime class. The first parameter of the method is the method name, and the subsequent parameter is the method's parameter corresponding to the Class object.

<img src="./images/11.png" alt="">

### getDeclaredMethod method
> This method is similar to the getMethod method, and can only return a specific method. The first parameter of the method is the method name and the second parameter name is the method parameter

<img src="./images/10.png" alt="">

## Get class member variables
> Create a Student class first
```java
public class Student {
    private String id;
    private String name;
    private String age;
    public String content;
    protected String address;

    public String getId() {
        return id;
    }
    public void setId(String id) {
        this.id = id;
    }
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public String getAge() {
        return age;
    }
    public void setAge(String age) {
        this.age = age;
    }
    public String getContent() {
        return content;
    }
    public void setContent(String content) {
        this.content = content;
    }
    public String getAddress() {
        return address;
    }
    public void setAddress(String address) {
        this.address = address;
    }
}
```

### getDeclaredFields method
> The getDeclaredFields method can obtain the class's member variable array including public, private, and protected, but does not include the declaration fields of the parent class.

<img src="./images/7.png" alt="">

### getFields method
> The getFields method can get all public fields of a class, including fields in the parent class

<img src="./images/8.png" alt="">

### getDeclaredField method
> The difference between this method and the getDeclaredFields method is that only single member variables of the class can be obtained

<img src="./images/9.png" alt="">