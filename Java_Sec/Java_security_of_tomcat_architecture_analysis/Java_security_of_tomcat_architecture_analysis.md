# Java Security Of Tomcat Architecture Analysis

## Introduction

​ `Apache Tomcat` software is an open source implementation of `Java Servlet`, `JavaServer Pages`, `Java Expression Language` and `Java WebSocket` technologies. The `Java Servlet`, `JavaServer Pages`, `Java Expression Language` and `Java WebSocket` specifications are developed under `Java Community Process`.

​ Simply put, `Tomcat` can be regarded as a `Web` server plus `Servlet` container.

![](img/1.png)

​ In the flowchart above, Tomcat receives and parses the HTTP request through the Connector component, and sends the ServletRequest object to the `Container` for processing. After the `Container` processing is completed, the response will be encapsulated into a `ServletRespone` object and returned to the `Connector`, and then the `Connector` parses the `ServletRespone` object into an HTTP response text format and sends it to the client. At this point, `Tomcat` completes a network communication.

## Architecture

![](img/2.png)

​ The `Tomcat` architecture diagram mainly contains three components: `Service`, `Connectot`, and `Container`.

- `Server`: `Web` server, a `Server` can contain multiple `Service`.
- `Service`: Each `Service` is independent, they share a `JVM` and system class library, and a `Service` is responsible for maintaining multiple `Connector` and a `Container`.
- `Connector`: `Connector` is used to connect `Service` and `Container`, parse client requests and forward to `Container`, and forward responses from `Container`. Each different Connector can handle different request protocols, including `HTTP/1.1`, `HTTP/2`, `AJP`, and so on.
- `Container`: `Tomcat`'s `Container` contains four seed containers, namely `Engine`, `Host`, `Context` and `Wrapper`. Among them, a `Container` corresponds to an `Engine`, an `Engine` can contain multiple `Host`, a `Host` can contain multiple `Context`, and a `Context` contains multiple `Wrapper`.
  - `Engine`: It can be regarded as an entry for containers to provide functions to the outside. Each `Engine` is a collection of `Host`, used to manage each `Host`.
  - `Host`: It can be regarded as a `virtual host`, and a `Tomcat` can support multiple virtual hosts. The function of a virtual host is to run multiple applications, which is responsible for installing and expanding these applications and identifying the application so that they can be distinguished. Each virtual host corresponds to a domain name, and a different `Host` container accepts requests for processing different domain names.
  - `Context`: A context container, which can be regarded as a `Web` application, and multiple `Web` applications can be run in each `Host`. For different Contexts in the same Host, the contextPath must be different. The contextPath of the default Context is a space or a slash.
  - `Wrapper`: Abstraction and wrapping of `Servlet`. Each `Context` can have multiple `Wrapper` to support different `Servlet`. Each `Wrapper` instance represents a specific `Servlet` definition. `Wrapper` is mainly responsible for managing `Servlet`, including `Servlet` loading, initialization, execution, and resource recycling.

​ The following figure shows the resolution process of the request in `Container`:

![](img/3.png)

## Three Major Components

​ There are three major components in the Java Web, namely `Servlet`, `Filter` and `Listener`. The loading order of the three is `Listener`->`Filter`->`Servlet`.

​ In the startInternal method of the `org.apache.catalina.core.StandardContext` class, listenerStart is called first, followed by filterStart, and finally loadOnStartup. These three calls trigger the construction loading of `Listener`, `Filter`, and `Servlet` respectively.

![](img/4.png)

### Listener

####Conception

​ `Listener` is a Java program that implements a specific interface. It is used to listen for a method or attribute. When the listened method is called or attribute is changed, a method will be automatically executed.

​ Concepts related to `Listener`:

- Event: A method is called, or a property is changed;
- Event source: the object being listened to (such as `ServletContext`, `requset`, method, etc.);
- Listener: Used to listen for event sources, and the listener will be triggered when an event occurs.

Listener category:

| Event Source | Listener | Description |
| :------------: | :-----------------------------: | :----------------------------------------------------------: |
| ServletContext | ServletContextListener | Used to listen to the creation and destruction process of ServletContext objects |
| HttpSession | HttpSessionListener | Used to listen to the creation and destruction process of HttpSession objects |
| ServletRequest | ServletRequestListener | Used to listen to the creation and destruction process of ServletRequest objects |
| ServletContext | ServletContextAttributeListener | Add, remove, and replace properties used to listen for ServletContext objects |
| HttpSession | HttpSessionAttributeListener | Used to listen for attribute addition, removal, and replacement of HttpSession objects |
| ServletRequest | ServletRequestAttributeListener | Add, remove, and replace properties used to listen for HttpServletRequest objects |
| HttpSession | HttpSessionBindingListener | Events used to listen for JavaBean objects bound to and unbinding from HttpSession objects |
| HttpSession | HttpSessionActivationListener | Used to monitor the process of object activation and passivation in HttpSession |

​ According to the different objects of listening, they are divided into three categories: `ServletContextListener`, `HttpSessionListener` and `ServletRequestListener`.	

#### Usage

- `ServletContextListener` configuration

```java
package com.memoryshell.tomcatmemoryshell;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;

@WebListener
public class MemoryListener implements ServletContextListener {
    @Override
    public void contextInitialized(ServletContextEvent servletContextEvent) {
        System.out.println("ServletContext object creation...");
    }

    @Override
    public void contextDestroyed(ServletContextEvent servletContextEvent) {
        System.out.println("ServletContext object destroyed...");
    }
}
```

- `web.xml` configuration

```xml
<?xm
l version="1.0" encoding="UTF-8"?>
<web-app xmlns="https://jakarta.ee/xml/ns/jakartaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="https://jakarta.ee/xml/ns/jakartaee https://jakarta.ee/xml/ns/jakartaee/web-app_5_0.xsd"
         version="5.0">
    <listener>
        <listener-class>com.memoryshell.tomcatmemoryshell.MemoryListener</listener-class>
    </listener>
</web-app>
```

![](img/9.png)

### Filter

####Conception

`Filter` is used to intercept user requests and server responses, and can make corresponding modifications to the request and response after interception. `Filter` is not a `Servlet` and cannot be accessed directly. It can intercept resources (`Servlet`, `JSP`, static pages, etc.) in the `Web` application, thereby realizing some corresponding functions.

#### Life Cycle

​ The life cycle of `Filter` is divided into three stages:

- Initialization phase: The initialization phase of `Filter` will only be called once when the `Web` application is started.
- Intercept and filtering phase: When a client requests access to the `URL` associated with the filter, the `Servlet` filter will first execute the `doFilter` method. The `FilterChain` parameter is used to access subsequent filters.
- Destruction phase: The destruction phase of `Filter` will only be called once when the web application is removed or the server is stopped to uninstall the `Filter` object.

![](img/6.png)

#### Usage

- `FilterChain`

​ A Servlet can register multiple `Filters`. The `Web` container will combine the registered multiple `Filters` into a "Filter chain"` and execute the `doFilter` method of each `Filter` in a certain order.

![](img/7.png)

- `Filter execution sequence`

​ Due to the different registration methods of `Filter`, its execution order is also different.

1. Annotation-based configuration: compare according to the string comparison rules of the class name, and execute the small value first;
1. Use `web.xml` configuration: organize according to the corresponding `mapping` order, and whoever defines it above is in front.

- `FilterConfig`

Similar to `Servlet`, since `Filter` can also access `Servlet`, the `Servlet` specification encapsulates the configuration parameter information representing the `ServletContext` object and `Filter` into an object called `FilterConfig`.

​ The `FilterConfig` interface is used to define the methods that the `FilterConfig` object should be provided externally, so that these methods can be called in the `doFilter` method of `Filter` to obtain the `ServletContext` object and to obtain some initialization parameters in the `web.xml` file.

![](img/8.png)

### Servlet

####Conception

`Servlet` is a program running on a `Web` server or application server, which is an intermediate layer between a request from an `HTTP` client and a database or application on an `HTTP` server. Dynamic resources used to process client requests, and generate corresponding return information based on the request and provide them to the user. When `Tomcat` receives a request from the client, it will be parsed into a `RequestServlet` object and sent to the corresponding `Servlet` for processing.

#### Life Cycle

​ The life cycle of `Servlet` is divided into five stages:

- Loading phase: When `Tomcat` first access to `Servlet`, an instance of `Servlet` is created.
- Initialization phase: When `Servlet` is instantiated, `Tomcat` will call the `init` method to initialize this object.
- Processing service phase: When the browser accesses `Servlet`, `Servlet` will call the `service` method to handle the request.
- Destruction phase: When `Tomcat` is closed or when `Servlet` is detected to be deleted from `Tomcat`, the `destroy` method will be automatically called to allow the instance to release the resources occupied. In addition, if a Servlet is not used for a long time, it will also be automatically destroyed by `Tomcat`.
- Uninstallation stage: When the `Servlet` calls the `destroy` method, it will wait for garbage collection. If you need to use this Servlet again, the `init` method will be called again for initialization.

![](img/5.png)

#### Usage

According to the above understanding of the `Servlet` life cycle, when you need to implement a `Servlet`, you need to inherit the `Servlet` interface and implement the corresponding five methods.

​ Two classes have been encapsulated in `Tomcat`, namely the `GenericServlet` class and the `HttpServlet` class. The `GenericServlet` abstract class implements the `Servlet` interface and simply implements four other methods except the `service` method in the `Servlet` interface.

​ Create a Servlet by inheriting the `GenericServlet` class, just override the `service` method. However, the GenericServlet abstract class is a general Servlet class and is not designed for a certain application scenario. Therefore, when processing `HTTP` requests, you need to manually implement the parsing and encapsulation of `HTTP` requests.

​ `HttpServlet` is a subclass of `GenericServlet`, which specifically deals with the `HTTP` protocol based on `GenericServlet`. It sets a processing method for each `HTTP` request. When using the `HttpServlet` class, you only need to rewrite the corresponding processing method according to the `HTTP` request type.

```java
@WebServlet(name = "MemoryServlet", value = "/MemoryServlet")
public class MemoryServlet extends HttpServlet {
    private String message;

    @Override
    public void init() {
        message = "This is MemoryShell page!";
    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");

        // Hello
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<h1>" + message + "</h1>");
        out.println("</body></html>");
    }
}
```

## Reference

- [Java Security Learning—A Brief Analysis of Tomcat Architecture](https://goodapple.top/archives/1359)