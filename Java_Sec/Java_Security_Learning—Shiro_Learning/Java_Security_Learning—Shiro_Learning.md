#Java Security Learning—Shiro Learning

Author: H3rmesk1t

Data: 2022.03.25

# Preface
This article mainly briefly learns and analyzes the 11 vulnerabilities with `CVE` numbers that have been exposed in history by the permission verification framework `Shiro`. According to the principles of each `CVE` vulnerability and the code updated version to analyze the principles, utilization methods, characteristics, etc. of security vulnerabilities.

<div align=center><img src="./images/1.png"></div>


# Shiro Introduction
[Apache Shiro](https://shiro.apache.org/) is a powerful and easy-to-use Java security framework that performs authentication, authorization, cryptography, and session management. With Shiro's easy-to-understand API, you can quickly and easily secure any application – from the smallest mobile applications to the largest web and enterprise applications.


# Shiro Features
Apache Shiro aims to be the most comprehensive, but also the easiest to use Java security framework available. Here are some of the frameworks finer points.
 - The easiest to understand Java Security API anywhere. Class and Interface names are intuitive and make sense. Anything is pluggable but good defaults exist for everything.
 - Support `authentication` ('logins') across one or more pluggable data sources (LDAP, JDBC, ActiveDirectory, etc).
 - Perform `authorization` ('access control') based on roles or fine-grained `permissions`, also using pluggable data sources.
 - First-class `caching` support for enhanced application performance.
 - Built-in POJO-based Enterprise `Session Management`. Use in both web and non-web environments or in any environment where Single Sign On (SSO) or clustered or distributed sessions are desired.
 - Heterogeneous client session access. You are no longer forced to use only the <tt>httpSession</tt> or Stateful Session Beans, which often unecessarily tie applications to specific environments. Flash applets, C# applications, Java Web Start, and Web Applications, etc. can now all share session state regardless of deployment environment.
 - Simple Single Sign-On (SSO) support piggybacking the above Enterprise Session Management. If sessions are federated across multiple applications, the user's authentication state can be shared too. Log in once to any application and the others all recognize that log-in.
 - Secure data with the easiest possible `Cryptography` APIs available, giving you power and simplicity beyond what Java provides by default for ciphers and hashes.
 - An incredibly robust yet low-configuration web framework that can secure any url or resource, automatically handle logins and logouts, perform Remember Me services, and more.
 - Extremely low number of required dependencies. Standalone configuration requires only <tt>slf4j-api.jar</tt> and one of slf4j's binding .jars. Web configuration additionally requires <tt>commons-beanutils-core.jar</tt>. Feature-based dependencies (Ehcache caching, Quartz-based Session validation, Spring dependency injection, etc.) can be added when needed.

## Authentication
[Authentication](https://shiro.apache.org/authentication-features.html) is the process of identity verification – you are trying to verify a user is who they say they are. To do so, a user needs to provide some sort of proof of identity that your system understands and trusts.
 - `Subject Based`: Almost everything you do in Shiro is based on the currently executing user, called a Subject. And you can easily retrieve the Subject anywhere in your code. This makes it easier for you to understand and work with Shiro in your applications.
 - `Single Method call`: The authentication process is a single method call. Needing only one method call keeps the API simple and your application code clean, saving you time and effort.
 - `Rich Exception Hierarchy`: Shiro offers a rich exception hierarchy to offered detailed explanations for why a login failed. The hierarchy can help you more easily diagnose code bugs or customer services issues related to authentication. In addition, the richness can help you create more complex authentication functionality if needed.
 - `'Remember Me' built in`: Standard in the Shiro API is the ability to remember your users if they return to your application. You can offer a better us
er experience to them with minimal development effort.
 - `Pluggable data sources`: Shiro uses pluggable data access objects (DAOs), called Realms, to connect to security data sources like LDAP and Active Directory. To help you avoid building and maintaining integrations yourself, Shiro provides out-of-the-box realms for popular data sources like LDAP, Active Directory, and JDBC. If needed, you can also create your own realms to support specific functionality not included in the basic realms.
 - `Login with one or more realms`: Using Shiro, you can easily authenticate a user against one or more realms and return one unified view of their identity. In addition, you can customize the authentication process with Shiro's notion of an authentication strategy. The strategies can be setup in configuration files so changes don't require source code modifications – reducing complexity and maintenance effort.

## Authorization
[Authorization](https://shiro.apache.org/authorization-features.html), also called access control, is the process of determining access rights to resources in an application.
 - `Subject-based`: Almost everything you do in Shiro is based on the currently executing user, called a Subject. And you can easily access the subject retrieve the Subject and checks its roles, permissions, or other relevant attributes anywhere in your code. This makes it easier for you to understand and work with Shiro in your applications.
 - `Checks based on roles or permissions`: Since the complexity of authorization differences greatly between applications, Shiro is designed to be flexible, supporting both role-based security and permission-based security based on your projects needs.
 - `Powerful and intuitive permission syntax`: As an option, Shiro provides an out-of-the-box permission syntax, called Wildcard Permissions, that help you model the fine grained access policies your application may have. By using Shiro's Wildcard Permissions you get an easy-to-process and human readable syntax. Moreoever, you don't have to go through the time-consuming effort and complexity of creating your own method for representing your access policies.
 - `Multiple enforcement options`: Authorization checks in Shiro can be done through in-code checks, JDK 1.5 annotations, AOP, and JSP/GSP Taglibs. Shiro's goal is to give you the choice to use the option you think are best based on your preferences and project needs.
 - `Strong caching support`: Any of the modern open-source and/or enterprise caching products can be plugged in to Shiro to provide a fast and efficient user-experience. For authorization, caching is cruel for performance in larger environments or with more complex policies using back-end security data sources.
 - `Pluggable data sources`: Shiro uses pluggable data access objects, referred to as Realms, to connect to security data sources where you keep your access control information, like an LDAP server or a relational database. To help you avoid building and maintaining integrations yourself, Shiro provides out-of-the-box realms for popular data sources like LDAP, Active Directory, and JDBC. If needed, you can also create your own realms to support specific functionality not included in the basic realms.
 - `Supports any data model`: Shiro can support any data model for access control — it doesn't force a model on you. Your realm implementation ultimately decides how your permissions and roles are grouped together and whether to return a "yes" or a "no" answer to Shiro. This feature allows you to architect your application in the manner you choose and Shiro will bend to support you.

## Permissions
Shiro defines a [Permission](https://shiro.apache.org/permissions.html) as a statement that defines an explicit behavior or action. It is a statement of raw functionality in an application and nothing more. Permissions are the lowest-level constructs in security polices, and they explicitly define only "what" the application can do.

Some example
les of permissions:
 - Open a file.
 - View the '/user/list' web page.
 - Print documents.
 - Delete the 'jsmith' user.

The above examples of permissions, "Open a file", "View the 'user/list' web page", etc are all valid permission statements. However, it would be very difficult to interpret those natural language strings and determine if a user is allowed to perform that behavior or not. So to enable easy-to-process yet still readable permission statements, Shiro provides powerful and independent permission syntax we refer to as the WildcardPermission.

## Caching
[Caching](https://shiro.apache.org/caching.html) is a first class feature built into Shiro from day one to ensure that security operations remain as fast as possible. However, while Caching as a concept is a fundamental part of Shiro, implementing a full Cache mechanism would be outside the core competency of a security framework. To that end, Shiro's cache support is basically an abstraction (wrapper) API that will 'sit' on top of an underlying production Cache mechanism (e.g. Hazelcast, Ehcache, OSCache, Terracotta, Coherence, GigaSpaces, JBossCache, etc). This allows a Shiro end-user to configure any cache mechanism they prefer.

Shiro has three important cache interfaces:
 - `CacheManager`: The primary Manager component for all caching, it returns Cache instances.
 - `Cache`: Maintains key/value pairs.
 - `CacheManagerAware`: Implemented by components wishing to receive and use a CacheManager instance.

A CacheManager returns Cache instances and various Shiro components use those Cache instances to cache data as necessary. Any Shiro component that implements CacheManagerAware will automatically receive a configured CacheManager, where it can be used to acquire Cache instances.

## Session Management
[Sessions](https://shiro.apache.org/session-management-features.html) are buckets of data that your users carry with them for a period of time when using your application. Sessions have traditionally been exclusive to web or EJB environments. No more! Shiro enables sessions for any application environment. Further, Shiro offers to a host of other great features to help you manage sessions.
 - `POJO/J2SE based (IoC friendly)`: Everything in Shiro (including all aspects of Sessions and Session Management) is interface-based and implemented with POJOs. This allows you to easily configure all session components with any JavaBeans-compatible configuration format, like JSON, YAML, Spring XML or similar mechanisms. You can also easily extend Shiro's components or write your own as necessary to fully customize session management functionality.
 - `Session Storage`: Because Shiro's Session objects are POJO-based, session data can be easily stored in any number of data sources. This allows you to customize exactly where your application's session data resides, for example, the file system, an enterprise cache, a relational database, or proprietary data store.
 - `Easy and Powerful Clustering`: Shiro's sessions can be easily clustered using any of the readily-available networked caching products, like Ehcache, Coherence, GigaSpaces, et. al. This means you can configure session clustering for Shiro once and only once, and no matter what web container you deploy to, your sessions will be clustered the same way. No need for container-specific configuration!
 - `Heterogeneous Client Access`: Unlike EJB or Web sessions, Shiro sessions can be 'shared' across various client technologies. For example, a desktop application could 'see' and 'share' the same physical session used by the same user in a server-side web application. We are unaware of any framework other than Shiro that can support this.
 - `Event listeners`: Event listeners allow you to listen to lifecycle events during a session's lifetime. You can listen for these events and react to them for custom application behavior - for example, updating a user record when their session expires.
 - `Host address retenti
on`: Shiro Sessions retain the IP address of the host from where the session was initiated. This allows you to determine where the user is located and react accordingly (mostly useful in intranet environments where IP association is determined).
 - `Inactivity/expiration support`: Sessions expire due to inactivity as expected, but they can be prolonged via a touch() method to keep them 'alive' if desired. This is useful in Rich Internet Application (RIA) environments where the user might be using a desktop application, but may not be regularly communicating with the server, but the server session should not expire.
 - `Transparent web use`: Shiro's web support implements the HttpSession interface and all of it's associated APIs. This means you can use Shiro sessions in existing web applications and you don't need to change any of your existing web code.
 - `Can be used for SSO`: Because Shiro's sessions are POJO based, they are easily stored in any data source, and they can be 'shared' across applications if needed. This can be used to provide a simple sign-on experience since the shared session can retain authentication state.

## Cryptography
[Cryptography](https://shiro.apache.org/cryptography-features.html) is the practice of protecting information from undesired access by hiding it or converting it into nonsense so no one else can read it. Shiro focuses on two core elements of Cryptography: ciphers that encrypt data like email using a public or private key, and hashes (aka message digests) that irreversibly encrypt data like passwords.
 - `Interface-driven, POJO based`: All of Shiro’s APIs are interface-based and implemented as POJOs. This allows you to easily configure Shiro Cryptography components with JavaBeans-compatible formats like JSON, YAML, Spring XML and others. You can also override or customize Shiro as you see necessary, leveraging its API to save you time and effort.
 - `Simplified wrapper over JCE`: The Java Cryptography Extension (JCE) can be complicated and difficult to use unless you’re a cryptography expert. Shiro’s Cryptography APIs are much easier to understand and use, and they dramatically simplify JCE concepts. So now even Cryptography novels can find what they need in minutes rather than hours or days. And you won’t sacrifice any functionality because you still have access to more complicated JCE options if you need them.
 - `"Object Orientifies" cryptography concepts`: The JDK/JCE’s Cipher and Message Digest (Hash) classes are abstract classes and quite confusing, requiring you to use obtuse factory methods with type-unsafe string arguments to acquire instances you want to use. Shiro 'Object Orientifies' Ciphers and Hashes, basing them on a clean object hierarchy, and allow you to use them by simple instantiation.
 - `Runtime Exceptions`: Like everywhere else in Shiro, all cryptography exceptions are RuntimeExceptions. You can decide whether to catch an exception based on your needs.


# Shiro Key Components
The verification process for one-time authentication and authorization is basically as follows:
 - The application obtains the currently accessed `Subject` and calls its corresponding verification method;
 - `Subject` delegates the verification to `SecurityManager` for judgment;
 - `SecurityManager` will call `Realm` to obtain information to determine whether the corresponding role of the user can operate.

## SecurityManager
`org.apache.shiro.mgt.SecurityManager` is a core interface of `shiro`, which is responsible for all security operations of a `Subject`:
 - The interface itself defines three methods: `createSubject`, `login`, and `logout` to create `Subject`, login, and logout.
 - The interface extends the `org.apache.shiro.authc.Authenticator` interface, and provides the `authenticate` method for authentication.
 - The interface extends the `org.apache.shiro.authz.Authorizer` interface, providing verification methods for `Permission` and `Role`, including `has`/`is`/`check` related naming methods.
 - The interface extends the `org.apache.shiro.session.mgt.SessionManager` interface, and provides the `start` and `getSession` methods to create a fetchable session.

And `Shiro` provides a default implementation class `org.apache.shiro.mgt.DefaultSecurityManager` for `SecurityManager` that contains all the above functions.

<div align=center><img src="./images/2.png"></div>

The following properties are included in the `DefaultSecurityManager`:
 - `subjectFactory`: DefaultSubjectFactory` is used by default, which is used to create a specific `Subject` implementation class.
 - `subjectDAO`: DefaultSubjectDAO` is used by default, which is used to save the most recent information in `Subject` into `Session`.
 - `rememberMeManager`: Used to provide `RememberMe` related functions.
 - `sessionManager`: Use `DefaultSessionManager` by default`
, `Session` related operations will be entrusted to this class.
 - `authorizer`: The default is `ModularRealmAuthorizer`, which is used to configure authorization policies.
 - `authenticator`: The default is `ModularRealmAuthenticator`, which is used to configure authentication policies.
 - `realm`: The configuration of authentication and authorization is configured by the user, including `CasRealm`, `JdbcRealm`, etc.
 - `cacheManager`: Cache Management, configured by the user, is first passed during authentication and authorization, and is used to improve the authentication and authorization speed.

`DefaultSecurityManager` also has a subclass `org.apache.shiro.web.mgt.DefaultWebSecurityManager`. This class is in the `shiro-web` package and is an implementation class provided by `Shiro` for HTTP`/`SOAP` and other `http` protocol connections. This class is created by default and configured `org.apache.shiro.web.mgt.CookieRememberMeManager` to provide `RememberMe` related functions.

<div align=center><img src="./images/3.png"></div>

## Subject
`org.apache.shiro.subject.Subject` is an interface used to represent a user in `Shiro`. Because the concept of `User` is used in too many components, `Shiro` deliberately avoided this keyword and used `Subject`.

The `Subject` interface also provides the ability to authenticate, authorize and get sessions. If you want to get a current `Subject` in an application, you usually use the `SecurityUtils#getSubject` method.

In fact, the implementation class `org.apache.shiro.subject.support.DelegatingSubject` in the core package is essentially a proxy class of `SecurityManager`. DelegatingSubject` stores a `transient` modified `SecurityManager` member variable. When using the specific verification method, `SecurityManager` is actually delegated to process it.

<div align=center><img src="./images/4.png"></div>

<div align=center><img src="./images/5.png"></div>

## Realm
`Realm` is mainly used to identify permissions and roles. `org.apache.shiro.realm.Realm` is an interface in `Shiro`. `Shiro` accesses the security entities of the specified application - users, roles, permissions, etc. through `Realm`. A `Realm` usually has a `1` to `1` correspondence with a data source, such as relational databases, file systems, or other similar resources. Therefore, the implementation class of this interface will use a data source-specific `API` for authentication or authorization, such as `JDBC`, file `IO`, `Hibernate/JPA`, etc., which is officially interpreted as: a security-specific `DAO` layer.

In use, developers usually do not directly implement the `Realm` interface, but implement the abstract class `AuthenticatingRealm`/`AuthorizingRealm` that provides some related functions, or use implementation classes provided for specific data sources such as `JndiLdapRealm`/`JdbcRealm`/`PropertiesRealm`/`TextConfigurationRealm`/`IniRealm`, etc.

<div align=center><img src="./images/6.png"></div>

# Shiro vulnerability environment construction
You can use a simple `Demo` I built myself: [ShiroVulnerabilityDemo](https://github.com/H3rmesk1t/JavaSec-Learn/tree/main/ShiroVulnerabilityDemo). Or build it according to the [Usage Method] in the `su18` master's article (https://su18.org/post/shiro-1/#:~:text=%E8%83%BD%E5%90%A6%E8%BF%9B%E8%A1%8C%E6%93%8D%E4%BD%9C%E3%80%82-,%E4%BD%BF%E7%94%A8,-%E6%9C%AC%E7%AB%A0%E6%9D%A5%E7%9C%8B%E4%B8%80%E4%B8%8B).

# Shiro vulnerability analysis recursive
## CVE-2010-3863
### Vulnerability Information
[CVE-2010-3863](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-3863): Apache Shiro before 1.1.0, and JSecurity 0.9.x, does not canonicalize URI paths before comparing them to entries in the shiro.ini file, which allows remote attackers to bypass intended access restrictions via a crafted request, as demonstrated by the `/./account/index.jsp` URI.

### Vulnerability Analysis
`Shiro` first calls the `PathMatchingFilterChainResolver#getChain` method to obtain and call the `Filter` to be executed.

<div align=center><img src="./images/7.png"></div>

Then the `getPathWithinApplication` method calls the `WebUtils.getPathWithinApplication` method to get the request path. This method obtains the `Context` path and the `URI` path respectively, and then uses string intercept to remove the `Context` path.

The `getRequestUri` method first obtains the value of `javax.servlet.include.request_uri`, and then calls the `decodeAndCleanUriString` method for processing.

The `decodeAndCleanUriString` method is to intercept the `; `;` URL Decode` and the adaptation of strings such as `JBoss`/`Jetty` to add `; jsessionid` at `url`.

<div align=center><img src="./images/8.png"></div>

After processing the request URL will be used to match attempts using `AntPathMatcher#doMatch`.

<div align=center><img src="./images/9.png"></div>

<div align=center><img src="./images/10.png"></div>

### Vulnerability recurs

In the follow-up above, we can see that the standardized path processing is not performed before the match, which leads to the possibility of bypassing the security verification if some special characters appear in the `URI`. For example, the following configuration:

```xml
[urls]
/user/** = authc
/admin/list = authc, roles[admin]
/admin/** = authc
/audit/** = authc, perms["audit:list"]
/** = anon
```

In the above configuration, some interfaces with specified permissions are configured for the requirements, and the permissions of anno are set for all other `URLs /**`. In this configuration, the risk of verification bypass is generated. Normal access to `/audit` will be intercepted by `Shiro`'s Filter` and jumped to the login URL. However, accessing `/./audit` is not matched with the configuration file, and it enters the matching range of `/**`, resulting in overpriced access.

<div align=center><img src="./images/11.png"></div>

<div align=center><img src="./images/12.png"></div>

### Vulnerability Fix
The `Shiro` update has added a standardized path function, and has processed `/`, `//`, `/./`, `/../`, etc.

<div align=center><img src="./images/13.png"></div>

<div align=center><img src="./images/14.png"></div>

## CVE-2014-0074
### Vulnerability Information
[CVE-2014-0074](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0074): Apache Shiro 1.x before 1.2.3, when using an LDAP server with unauthenticated bind enabled, allows remote attackers to bypass authentication via an empty (1) username or (
2) password.

### Vulnerability Analysis
According to the configuration of the `BUG` committer, set `Realm` to `ActiveDirectoryRealm` and specify its `ldapContextFactory` to `JndiLdapContextFactory`. The `BUG` committer proposed two scenarios in total, one is to bypass the empty account with an empty password, and the other is to bypass the empty account with an arbitrary password.

```ini
[main]
# Login address
authc.loginUrl = /login

# ldap
ldapContextFactory = org.apache.shiro.realm.ldap.JndiLdapContextFactory
ldapContextFactory.url = ldap://127.0.0.1:389/

# realm
adRealm = org.apache.shiro.realm.activedirectory.ActiveDirectoryRealm
adRealm.ldapContextFactory = $ldapContextFactory
adRealm.searchBase = "cn=config,dc=h3rmesk1t,dc=org"


[urls]
/index = anon
/login = anon
/logout = logout
/** = authc
```

### Vulnerability recurs
#### Scene 1
When the ldap server allows anonymous access (Anonymous), you can log in with an empty user and an empty password. First, access the `/login` interface to log in, access link: `http://localhost:8080/login?username=cn=test,dc=h3rmesk1t,dc=org&password=test`, after successfully logging in, the page jumps to `/user`, displays the page you will see after authentication, and prints out the `principal` of the current user. Then visit the `/logout` interface to log out, and the page jumps back to the `/login` login page. Try login again, use an empty username and empty password, access link: `http://localhost:8080/login?username=&password=`, After successful authentication, the page jumps to `/user`, and you can access the page that needs authentication to be displayed. The result of `SecurityUtils.getSubject().getPrincipal()` is `"`. Other pages that require authentication can also be accessed directly, such as `/admin`.

<div align=center><img src="./images/15.png"></div>

<div align=center><img src="./images/16.png"></div>

#### Scene 2
First, modify the configuration file of `openldap` to enable unauthorized `bind`. Next, use a combination of empty username + any password to try login. Visit the link: `http://localhost:8080/login?username=&password=123`. I found that I would also log in successfully. The page jumps to `/user`, and the same `principal` is an empty string.

### Vulnerability Fix
[Detailed vulnerability fix information](https://github.com/apache/shiro/commit/f988846207f98c98ff24213ee9063798ea5d9b6c). The official added the validateAuthenticationInfo methods to verify that the principal and `credential` are empty. Only if the principal` is not empty will the verification of `credential` be performed before the `getLdapContext` method creates `InitialLdapContext`. If null, an exception will be thrown.


## CVE-2016-4437
### Vulnerability Information
[CVE-2016-4437](): Apache Shiro before 1.2.5, when a cipher key has not been configured for the "remember me" feature, allows remote attackers to execute arbitrary code or bypass intended access restrictions via an unspecified request parameter.

### Vulnerability Analysis
The vulnerability problem is mainly in `RememberMe`.
#### RememberMeManager






# refer to
 - [Learn Shiro Safety from CVE](https://su18.org/post/shiro-5/)