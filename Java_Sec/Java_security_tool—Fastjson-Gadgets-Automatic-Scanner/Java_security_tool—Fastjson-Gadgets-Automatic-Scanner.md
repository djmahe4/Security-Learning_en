# Fastjson-Gadgets-Automatic-Scanner Simple Analysis

Author: H3rmesk1t

Data: 2022.03.08

# Preface
In the `WP` after the `SUSCTF 2022` competition, I saw that a master directly used the `jar` file in the `lib` package provided by the question backend to automatically mine the `Fastjson`Gadget`Gadget`, so I wanted to try out whether I could realize the `Fastjson-Gadget` injected by `JNDI`. Therefore, with this simple gadget, it may not be as accurate as other masters write, but it can basically be determined to a smaller range for manual detection.

# Project address
[Fastjson-Gadgets-Automatic-Scanner](https://github.com/H3rmesk1t/Fastjson-Gadgets-Automatic-Scanner)

# Project Module
The function structure defined by the project is as follows:

<div align=center><img src="./images/1.png"></div>

At the same time, here we briefly talk about the implementation ideas for the main functions in the project. For the analysis of the deserialization vulnerability of `Fastjson`, you can see what I wrote before [Java Security Learning—fastjson Deserialization vulnerability](https://github.com/H3rmesk1t/Learning_summary/blob/main/WebSec/Java%E5%AE%89%E5%85%A8%E5%AD%A6%E4%B9%A0%E2%80%94fastjs on%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/Java%E5%AE%89%E5%85%A8%E5%AD%A6%E4%B9%A0%E2%80%94fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E.md).

## command && jar_process
These two functions mainly use the `jar` package that needs to be detected for a preprocessing operation, for example: create the project folder of the `jar` package. The parameter `operating_system` that needs to be entered here is mainly to consider the problem of processing the input file path on different operating systems.

<div align=center><img src="./images/2.png"></div>

<div align=center><img src="./images/3.png"></div>

## jar_decompile
This function mainly decompiles the `jar` package that needs to be detected and generates the corresponding `java` source code file. Here we use the `java-decompiler.jar` in the `IntelliJ IDEA` plug-in to decompile the `jar` package, and then use the `unzip` command to decompile the `jar` package into the project folder that was created before, and obtain the `java` source code file.

<div align=center><img src="./images/4.png"></div>

<div align=center><img src="./images/5.png"></div>

## scanner_dir && javafile_generate
These two functions mainly traverse the previously decompressed project directory to obtain the `java` source code file and return the `java` source code file path.

<div align=center><img src="./images/6.png"></div>

<div align=center><img src="./images/7.png"></div>

## scanner_file
This function mainly conducts a preliminary detection of the `java` source code file. When there is no `InitialContext()` related content in the file, directly pass` (the purpose is to mine the related utilization of `JNDI` injection, so when there is no key class `InitialContext` in `JNDI` injection in the file, no syntax tree judgment is performed). Use the `javalang` library to parse the source code and obtain an abstract syntax tree. Then traverse the class declaration and method declaration and judge at the class level on the syntax tree. The scanned Gadget results can be blacklisted (the blacklist detection operation can be removed when used, and the project detects the currently known blacklist classes). Finally, the scan results that meet the conditions are printed and saved.

<div align=center><img src="./images/8.png"></div>

## class_declaration_generate
Because the `Fastjson`'s checkAutoType` method has restrictions on deserialized classes in the source code, such as: it cannot inherit the `Classloader`, cannot implement the `DataSource` and `RowSet` interfaces, and must have a constructor without parameters, etc.

<div align=center><img src="./images/9.png"></div>

The function `class_declaration_generate` is used to filter for the checkAutoType` restriction feature, and determines whether the corresponding properties of the `ClassDeclaration` object meet the conditions. First, non-class declarations are not analyzed, and whether they are inherited from `Classloader`; then determines whether they are disabled interfaces such as `DataSource` and `RowSet`; finally determines whether there is a constructor without parameters. Through the above processing, a rough list of class declarations is obtained, which is returned to `scanner_file` for further processing.

<div align=center><img src="./images/10.png"></div>

## lookup_detect
The function `class_declaration_generate` returns the obtained class declaration list to the function `scanner_file`. After the function `scanner_file` gets the class declaration list, it will traverse the class declaration to get the class declaration, and then traverse the method declaration for this class declaration. For each method declaration, use the function `lookup_detect` for the final confirmation. This is because after obtaining the class declaration, it is also necessary to determine whether the `lookup` method is called, and the parameters that require the `lookup` method are variables.

For the judgment of whether to call the `lookup` method, you only need to traverse the entire child nodes of the MethodDeclaration object in depth first, and judge whether the node type is `MethodInvaction` and whether the called function name is `lookup`. Whether the variables of `lookup` are controllable can be simplified to believe that the attributes of the class and the method entry parameters are controllable variables, thereby avoiding analysis of the data flow.

<div align=center><img src="./images/12.png"></div>

# Project usage

```sh
usage: python main.py [-h] jar operating_system

positional arguments:
  jar Enter the jar to be scanned
  operating_system Enter the operating system Windows or Linux or MacOS

optional arguments:
  -h, --help show this help message and exit
```

You can see that the `Gadget` used in the `SUSCTF` competition questions have achieved initial results in the scanning results.

<div align=center><img src="./images/13.png"></div>

<div align=center><img src="./images/14.png"></div>

# Summarize
There are many shortcomings in this project, such as whether the mining of other `jar` packages is completely effective, etc. After further study, I hope that the project can be improved. I also hope that the masters will give you advice and provide better ideas and ideas. It would be even better if the masters can click on `Star` (manually act coquettish).