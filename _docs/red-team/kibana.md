---
title: Kibana - The Security App
category: Red Team
order: 8
---

# PowerShell

Search for Powershell Remoting (egress network)

```
event.module : sysmon and event.type : connection and network.direction : egress and destination.port : 5985
```

There is the process start event for `wsmprovhost.exe` with an `-Embedding` parameter in the command arguments.

```
event.module : sysmon and event.type : process_start and process.command_line : "C:\\Windows\\system32\\wsmprovhost.exe -Embedding"
```

PowerShell logging will also provide the script block, which tell us exactly which code or commands were executed.

> **Note**: Use the `process.pid` from the previous query to find its associated script block.

```
event.module : powershell and winlog.process.pid: 2984
```


# PsExec

We can build a detection, because we can correlate events such as:

* File creation.
* Service installed.
* Process start.

Cobalt strike by default have some behaviours that we can modify:

* It uses the same name for the service and the exe.
* The name is a random alphanumeric string of lentgh 7.
* The service binary is always dropped into `C:\Windows`.


`psexec` and `psexec64` are the only `jump` methods that will perform a process migration automatically with `rundll32`, so it can automatically delete the service binary from disk.

It's parent process will be the service binary and would result ini a further process create event. `psexec_psh` will execute PowerShell via `%COMSPEC%` which if the default command line interpreter, usually `cmd.exe`.


```
event.module : sysmon and event.type : creation and event.category : file and file.extension : exe and file.directory : "C:\\Windows"
```

```
event.provider : "Service Control Manager" and message : "A service was installed"
```

# Windows Management Instrumentation (WMI)

When binaries are executed via WMI, it will be a child of `WmiPrvSE.exe`. 

We can look for process create event where `WmiPrvSE` is the parent.

```
event.module: sysmon and event.type : process_start and process.parent.name : WmiPrvSE.exe
```