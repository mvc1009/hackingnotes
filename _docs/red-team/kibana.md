---
title: Kibana - The Security App
category: Red Team
order: 8
---

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