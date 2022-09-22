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

# Distributed Component Object Model (DCOM)

Processes started via DCOM may also be seen where the parent is `svchost.exe` which is started with the command line `-k DcomLaunch`.

```

```

# Make Token

The `make_token` module of C2 create a token in order to impersonate a user with their credentials.

The user of `make_token` generates the even `4624: An account was successfully logged on`. This event is very common in Windows domain, but can be narrowed down by filtering on the `Logon Type`.

`make_token` uses `LOGON32_LOGON_NEW_CREDENTIALS` which is type `9`.

```
event.code: 4624 and winlog.event_data.LogonType: 9
```

# Spawn

Like `make_token` this will generate the follwing alert `4624: An account was successfully logged on`. but with the logon type 2 `LOGON32_LOGON_INTERACTIVE`.

```
event.type: process_start and process.name: rundll32.exe
```


# Pass The Hash

Sysmon will record the pass the hash technique with the event of a process creation for `cmd.exe` including the command line arguments `echo 1cbe909fe8a > \\.\pipe\16ca6d`.

This unsual pattern can be searched with:

```
event.module: sysmon and event.type: process_start and process.name: cmd.exe and process.command_line: *\\\\.\\pipe\\*
```

It will also generate a `4624` event with the logon type `9`.

```
event.code: 4624 and winlog.logon.id: 0xe6d64
```

# Over Pass The Hash

When a TGT is requested and `4768: A Kerberos authentication ticket (TGT) was requested` event is created.

By default windows uses `AES256 (0X12)` as KeyType but if no AESKeys is used during the attack a `4768` with `RC4-HMAC (0x17)` as KeyType is generated.

```
event.code: 4768 and winlog.event_data.TicketEncryptionType: 0x17
```