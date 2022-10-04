---
title: Kibana - The Security App
category: Red Team
order: 8
---

# PowerShell Remoting

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

# Kerberoasting

Every time a TGS is requested a windows event `4769 - A Kerberos service ticket was requested` is generated.

Be careful while doing kerberoasting, it could be some HONEYPOTS.

```
event.code: 4769 and winlog.event_data.ServiceName : svc_honey
```

# AS-REP Roasting

AS-REP Roasting with Rubeus will generate a 4768 with an encryption type of 0x17 and preauth type of 0.  There is no `/opsec` option to AS-REP Roast with a high encryption type and even if there was, it would make the hash much harder to crack.

```
event.code: 4768 
```

# AD CS Abuse

When a certificate request is made, the CA generates a `4886 - Certificate Services received a certificate request`.

```
event.code: 4886
```

If the request is successful, and a certificate issued, the CA generates a `4887 - Certificate Services approved a certificate request and issued a certificate`.

```
event.code: 4887
```

The template name is not logged and neither is the subject alternate name. There is practically no indication which are malicious requests. The defender would have to go to the CA itself and lookup the certificate by way of the `Request ID`.

Finally when a TGT is requested, the DC generates a `4768 event`.

> **Note**: Not easy to correlate.