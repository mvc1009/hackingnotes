---
title: Host Privilege Escalation
category: Red Team
order: 6
---

Privilege escalation allows us to elevate privileges from a user to local administrator. Notice that is not a necessary step, elevated privileges can provide a tactical advantage by allowing you to leverage some additional capabilities (dumping creds with Mimikatz or manipulate host configuration).

> **Note**: We need to mantain the principle of least privilege to reach the assessment goal. Exploiting a pirivilege escalation vulnerability provides defenders with additional data points to detect the presence.

`SharpUp` is C# version of `PowerUp`.

* [https://github.com/GhostPack/SharpUp](https://github.com/GhostPack/SharpUp)

Different techniques to exploit privilege escalation are detailed on [https://mvc1009.github.io/hackingnotes/privilege-escalation/windows-privesc/](Windows Privilege Escalation) on this gitbook.

# Windows Services

A Windows "service" is a special type of application that is usually started automatically when the computer boots. Services are used to start and manage core Windows functionality such as Windows Defender, Windows Firewall, Windows Update and more. Third party applications may also install a Windows Service to manage how and when they're run.


> **OPSEC Alert**: Restore the service configuration once you are done. Ensure you don't interrupt business critical services, so seek permission before exploiting these types of vulnerabilities.


# Unquoted Service Path

An unquoted service path is where the path to the service binary is not wrapped in quotes. It's not a problem but in certain environment it can lead to privilege escalation.

```
beacon> run wmic service get name,pathname
```
> **Note**: Standard users cannot stop, restart or start services by default, so you would usually need to wait for a computer reboot.


# Always Install Elevated

This policy allows standard users to install applications that require access to directories and registry keys that they may not usually have permission to change. This is equivalent to granting full administrative rights and even though Microsoft strongly discourages its use, it can still be found.

> **Note**: When this MSI is eventually installed, it will appear as an installed program on the target. Change properties such as `Author` and `Manufacturer`.


