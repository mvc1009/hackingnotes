---
title: PORT 3389/tcp - RDP
category: Services
order: 14
---

# Introduction

Remote Desktop Protocol is a proprietary protocol developed by Microsoft which provides a user with a graphical interface to connect to another computer over a network connection. The user employs RDP client software for this purpose, while the other computer must run RDP server software

![](/hackingnotes/images/rdp.png)

# Enumeration

With nmap we can enumerate the service a little bit, and obtain information such as the DOMAIN or the HOSTNAME. Also checks available encryption and DoS vulnerabilities.

```
nmap -sV --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -p 3389 <ip-addr>
```

## Checking Credentials

With `rdp_check` we can check credentials.

```
rdp_check <domain>/<username>:<password>@<ip-addr>
```

# Connect via RDP

## rdesktop

```
rdesktop <ip-addr>
rdesktop -u <user> -p <password><ip-addr>
rdesktop -d <domain> -u <user> -p <password> <ip-addr>
```

## xfreerdp

**xfreerdp** is an X11 Remote Desktop Protocol (RDP) client which is part of the FreeRDP project. An RDP server is built-in to many editions of Windows. Alternative servers included xrdp and VRDP (VirtualBox).

```
xfreerdp /d:<domain> /u:<user> /p:<password> /v:10.10.10.10
xfreerdp /u:<user> /p:<password> /v:10.10.10.10
```

Connect RDP via pass the hash.

```
xfreerdp /u:<user> /pth:e3071bcf8c3ad25c891a8898f56aa62b /v:10.10.10.10
```

Other configurations.

```
/workarea                        Full Window
+clipboard                       Enable shared clipboard
/drive:share,/mnt/folder        Create a Shared folder
```

# Post Exploitation

With `mimikatz` is possible to obtain the current sessions and connect it. Check section \*\*`Hijacking RDP Session` \*\* to more info.

* [Get Credentials](../../transfering-files/get-credentials/)

# Enable RDP

When we fully compromised the server we can enable RDP.

```
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

And add the user or group to the Remote Desktop Users group.

```
net localgroup “remote desktop users” user  /add
```
