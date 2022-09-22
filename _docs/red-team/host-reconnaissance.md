---
title: Host Reconnaissance
category: Red Team
order: 4
---

After compromising a target is important to collect as many data as possible without being detected.

# .NET version

In order to execute our binaries as desired we need to compile them in the correct `.NET` version.

We can check version installed with:

```
beacon> reg queryv x64 HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full Release
```
We can check the version on microsoft documentation.

* [https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/versions-and-dependencies](https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/versions-and-dependencies)

We don't have to compile our binary with the exact version of .NET installed on the target machine. The `Common Language Runtime (CLR)` is a component of .NET Framework that manages the execution of .NET assemblies, and each .NET framework release is designed to run on a specific version of CLR.

We just need to compile our assemblie on a version with the same CLR of the target.

| .NET Framework Version | CLR Version |
|:----------------------:|:-----------:|
|      2.0, 3.0, 3.5     |      2      |
|       4, 4.5-4.8       |      4      |


# Host Safety-Checks

`Seatbelt` is a .NET application written in C# that makes various checks.

```
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Debug\Seatbelt.exe -group=system
```
* [https://github.com/GhostPack/Seatbelt](https://github.com/GhostPack/Seatbelt)

> **Note**: The source code should be compiled with the .NET CLR version of the target.

With the parameter `-group=user` we can enumerate the user's environment.

```
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Debug\Seatbelt.exe -group=user
```

# Web Proxies

A web proxy acts an intermediary between a client and a target web server. They are commonly deployed across organizations for filtering, monitoring, performance and security.

`SSL offloading` can even be used to inspect HTTPS traffic. This is achieved by establishing two independent HTTPS sessions, one between the client and the proxy and the other one between the proxy and the server.

So our HTTP beacon traffic may be logged.

We can check internet settings with `Seatbelt`.

```
beacon> execute-assembly .\Seatbelt.exe InternetSettings

  HKCU                     ProxyEnable : 1
  HKCU                     ProxyOverride : ;local
  HKCU                     ProxyServer : squid.corp.local:8080
```

There are differents methods to see if we are reciving traffic through a web proxy, one method is to sniff the traffic and see with wireshark if any additional headers add added by the proxy.
