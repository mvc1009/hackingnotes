---
title: C2 - Cobalt Strike
category: Red Team
order: 3
---

**Cobalt Strike** was one of the first public red team command and control frameworks.

Red Teamers and penetration testers use Cobalt Strike to demonstrate the risk of a breach and evaluate mature security programs.

Cobalt Strike is split into client and a server components. 

Check more info in the official documentation.

* [https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/welcome_main.htm](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/welcome_main.htm)

# Installation

```
sudo apt-get update
sudo apt-get install openjdk-11-jdk
sudo apt install proxychains socat
sudo update-java-alternatives -s java-1.11.0-openjdk-amd64
```

# Starting the Team Server

The server, referred to as the team server, is the controller for the Beacon payload and the host for Cobalt Strike’s social engineering features. The team server also stores data collected by Cobalt Strike and it manages logging.

The server run on a **supported Linux** systems. To start the team server, execute the following command:

```
./teamserver <IP> <Password> <Malleable C2 Profile>

[*] Generating X509 certificate and keystore (for SSL)
[+] Team server is up on 0.0.0.0:50050
[*] SHA256 hash of SSL cert is: eadd46ff4f74d582290ce1755513ddfc0ffd736f90bed5d8d662ee113faccb43
```
Once started we can launch the client and connect with the password used.

[IMAGEN]

Verify the server's fingerprint before connecting.

> **Important:** The team server allows multiple clients to connect at the same time. If remote team members needs to connect, you shouldn't expose port 50050 directly to internet. Use a secure remote access solution such as SSH or VPN.


## Listeners