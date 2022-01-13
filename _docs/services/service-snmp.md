---
description: >-
  The Simple Network Management Protocol (SNMP) talks to your network to find
  out information related to this network device activity: for example, bytes,
  packets, and errors transmitted and received.
---

# PORT 161/udp - SNMP

## Introduction

SNMP is not well-understood by many network administrators. This often results in SNMP misconfigurations, which can result in significant information leakage.

## Scanning the network

To scan for open SNMP ports we can use nmap:

```
sudo nmap -sU --open -P 161 <ip-addr>/<mask> -oG open-snmp.nmap
```

### Bruteforce attack

We can use tools such as `onesixtyone`, which will attempt to brute force attack against a list of IP addresses. First we need to create a file containing community strings:

```
echo public > community.txt
echo private >> community.txt
echo manager >> community.txt

for ip in $(seq 1 254); do echo 10.0.0.$ip; done > ips.txt
```

And run the tool:

```
onesixtyone -c community.txt -i ips.txt
```

## Enumeration

### Entire MIB Tree

```
snmpwalk -c public -v1 -t 10 <ip-addr>
```

### Windows Users

```
snmpwalk -c public -v1 -t <ip-addr> 1.3.6.1.4.1.77.1.2.25
```

### Running Windows Processes

```
snmpwalk -c public -v1 <ip-addr> 1.3.6.1.2.1.25.4.2.1.2
```

### Open TCP Ports

```
snmpwalk -c public -v1 <ip-addr> 1.3.6.1.2.1.6.13.1.3
```

### Installed Software

```
snmpwalk -c public -v1 <ip-addr> 1.3.6.1.2.1.25.6.3.1.2
```
