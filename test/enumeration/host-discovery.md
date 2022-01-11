---
description: >-
  When we have our pool of IP addresses, we have to identify the devices and the
  roles played by each IP in the target organization.
---

# Host Discovery 🛎

## Live Hosts

There are different methods that one can use to identify live hosts. 

### ICMP Ping Sweep

The most common is the **ICMP ping sweep.** It consists of ICMP ECHO requests sent to multiple hosts. If a given host is alive, it will return an ICMP ECHO reply.

```text
fping -a -g [IP-Range]/[Mask]

nmap -sn [IP-Range]/[Mask] -oG ping-sweep.nmap
grep "Up" ping-sweep.nmap | cut -d " " -f 2
```

{% hint style="info" %}
**Note**: For internal Audits, when a host reply a ping shown by fping and doesn't reply for nmap command this could be a **router** or **switch.**
{% endhint %}

Other technic to detect live hosts with ICMP Ping sweep is with this script:

```text
#!/bin/bash

for i in $(seq 1 255); do
    timeout 1 bash -c "ping -c 1 10.10.10.$i" > /dev/null && echo "10.10.10.$i - Active" &
done; wait
```

### Most common ports

The second technique is doing a most common port scanner with the following ports:

* 22 - SSH
* 80 - HTTP
* 443 - HTTPS
* 445 - SMB

```text
nmap -p 22,445,80,443 [IP-Range]/[Mask]
```

