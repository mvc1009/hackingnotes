---
description: Some tips to discover the operative system that runs on the target machine.
---

# OS Discovery 🖥

## TTL

The default values of TTL on a ICMP packet, shown in the following table, can help us to identify the operative system:

| Operative System | TTL |
| :--- | :--- |
| Windows | 128 |
| Linux | 64 |
| Solaris / AIX | 254 |
| OpenBSD | 255 |
| FreeBSD 5.0 | 64 |
| FreeBSD 3.4, 4.0 | 255 |
| Cisco | 254 |

The following example is for a **Linux** device:

```text
❯ ping localhost
PING localhost(localhost (::1)) 56 data bytes
64 bytes from localhost (::1): icmp_seq=1 ttl=64 time=0.053 ms
64 bytes from localhost (::1): icmp_seq=2 ttl=64 time=0.051 ms
```

