---
title: PORT 111/tcp - RPCBind
category: Services
order: 6
---

Provides information between Unix based systems. Port is often probed, it can be used to fingerprint the Nix OS, and to obtain information about available services. Port used with NFS, NIS or others..

# Enumeration

We can enumerate RPCBind service with `rpcinfo` or `nmap`:

```
rpcinfo ip-addr
nmap -sSUC -p 111 ip-addr
```

**Example** output of `rpcinfo`:

```
program version netid     address                service    owner
    100000    4    tcp6      ::.0.111               portmapper superuser
    100000    3    tcp6      ::.0.111               portmapper superuser
    100000    4    udp6      ::.0.111               portmapper superuser
    100000    3    udp6      ::.0.111               portmapper superuser
    100000    4    tcp       0.0.0.0.0.111          portmapper superuser
    100000    3    tcp       0.0.0.0.0.111          portmapper superuser
    100000    2    udp       0.0.0.0.0.111          portmapper superuser
    100000    4    local     /run/rpcbind.sock      portmapper superuser
    100000    3    local     /run/rpcbind.sock      portmapper superuser
    100005    1    udp       0.0.0.0.128.213        mountd     superuser
    100005    1    tcp       0.0.0.0.208.235        mountd     superuser
    100005    1    udp6      ::.163.28              mountd     superuser
    100005    1    tcp6      ::.183.211             mountd     superuser
    100005    2    udp       0.0.0.0.190.193        mountd     superuser
    100005    2    tcp       0.0.0.0.188.127        mountd     superuser
    100005    2    udp6      ::.233.215             mountd     superuser
    100005    2    tcp6      ::.165.45              mountd     superuser
    100005    3    udp       0.0.0.0.130.78         mountd     superuser
    100005    3    tcp       0.0.0.0.148.209        mountd     superuser
    100005    3    udp6      ::.150.143             mountd     superuser
    100005    3    tcp6      ::.217.45              mountd     superuser
    100003    2    tcp       0.0.0.0.8.1            nfs        superuser
    100003    3    tcp       0.0.0.0.8.1            nfs        superuser
    100003    4    tcp       0.0.0.0.8.1            nfs        superuser
    100227    2    tcp       0.0.0.0.8.1            -          superuser
    100227    3    tcp       0.0.0.0.8.1            -          superuser
    100003    2    udp       0.0.0.0.8.1            nfs        superuser
    100003    3    udp       0.0.0.0.8.1            nfs        superuser
    100003    4    udp       0.0.0.0.8.1            nfs        superuser
    100227    2    udp       0.0.0.0.8.1            -          superuser
    100227    3    udp       0.0.0.0.8.1            -          superuser
    100003    2    tcp6      ::.8.1                 nfs        superuser
    100003    3    tcp6      ::.8.1                 nfs        superuser
    100003    4    tcp6      ::.8.1                 nfs        superuser
    100227    2    tcp6      ::.8.1                 -          superuser
    100227    3    tcp6      ::.8.1                 -          superuser
    100003    2    udp6      ::.8.1                 nfs        superuser
    100003    3    udp6      ::.8.1                 nfs        superuser
    100003    4    udp6      ::.8.1                 nfs        superuser
    100227    2    udp6      ::.8.1                 -          superuser
    100227    3    udp6      ::.8.1                 -          superuser
    100021    1    udp       0.0.0.0.167.136        nlockmgr   superuser
    100021    4    tcp       0.0.0.0.174.121        nlockmgr   superuser
    100021    1    udp6      ::.164.129             nlockmgr   superuser
    100021    1    tcp6      ::.130.83              nlockmgr   superuser
```

## NFS

If you find the service NFS then probably you will be able to list and download(and maybe upload) files:

```
nmap -p 2049 -sV --script nfs-\* ip-addr
showmount -e ip-addr
```

After finding the nfs folder we can mount these shares in our filesystem:

```
sudo mount -o nolock -t nfs [-o vers=2] <ip-addr>:<remote_folder> <local_folder> 
```

* [NFS Service](../nfs)

# References:

* [https://docs.oracle.com/cd/E56339\_01/html/E53865/gntib.html](https://docs.oracle.com/cd/E56339\_01/html/E53865/gntib.html)
* [https://book.hacktricks.xyz/pentesting/nfs-service-pentesting](https://book.hacktricks.xyz/pentesting/nfs-service-pentesting)
* [https://book.hacktricks.xyz/pentesting/pentesting-rpcbind](https://book.hacktricks.xyz/pentesting/pentesting-rpcbind)
