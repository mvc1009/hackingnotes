---
description: >-
  The Domain Name System (DNS) is the phonebook of the Internet. Humans access
  information online through domain names, like nytimes.com or espn.com.
---

# PORT 53/tcp/udp - DNS

## Introduction

In this section only will be shown the methodology to enumerate locally the DNS service. If you need to take a look of DNS enumeration vía internet, you will found in the following section.

{% page-ref page="../reconnaissance/information-gathering.md" %}

**DNS queries** produce listing calls Resource Records. This is a representation of Resource Records:

![Table of DNS Record Types ](../.gitbook/assets/understanding-different-types-of-record-in-dns-server-2-1.png)

## Enumeration

First we will need to a Reverse DNS Lookup,

With **Reverse DNS Lookup**, we will receive the IP address associated to a given domain name. 

```text
# With nslookup
nslookup
> server IP_DNS_SERVER
> IP

# With dig
dig -x IP @IP_DNS_SERVER
```

There are usually  two name servers. Take note of both of them an run the next command to show all A records:

```text
nslookup -query=AXFR [Domain] [Nameserver]
dig axfr DOMAIN.LOCAL @IP_DNS_SERVER
```

Finally, just add the DNS records to you `/etc/hosts`.

