---
title: PORT 53/tcp - DNS
category: Services
order: 3
---

The Domain Name System (DNS) is the phonebook of the Internet. Humans access information online through domain names, like nytimes.com or espn.com.

# Introduction

In this section only will be shown the methodology to enumerate locally the DNS service. If you need to take a look of DNS enumeration vía internet, you will found in the following section.

* [Information Gathering](../../reconnaissance/information-gathering/)

**DNS queries** produce listing calls Resource Records. This is a representation of Resource Records:

![Table of DNS Record Types](/hackingnotes/images/table_dnstypes.png)

# Enumeration

First we will need to a Reverse DNS Lookup,

With **Reverse DNS Lookup**, we will receive the IP address associated to a given domain name.

```
# With nslookup
nslookup
> server IP_DNS_SERVER
> IP

# With dig
dig -x IP @IP_DNS_SERVER
```

There are usually two name servers. Take note of both of them an run the next command to show all A records:

```
nslookup -query=AXFR [Domain] [Nameserver]
dig axfr DOMAIN.LOCAL @IP_DNS_SERVER
```

Finally, just add the DNS records to you `/etc/hosts`.
