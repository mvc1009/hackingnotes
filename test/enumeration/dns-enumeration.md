---
description: >-
  The Domain Name System (DNS) is on of the most critical systems on the
  Internet and is a distributed database responsible for translating
  user-friendly domain names into IP addresses.
---

# DNS Enumeration

## Interacting with DNS servers

DNS queries produce listintgs calles Resource Records. This is a representation of Resource Records:

![Table of DNS Record Types ](../.gitbook/assets/understanding-different-types-of-record-in-dns-server-2-1.png)

### DNS Lookup

A **DNS lookup** is the simplest query a DNS server can receive. Its asks the DNS to resolve a given hostname.

```text
nslookup [Domain]
dig [Domain]
host [DOMAIN]
```

Once we retrieved all the IP addresses corresponding to the domains, we need to consider two things:

* **Is this IP address hosting only that given domain?**

It is possible that more than one domain is configured on the same IP address, even if a PTR record is not set. This is also typical in corporate networks where multiple subdomains run on the same web server. First thing to try is **reverse lookup** and the second is **search** on **google** or **bing**:

```text
bing> ip:[IP]
```

* Who does this IP address belongs to?

To search the owner of an IP address we can use [whois.arin.net](https://whois.arin.net) or one of the WHOIS tools seen earlier

In order to collect the highest number of domains and subdomain related to the target organization, we can use different techniques:

* DNS Lookup
* MX Lookup
* Zone transfers

### Reverse DNS Lookup

With **Reverse DNS Lookup**, we will recieve the IP address associated to a given domain name. This process queries for DNS pointer records \(PTR\).

```text
nslookup -type=PTR [IP]
dig [Domain] PTR
```

or use online tools:

* [https://network-tools.com/nslookup/](https://network-tools.com/nslookup/)

### Mail Exchange Lookup

With **MX\(Mail Exchange\) lookup**, we retrieve a list of servers responsible for delivering emails for that domain:

```text
nslookup -type=MX [Domain]
dig [Domain] MX
```

or use online tools:

* [https://www.dnsqueries.com/](https://www.dnsqueries.com/)
* [https://www.mxtoolbox.com/](https://www.mxtoolbox.com/)

### Zone Transfers

**Zone transfers** are usually a misconfiguration of the remote DNS server. They should be enabled only for trusted IP addresses. Whe zone transfers are enabled, we can enumerate the entire DNS record for that zone. This includes all the sub domains **\(A records\).**

```text
nslookup -type=NS [Domain]
dig [Domain] NS
host -t ns [Domain]
```

There are usually  two name servers. Take note of both of them an run the next command to show all A records:

```text
nslookup -query=AXFR [Domain] [Nameserver]
dig axfr [Nameserver] [Domain]
host -l [Domain] [Nameserver]
dnsrecon -d [Domain] -axfr
```

Another technique to discover A records if Zone transfers are well configured is to **bruteforce** them with a most common subdomain names:

```text
fierce -dns [Domain] -dnsserver [Nameserver] -f [Wordlist]
dnsmap [Domain]
dnsrecon -d [Domain] -D [Wordlist] -t brt
```



