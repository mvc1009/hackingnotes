---
title: PORT 80/tcp, 443/tcp - HTTP Server
category: Services
order: 5
---

It is a brief methodology to use in front of web applications.

# Scanning

First of all we need to scan the ports and use some enumerating tools such as `nmap`, `nikto` or `davtest`.

## Nmap

Search for vulns:

```
nmap -p 80,443 -sV -sC --script=http-vuln* 10.10.10.10
```

Search for info:

```
nmap -p 80,443 -sV -sC 10.10.10.10
```

## Nikto

Nikto is a free software command-line vulnerability scanner that scans webservers for dangerous files/CGIs.

```
nikto -host 10.10.10.10:80
```

## Davtest

DAVTest tests WebDAV enabled servers by uploading test executable files, and then (optionally) uploading files which allow for command execution or other actions directly on the target.

```
davtest --url http://10.10.10.10
```

# Fuzzing

In the world of cybersecurity, **fuzz** testing (or **fuzzing**) is an automated software testing technique that attempts to find hackable software bugs by randomly feeding invalid and unexpected inputs and data into a computer program in order to find coding errors and security loopholes.

This technique is also used to discover new web content such as directories, files or parameters. There are many different tools that could help us to do fuzzing in web applications (wfuzz, ffuf, dirb, dirbuster...). But I'm going to use wfuzz and ffuf.

## Directory Fuzzing

Wordlist:

```
/usr/share/wordlist/dirbuster/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt

#IIS Server
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt
```

> **Note**: _IIS server_ is **non-case sensitive**

Command:

```
gobuster dir -w wordlists.txt -x 'asp,aspx,html' -b 404 -u http://SEVER_IP:PORT/
ffuf -w wordlists.txt:FUZZ -e .php,.html-.aspx -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1
dirb http://SERVER_IP:PORT
wfuzz -Z -c -w wordlists.txt -z list,-.asp-.aspx-.html --hc 404 http://SERVER_IP:PORT/FUZZFUZ2Z
```

## Vhost Fuzzing

Wordlists:

```
/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Discovery/DNS/shubs-subdomains.txt
```

Command for different hosts:

```
ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.example.com/
```

Command for the same host:

```
wfuzz -Z -c -w /usr/share/seclists/Discovery/DNS/shubs-subdomains.txt -H "Host: FUZZ.example.com" --hh <length> http://ip-addr
```

## Parameter Fuzzing

Wordlist:

```
/opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt
```

### GET

```
ffuf -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://example.com/admin/admin.php?FUZZ=key -fs xxx
```

### POST

```
 ffuf -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://example.com/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```

# Default Installation Routes

These are some default installation routes of Linux and Windows webservers.

## Linux

```
/var/www/html/
```

## Windows

```
C:\xampp\htdocs\
C:\inetpub\wwwroot\
```
