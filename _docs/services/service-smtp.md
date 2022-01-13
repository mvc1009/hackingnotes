---
description: >-
  The Simple Mail Transfer Protocol (SMTP) is a communication protocol for
  electronic mail transmission. As an Internet standard.
---

# PORT 25/tcp - SMTP

## Enumeration

### User Enumeration

SMTP supports several interesting commands, such as `VRFY` and `EXPN`.

* **VRFY**: Ask the server to verify and email address.
* **EXPN**: Ask the server for membership of a mailing list.

```
smtp-user-enum.pl -M VRFY -U users.txt -t 10.0.0.1
smtp-user-enum.pl -M EXPN -u admin1 -t 10.0.0.1
smtp-user-enum.pl -M RCPT -U users.txt -T mail-server-ips.txt
smtp-user-enum.pl -M EXPN -D example.com -U users.txt -t 10.0.0.1
```

## Send Mails

### Telnet / Netcat

We can conect to our SMTP server via telnet.

```
telnet smtp.server.local 25
nc -nv smtp.server.local 25
```

Once we've got established our connection, we will send a **HELO** with the name of the host we are trying to connect followed by the message

```
HELO smtp.server
MAIL FROM: test@server.local
RCPT TO: victim@server.local
DATA
Subject: Check this out!
Body of the message ended with a dot
.
```

### Swiss Army Knife SMTP (swaks)

Other solution to automatize some tasks is using **swaks**:

```
 swaks --to 'victim@server.local' --from 'test@server.local' --server 'smtp.server.local' --header 'Subject: Check this out!' --body 'Body of the message'
```

## References:

* [https://book.hacktricks.xyz/pentesting/pentesting-smtp](https://book.hacktricks.xyz/pentesting/pentesting-smtp)
* [http://systemadmin.es/2009/01/como-mandar-un-email-con-telnet-protocolo-smtp](http://systemadmin.es/2009/01/como-mandar-un-email-con-telnet-protocolo-smtp)
* [https://metacpan.org/pod/distribution/Mail-Toaster/contrib/swaks](https://metacpan.org/pod/distribution/Mail-Toaster/contrib/swaks)
