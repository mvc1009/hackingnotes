# PORT 21/tcp - FTP

## Introduction

## FileZilla Server (From LFI)

### FileZilla Server credentials

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

{% hint style="info" %}
**Note**: You need to modify **password** and **salt** variables of the python script and unescape the salt.
{% endhint %}

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

{% embed url="https://github.com/l4rm4nd/FileZilla-Password-Decryptor" %}

### FileZilla client credentials

FileZilla client save last saved credentials on the following link.

```
C:\Users\VICTIM\AppData\Roaming\FileZilla\RecentServers.xml
```
