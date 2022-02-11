---
title: Domain Enumeration
category: Active Directory
order: 1
---

In order to obtain information about our target domain we need to enumerate it. There are several ways to enumerate the domain with some kali tools, but in this section we are going to use PowerShell and the .NET framework.

* Domain Class:

```
$ADClass = [System.DirectoryServices.ActiveDirectory.Domain]
$ADClass::GetCurrentDomain()
```
Exists multiple scripts to enumerate the domain.

* PowerView.ps1: [https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
* AD Module: [https://github.com/samratashok/ADModule](https://github.com/samratashok/ADModule)

## Importing the module

*  PowerView

First of all the module needs to be imported. Normally is not detected by AV, in case of detection, AMSI will need be evaded.

```
Import-Module .\PowerView.ps1
. .\PowerView.ps1
```

* ADModule

Its important to import first a `.dll` file if RSAT is not installed on the machine.

```
Import-Module .\Microsoft.ActiveDirectory.Management.dll
Import-Module .\ActiveDirectory\ActiveDirectory.psd1
```

## Current Domain

*  PowerView
```
Get-NetDomain
```

* ADModule
```
Get-ADDomain
```

## Another Domain

*  PowerView
```
Get-NetDomain -Domain corp.local
```

* ADModule
```
Get-ADDomain -Identity corp.local
```

## Domain SID

*  PowerView
```
Get-DomainSID
```

* ADModule
We can find the SID inside the `Get-ADDomain` output.

```
(Get-ADDomain).DomainSID
```

## Domain Policy

*  PowerView
```
Get-DomainPolicy
(Get-DomainPolicy)."system access"
(Get-DomainPolicy -Domain corp.local)."system access"
```

## Domain Controllers

*  PowerView
```
Get-NetDomainController
Get-NetDomainController -Domain corp.local
```
* ADModule
```
Get-ADDomainController
Get-ADDomainController -DomainName corp.local
```

## List Users & Properties / Attributes

*  PowerView
```
Get-NetUser
Get-NetUser -Username <user>
Get-UserProperty
Get-UserProperty -Properties pwdlastset
```

* ADModule
```
Get-ADUser -Filter * -Properties *
Get-ADUser -Identity <username> -Properties *
Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property | select Name
Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}
```

> **Note:** Some sysadmins paste the password on the description field.

## Search a particular string in users's attributes

Valuable info can be found in user's attributes such as description.

*  PowerView
```
Find-UserField -SearchField Description -SearchTerm "built"
```

*  ADModule
```
Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | select name,Description
```