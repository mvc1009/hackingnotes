---
title: Domain Enumeration
category: Active Directory
order: 1
---

In order to obtain information about our target domain we need to enumerate it. There are several ways to enumerate the domain with some kali tools, but in this section we are going to use PowerShell and the .NET framework.

* Domain Class:

```powershell
$ADClass = [System.DirectoryServices.ActiveDirectory.Domain]
$ADClass::GetCurrentDomain()
```
Exists multiple scripts to enumerate the domain.

* **PowerView.ps1**: [https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
* **AD Module**: [https://github.com/samratashok/ADModule](https://github.com/samratashok/ADModule)

## Importing the module

*  PowerView

First of all the module needs to be imported. Normally is not detected by AV, in case of detection, AMSI will need be evaded.

```powershell
Import-Module .\PowerView.ps1
. .\PowerView.ps1
```

* ADModule

Its important to import first a `.dll` file if RSAT is not installed on the machine.

```powershell
Import-Module .\Microsoft.ActiveDirectory.Management.dll
Import-Module .\ActiveDirectory\ActiveDirectory.psd1
```

## Current Domain

*  PowerView
```powershell
Get-NetDomain
```

* ADModule
```powershell
Get-ADDomain
```

## Another Domain

*  PowerView
```powershell
Get-NetDomain -Domain corp.local
```

* ADModule
```powershell
Get-ADDomain -Identity corp.local
```

## Domain SID

*  PowerView
```powershell
Get-DomainSID
```

* ADModule
We can find the SID inside the `Get-ADDomain` output.

```powershell
(Get-ADDomain).DomainSID
```

## Domain Policy

*  PowerView
```powershell
Get-DomainPolicy
(Get-DomainPolicy)."system access"
(Get-DomainPolicy -Domain corp.local)."system access"
```

## Domain Controllers

*  PowerView
```powershell
Get-NetDomainController
Get-NetDomainController -Domain corp.local
```
* ADModule
```powershell
Get-ADDomainController
Get-ADDomainController -DomainName corp.local
```

## Users & their Properties / Attributes

*  PowerView
```powershell
Get-NetUser
Get-NetUser -Username <user>
Get-UserProperty
Get-UserProperty -Properties pwdlastset
```

* ADModule
```powershell
Get-ADUser -Filter * -Properties *
Get-ADUser -Identity <username> -Properties *
Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property | select Name
Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}
```

> **Note:** Some sysadmins paste the password on the description field.

### Search a particular string in users's attributes

Valuable info can be found in user's attributes such as description.

*  PowerView
```powershell
Find-UserField -SearchField Description -SearchTerm "built"
```

*  ADModule

```powershell
Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | select name,Description
```

## Computers in the domain

*  PowerView
```powershell
Get-NetComputer
Get-NetComputer -OperatingSystem "*Server 2016*"
Get-NetComputer -Ping
Get-NetComputer -FullData
```

*  ADModule
```powershell
Get-ADComputer -Filter * | select Name
Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' -Properties OperatingSystem | select Name,OperatingSystem
Get-ADComputer -Filter * -Properties DNSHostname | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}
Get-ADComputer -Filter * -Properties *
```

## Domain Groups

*  PowerView
```powershell
Get-NetGroup
Get-NetGroup -Domain <targetdomain>
Get-NetGroup -FullData
```
> **Note**: It is also possible search for all groups containing a word:

```powershell
Get-NetGroup *admin*
```

*  ADModule
```powershell
Get-ADGroup -Filter * | select Name
Get-ADGroup -Filter * -Properties *
```

> **Note**: It is also possible search for all groups containing a word:

```powershell
Get-ADGroup -Filter 'Name -like "*admin*"' | select Name
```

### Find memberships

*  PowerView
```powershell
Get-NetGroupMember -GroupName "Domain Admins" -Recurse
Get-NetGroup -UserName "username"
```

*  ADModule
```powershell
Get-ADGroupMember -Identity "Domain Admins" -Recursive
Get-ADPrincipalGroupMembership -Identity username
```

## Local Groups

To do that task needs administrator privs on non-dc machines.

*  PowerView
```powershell
Get-NetLocalGroup -ComputerName dc01.corp.local -ListGroups
Get-NetLocalGroup -ComputerName filesrv1.corp.local -ListGroups
```

The following command shows the members of all the local groups on a machine.

```powershell
Get-NetLocalGroup -ComputerName filesrv1.corp.local -ListGroups -Recurse
```

## Logged Users (User has a session on)

Like local groups to do that task needs administrator privs on non-dc machines.


*  PowerView

Get actively logged users on a computer _(needs local admin rights on the target)_
```powershell
Get-NetLoggedon -ComputerName filesrv1.corp.local
```

Get locally logged users on a computer _(needs remote registry on the target (by default))_
```powershell
Get-LoggedonLocal -ComputerName filesrv1.corp.local
```

Get the last logged user on a computer _(needs local admin rights and remote registry on the target (by default))_
```powershell
Get-LastLoggedOn -ComputerName filesrv1.corp.local
```

## Find important targets

### Shares

*  PowerView
```powershell
Invoke-ShareFinder -Verbose
```

### Sensitive Files

*  PowerView
```powershell
Invoke-FileFinder -Verbose
```

### File servers

* PowerView
```powershell
Get-NetFileServer
```

## Group Policy (GPO)

Group Policy provides the ability to manage configuration and changes easily and centrally in active directory.


*  PowerView
```powershell
Get-NetGPO
Get-NetGPO -ComputerName machine01.corp.local
Get-NetGP OGroup
```

*  ADModule
```powershell
Get-GPO -All
Get-GPResultantSetOfPolicy -ReportType Html -Path c:\windows\temp\report.html
```
> **NOTE:** We can get more infomration with:
>`gpresult /R /V`




















*  PowerView
```powershell
```

*  ADModule
```powershell
```
