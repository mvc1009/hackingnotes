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
Get-NetGPO Group
```

*  ADModule
```powershell
Get-GPO -All
Get-GPResultantSetOfPolicy -ReportType Html -Path c:\windows\temp\report.html
```
> **NOTE:** We can get more infomration with:
>`gpresult /R /V`

### Users on Localgroups

We can also get users which are in a local group of a machine using GPO.

* PowerView:
```powershell
Find-GPOComputerAdmin -Computer machine01.corp.local
```

Or we can find machines where a user is member of a specific group.

* PowerView:
```powershell
Find-GPOLocation -UserName <user> -Verbose
```

## Organization Unit (OU)

* PowerView:
```powershell
Get-NetOU -FullData
```

* ADModule:
```powershell
Get-ADOrganizationalUnit -Filter * -Properties *
```

To read which GPO is aplied to each OU, use the `gplink` value extracted from `Get-NetOU`.

* PowerView:
```powershell
Get-NetGPO -GPOname '{FD2B3AF5-356B-ADE4-98C1F4EF8081}'
```

* ADModule:
```powershell
Get-GPO -Guid FD2B3AF5-356B-ADE4-98C1F4EF8081
```

## Access Control Model (ACL)

Enables control on the ability of a process to access objects and other resources in active diectory based on: 
	
	* **Access Tokens**: Security context of a process which contains the identity and privileges of a user.
	* **Security Descriptors**: SID of the owner , Discretionary ACL (DACL) and System ACL (SACL).

It's a list of Access Control Entities (ACE) which corresponds to an individual permission or audits access. Determines who has permission and what can be done on an object. 

Exists two types:

	* **DACL**: Defines the permissions trustees a user or group have on an object.
	* **SACL**: Logs sucess and failure audit messages when an object is accessed.

ACLs are vital to security architecture of Active Directory.

We can list the ACLs associated to a specified object, with a specified prefix, specified LDAP search or to specific path.

* PowerView:
```powershell
Get-ObjectAcl -SamAccountName <username> -ResolveGUIDs
Get-ObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbose
Get-ObjectAcl -ADSpath "LDAP://CN=Domain Admins,CN=Users,DC=corp,DC=local" -ResolveGUIDS -Verbose
Get-PathAcl -Path "\\dc01.corp.local\sysvol"
```

* ADModule:
```powershell
(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=corp,DC=local').Access
```

PowerView has a module named `ACLScanner` that finds interesting ACL such as ACL that are modified or ones which determines where and which object we can modify.

* PowerView:
```powershell
Invoke-ACLScanner -ResolveGUIDs
```

## Domain Trusts

In an active directory environment, trust is a relationship between two domains or forests which allows users of one domain or forest to access resources in the other domain or forest.

Trust can be automatic for example parent-child, same forest, etc... or established manually.

Trusted Domain Objects (TDOs) the trust relationship in a domain.

### Directions of Trust

Exist diferent directions of Trust:

* **One-Way Trust**:

It is unidirectional. Users in the trusted domain can access resources in the trusting domain but not backwards.

![One-Way-Trust](/hackingnotes/images/one-way-trust.png)

* **Two-Way Trust**:

It is bidirectional. Users of both domains can access resources in the other domain

![Two-Way-Trust](/hackingnotes/images/two-way-trust.png)

### Trust Transitivity

Exist different types of transitivity on a domain:

* **Transitive**:

Transitivie is a property of trust which means that the trust can be extended to etablish trust relationships with other domains.

All the default intra-forest trust relationships such as Tree-Root or Parent-Child between domains within a same forest are transitive Two-Way trusts.

![Trust Transitive](/hackingnotes/images/trust-transitive.png)

Means that Domain A trusts Domain B and Domain B trusts Domain C so Domain A also trusts Domain C in a Two-Way Trust direction.


* **Nontransitive**:

Nontransitive means that the trust can not be extended to other domains in the forest, we can find it on a two-way or one-way.

This is the default trust called external trust between two domains in different forests, when forests do not have a trust relationship.

## Type of Trusts

There are many types of trusts:

### Default / Automatic Trusts

* **Parent-Child**:

It is created automatically between the new domain an the domain that precedes it (parent-child trust) in the namespace hierarchy, whenever a domain is added in a tree.

For example lab.corp.local is a child of corp.local. Always the trust is in a two-way transitive.


* **Tree-Root**:

It is created automatically between whenever a new domain tree is added to a forest root.

The trust is always two-way transitive.

![Domain Trusts](/hackingnotes/images/domain-trusts.png)

### Shortcut Trust

The shortcut trust is used to reduce access times in a complex trust scenarios. We can found it in a one-way or two-way transitive form.

![Shortcut Trusts](/hackingnotes/images/shortcut-trust.png)

### External Trusts

An external trust gives the opportunity of trust between two domains in different forests which do not have any trust relationship. Can be one-way or two-way and is nontransitive.

![External Trusts](/hackingnotes/images/external-trust.png)

### Forest Trust

Forest trust is a trust between forest root domains. Cannot be extended to a third forest so has no implicit trust.

Can be one-way or two-way and transitive or nontransitive.

![Forest Trusts](/hackingnotes/images/forest-trust.png)

> **Note**: In case of nonsensitvie Forest 1 would not have any type of trust relationship with Forest 3.

## Domain Trust Mapping

We can get a list of all domain trusts for a domain.

* PowerView:
```powershell
Get-NetDomainTrust
Get-NetDomainTrust -Domain es.lab.corp.local
```

* ADModule:
```powershell
Get-ADTrust
Get-ADTrust -Identity es.lab.corp.local
```

## Forest Mapping

We can get details about a forest:

* PowerView:
```powershell
Get-NetForest
Get-NetForest -Forest extcorp.local
```
* ADModule:
```powershell
Get-ADForest
Get-ADForest -Identity extcorp.local
```

We can get all domains in a forest:

* PowerView:
```powershell
Get-NetForestDomain
Get-NetForestDomain -Forest extcorp.local
```

* ADModule:
```powershell
(Get-ADForest).Domains
```

We can get all global catalogs of a forest:

* PowerView:
```powershell
Get-NetForestCatalog
Get-NetForestCatalog -Forest extcorp.local
```

* ADModule:
```powershell
Get-ADForest | select -ExpandProperty GlobalCatalogs
```

We can get the map trusts of a forest:

* PowerView:
```powershell
Get-NetForestTrust
Get-NetForestTrust -Forest extcorp.local
```

* ADModule:
```powershell
Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'
```

## User Hunting 

### Local Admin Check

Find all machines on the current domain where the current user has local admin access.

* PowerView:
```powershell
Find-LocalAdminAccess -Verbose
```

> **Note**: This function queries the domain controller for a list of computers `Get-NetComputer` and then use multi-threaded `Invoke-CheckLocalAdminAccess` on each machine.
> **MAKE A LOT OF NOISE**

In case `Find-LocalAdminAccess` is blocked you can use:

```powershell
Import-Module .\Find-WMILocalAdminAccess.ps1
Find-WMILocalAdminAccess -ComputerName machine01.corp.local
Find-WMILocalAdminAccess -ComputerFile .\computers.txt -Verbose
```
> **NOTE**: WMI needs ADMIN PRIV to work, so if we get an error is that the user has not enough privileges.

### Get Local Admins (Local Admin Priv. needed)

We can find local admins on all machines of the domain but we need administrator privileges on non-dc machines.

* PowerView:
```powershell
Invoke-EnumerateLocalAdmin -Verbose
```
> **Note**: This function queries the DC fo a list of computers `Get-NetComputer` an then use multi-threaded `Get-NetLocalGroup` on each machine.
> **MAKE A LOT OF NOISE**

### Machines where a User/Group has session

We can find computers where a domain admin or another specified user or group has an active session:

* PowerView:
```powershell
Invoke-UserHunter
Invoke-UserHunter -GroupName "RDPUsers"
Invoke-UserHunter -UserName "john.brown"
```
> **Note**: This function queries the DC for members of a given group using `Get-NetGroupMember`, gets a list of computers with `Get-NetComputer` and list sessions and logged users with `Get-NetSession` and `Get-NetLoggedon` from each machine.

We can also confirm the admin access with:

* PowerView:
```powershell
Invoke-UserHunter -CheckAcces
```
We can also find with `Invoke-UserHunter` where a domain admin is logged-in.

* PowerView:
```powershell
Invoke-UserHunter -Stealth
```
> **Note**: This option queries the DC for members of the given group using `Get-NetGroupMember`, gets a list of _only of high traffic servers such as DC, File Servers and Distributed File Servers_ for less traffic generation and list sessions and logged on users with `Get-NetSession` and `Get-NetLoggedon`.
> **MAKE NOISE**


> **DEFENSE NOTE**: 
> `Netcease.ps1` is a script which change permission on the NetSessionEnum by removing permission to Authenticated Users group.
> [https://github.com/p0w3rsh3ll/NetCease](https://github.com/p0w3rsh3ll/NetCease).
>
> The binary net.exe uses SAMR protocol, exists another script which hardens a server.
> [https://vulners.com/n0where/N0WHERE:139229](https://vulners.com/n0where/N0WHERE:139229)