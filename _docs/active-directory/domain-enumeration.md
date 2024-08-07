---
title: Domain Enumeration
category: Active Directory
order: 2
---

In order to obtain information about our target domain we need to enumerate it. There are several ways to enumerate the domain with some kali tools, but in this section we are going to use PowerShell and the .NET framework.

* Domain Class:

```powershell
$ADClass = [System.DirectoryServices.ActiveDirectory.Domain]
$ADClass::GetCurrentDomain()
```
Exists multiple scripts to enumerate the domain.

* **PowerView.ps1**: [https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
* **ADModule**: [https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps)
* **SharpView**: [https://github.com/tevora-threat/SharpView](https://github.com/tevora-threat/SharpView)
* **ADSearch**: [https://github.com/tomcarver16/ADSearch](https://github.com/tomcarver16/ADSearch)

# Powerview on Linux

There are some alternatives based on linux systems. 

* [https://github.com/the-useless-one/pywerview](https://github.com/the-useless-one/pywerview)

First we need to obtain a TGT, to do that task we can use `impacket-getTGT`.

```
impacket-getTGT domain/user:pass -dc-ip 10.10.10.10
```

Use `klist` to get the info about the ticket.

```
klist example.ccache
```

We can save the ticket on a variable or we can specify it on each command:

> **Note**: pywerview needs the FULL hostname in SPN to work properly.

```
export KRB5CCNAME=example.ccache
ython3 pywerview.py get-netcomputer -t srv-ad.contoso.com -u stormtroopers -k

KRB5CCNAME=example.ccache python3 pywerview.py get-netcomputer -t srv-ad -u stormtroopers -k
```



# Importing the module

*  PowerView:

First of all the module needs to be imported. Normally is not detected by AV, in case of detection, AMSI will need be evaded.

```powershell
Import-Module .\PowerView.ps1
. .\PowerView.ps1
```

* ADModule:

Its important to import first a `.dll` file if RSAT is not installed on the machine.

```powershell
Import-Module .\Microsoft.ActiveDirectory.Management.dll
Import-Module .\ActiveDirectory\ActiveDirectory.psd1
```

# Current Domain

* PowerShell:
```powershell
$env:USERDNSDOMAIN
```

Identify current user domain
```powershell
(Get-ADDomain).DNSRoot
```
Identify current computer domain
```powershell
(Get-WmiObject Win32_ComputerSystem).Domain
```

* PowerView:
```powershell
Get-NetDomain
```

* PowerView (dev):
```powershell
Get-Domain
```

* ADModule:
```powershell
Get-ADDomain
```

# Another Domain

*  PowerView:
```powershell
Get-NetDomain -Domain corp.local
```

* PowerView (dev):
```powershell
Get-Domain -Identity corp.local
```

* ADModule:
```powershell
Get-ADDomain -Identity corp.local
```

# Domain SID

*  PowerView:
```powershell
Get-DomainSID
```

* ADModule:
We can find the SID inside the `Get-ADDomain` output.

```powershell
(Get-ADDomain).DomainSID
Get-ADDomain | select DNSRoot,NetBIOSName,DomainSID
```

# Domain Policy

*  PowerView:
```powershell
Get-DomainPolicy
(Get-DomainPolicy)."system access"
(Get-DomainPolicy -Domain corp.local)."system access"
```
* PowerView (dev):
```powershell
Get-DomainPolicyData | select -ExpandProperty SystemAccess
```

# Domain Controllers

*  PowerView:
```powershell
Get-NetDomainController
Get-NetDomainController -Domain corp.local
```

* PowerView (dev):
```powershell
Get-DomainController
Get-DomainController -Domain corp.local
```

* ADModule:
```powershell
Get-ADDomainController
Get-ADDomainController -DomainName corp.local
```

# Users & their Properties / Attributes

*  PowerView:
```powershell
Get-NetUser
Get-NetUser -Domain corp.local
Get-NetUser -Username <user>
Get-NetUser -SPN
Get-UserProperty
Get-UserProperty -Properties pwdlastset
```

* PowerView (dev):
```powershell
Get-DomainUser
Get-DomainUser -Identity <user>
Get-DomainUser -Properties pwdlastset
```

* ADModule:
```powershell
Get-ADUser -Filter * -Properties *
Get-ADUser -Server corp.local -Filter * -Properties *
Get-ADUser -Identity <username> -Properties *
Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property | select Name
Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}
```

> **Note:** Some sysadmins paste the password on the description field.

> **Note:** Service accounts stores the password on the LSAS in clear text.

## Search a particular string in users's attributes

Valuable info can be found in user's attributes such as description.

*  PowerView:
```powershell
Find-UserField -SearchField Description -SearchTerm "built"
```

*  ADModule:
```powershell
Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | select name,Description
```

# Computers in the domain

*  PowerView:
```powershell
Get-NetComputer
Get-NetComputer -OperatingSystem "*Server 2016*"
Get-NetComputer -Ping
Get-NetComputer -FullData
```

* PowerView (dev):
```powershell
Get-DomainComputer
Get-DomainComputer -Properties DnsHostName
```

*  ADModule:
```powershell
Get-ADComputer -Filter * | select Name
Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' -Properties OperatingSystem | select Name,OperatingSystem
Get-ADComputer -Filter * -Properties DNSHostname | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}
Get-ADComputer -Filter * -Properties *
```

# Domain Groups

*  PowerView:
```powershell
Get-NetGroup
Get-NetGroup -Domain <targetdomain>
Get-NetGroup -FullData
```
> **Note**: It is also possible search for all groups containing a word:

```powershell
Get-NetGroup *admin*
```

* PowerView (dev):
```powershell
Get-DomainGroup
Get-Domain | where Name -like "*Admins*"
```

*  ADModule:
```powershell
Get-ADGroup -Filter * | select Name
Get-ADGroup -Filter * -Properties *
```

> **Note**: It is also possible search for all groups containing a word:

```powershell
Get-ADGroup -Filter 'Name -like "*admin*"' | select Name
```

## Find memberships

*  PowerView:
```powershell
Get-NetGroupMember -GroupName "Domain Admins" -Recurse
Get-NetGroup -UserName "username"
```

* PowerView (dev):
```powershell
Get-DomainGroupMember -Identity "Domain Admins"
```

*  ADModule:
```powershell
Get-ADGroupMember -Identity "Domain Admins" -Recursive
Get-ADPrincipalGroupMembership -Identity username
```

# Local Groups

To do that task needs administrator privs on non-dc machines.

*  PowerView:
```powershell
Get-NetLocalGroup -ComputerName dc01.corp.local -ListGroups
Get-NetLocalGroup -ComputerName filesrv1.corp.local -ListGroups
```

The following command shows the members of all the local groups on a machine.

```powershell
Get-NetLocalGroup -ComputerName filesrv1.corp.local -ListGroups -Recurse
```

# Logged Users (User has a session on)

Like local groups to do that task needs administrator privs on non-dc machines.


*  PowerView:

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

# Find important targets

## Shares

*  PowerView:
```powershell
Invoke-ShareFinder -Verbose
Invoke-ShareFinder -ExcludeStandard
```

* PowerView (dev):
```powershell
Find-DomainShare
Find-DomainShare -CheckShareAccess
```

## Sensitive Files

*  PowerView:
```powershell
Invoke-FileFinder -Verbose
```

* PowerView (dev):
```powershell
Find-InterestingDomainShareFile -Include *.doc*, *.xls*, *.csv, *.ppt*
```

## File servers

* PowerView:
```powershell
Get-NetFileServer
```

# Group Policy (GPO)

Group Policy provides the ability to manage configuration and changes easily and centrally in active directory.


*  PowerView:
```powershell
Get-NetGPO
Get-NetGPO -ComputerName machine01.corp.local
Get-NetGPO Group
```

* PowerView (dev):
```powershell
Get-DomainGPO
Get-DomainGPO -Properties DisplayName
```

*  ADModule:
```powershell
Get-GPO -All
Get-GPResultantSetOfPolicy -ReportType Html -Path c:\windows\temp\report.html
```
> **NOTE:** We can get more infomration with:
>
>`gpresult /R /V`

## Users on Localgroups

We can also get users which are in a local group of a machine using GPO.

* PowerView:
```powershell
Find-GPOComputerAdmin -Computer machine01.corp.local
```

* PowerView (dev):
```powershell
Get-DomainGPOLocalGroup | select GPODisplayName, GroupName
```

Or we can find machines where a user is member of a specific group.

* PowerView:
```powershell
Find-GPOLocation -UserName <user> -Verbose
```

* PowerView (dev):
```powershell
Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators | select objectName, GPODisplayName, ContainerName, ComputerName | fl
```

# Organization Unit (OU)

* PowerView:
```powershell
Get-NetOU -FullData
```
* PowerView (dev):
```powershell
Get-DomainOU
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

To know which computers are inside a OU:

* PowerView:
```powershell
Get-NetOU -OUName Students | %{Get-NetComputer -ADSPath $_}
```
* PowerView (dev):
```powershell
Get-DomainOU "Servers" | %{Get-DomainComputer -SearchBase $_.distinguishedname -properties name}
```

# Access Control List (ACL)

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
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
```

# Domain Trust Mapping

We can get a list of all domain trusts for a domain.

* PowerView:
```powershell
Get-NetDomainTrust
Get-NetDomainTrust -Domain es.lab.corp.local
```

* PowerView (dev):
```powershell
Get-DomainTrust
```

* ADModule:
```powershell
Get-ADTrust
Get-ADTrust -Identity es.lab.corp.local
```
* Other:
```
nltest /domain_trusts
```

# Forest Mapping

A Forest is like a tree of domains (domain and subdomains) and the name of the forest is the name as the root domain of the tree.

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

# User Hunting 

## Local Admin Check

Find all machines on the current domain where the current user has local admin access.

* PowerView:
```powershell
Find-LocalAdminAccess -Verbose
```

> **Note**: This function queries the domain controller for a list of computers `Get-NetComputer` and then use multi-threaded `Invoke-CheckLocalAdminAccess` on each machine.
> **MAKE A LOT OF NOISE**

In case `Find-PSRemotingLocalAdminAccess.ps1` is blocked you can use:

```powershell
Import-Module .\Find-WMILocalAdminAccess.ps1
Find-WMILocalAdminAccess -ComputerName machine01.corp.local
Find-WMILocalAdminAccess -ComputerFile .\computers.txt -Verbose
```
> **NOTE**: WMI needs ADMIN PRIV to work, so if we get an error is that the user has not enough privileges.

## Get Local Admins (Local Admin Priv. needed)

We can find local admins on all machines of the domain but we need administrator privileges on non-dc machines.

* PowerView:
```powershell
Invoke-EnumerateLocalAdmin -Verbose
```
> **Note**: This function queries the DC fo a list of computers `Get-NetComputer` an then use multi-threaded `Get-NetLocalGroup` on each machine.
>
> **MAKE A LOT OF NOISE**

## Sessions opened on a machine

Returns session information for a computer where `CName` is the source IP.

* PowerView Dev:
```powershell
Get-NetSession -ComputerName dc01.corp.local | select CName, UserName
```
## Machines where a User/Group has session

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
>
> **MAKE NOISE**

> **RedTeam Note**: To prevent of beeing detected by the Microsoft ATA (Advanced Thread Analytics) that analyzes the traffic of the DC, use a list of computers and remove the DC from it.
>
> `Get-NetComputer`
> `Invoke-UserHunter -ComputerFile hosts.txt`


> **BlueTeam Note**: 
> `Netcease.ps1` is a script which change permission on the NetSessionEnum by removing permission to Authenticated Users group. This Script should be executed on the DC.
> [https://github.com/p0w3rsh3ll/NetCease](https://github.com/p0w3rsh3ll/NetCease).
>
> To revert the effect:
> `.\Netcease.ps1 -Revert`
>
> After any modfification we need to restart the server:
> `Restart-Service -Name Server -Force`
>
> The binary net.exe uses SAMR protocol, exists another script which hardens a server.
> [https://vulners.com/n0where/N0WHERE:139229](https://vulners.com/n0where/N0WHERE:139229)

# SQLServers

We can provide a list of all SQL servers which have a SPN register on the domain controller.

* PowerUPSql
```powershell
Get-SQLInstanceDomain
```

> **Note**: This not mean that is a SQL Server running or listening, that means htat there are a MSSQL on a SPN.

# BloodHound

Provides GUI for AD entities and relationships for the data collected by its ingestors (SharpHound.ps1).

[https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

First we need to run ingestors on a machine in order to collect data.

```
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -Verbose
```

SharpHound has a number of different collection methods (all documented on the repository):


* **Default**: Performs group membership collection, domain trust collection, local group collection, session collection, ACL collection, object property collection, and SPN target collection
* **Group**: Performs group membership collection
* **LocalAdmin**: Performs local admin collection
* **RDP**: Performs Remote Desktop Users collection
* **DCOM**: Performs Distributed COM Users collection
* **PSRemote**: Performs Remote Management Users collection
* **GPOLocalGroup**: Performs local admin collection using Group Policy Objects
* **Session**: Performs session collection
* **ComputerOnly**: Performs local admin, RDP, DCOM and session collection
* **LoggedOn**: Performs privileged session collection (requires admin rights on target systems)
* **Trusts**: Performs domain trust enumeration
* **ACL**: Performs collection of ACLs
* **Container**: Performs collection of Containers
* **DcOnly**: Performs collection using LDAP only. Includes Group, Trusts, ACL, ObjectProps, Container, and GPOLocalGroup.
* **ObjectProps**: Performs Object Properties collection for properties such as LastLogon or PwdLastSet
* **All**: Performs all Collection Methods except GPOLocalGroup.



Sometimes BloodHound miss to check the sessions so we can execute it manually.

```
Invoke-BloodHound -CollectionMethod LoggedOn -Verbose
```

> **Note**: Remember that we can append the invoke command at the end of the file an executed it out of memory with `iex (iwr ...)`

> **RedTeam Note**: We can avoid detections like **ATA** with:
>
> `Invoke-BloodHound -CollectionMethod All -ExcludeDC`

After execution download the `.zip` file and drop to `BloodHound` in order to import it.

![BloodHound](/hackingnotes/images/bloodhound.png)

> **OPSEC Alert**: Running collections method such as `LocalAdmin`, `RDP`, `DCOM`, `PSRemote` and `LoggedOn` will allow SharpHound to enumerate every single computer in the domain.
>
> Collecting this information is useful to BloodHound and without it you may see fewer paths.

To use on LDAP queries we can use `DcOnly` collection method.

```
Invoke-BloodHound -CollectionMethod DcOnly
```

## Raw queries

Executing raw queries is useful for finding nodes that have particular properties or to help specific attack paths.

* Query all users that have `Service Principal Name (SPN)` set.

```
MATCH (u:User {hasspn:true}) RETURN u
```
* Query all users that have `Do not require Kerberos preauthenticaion` set.

```
MATCH (u:User {dontreqpreauth:true}) RETURN u
```
* Query all computers that are `AllowedToDelegate`.

```
MATCH (c:Computer), (t:Computer), p=((c)-[:AllowedToDelegate]->(t)) RETURN p
```

* Query all computers with `Unconstrained Delegation`.

```
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c
```

* Query all computers with `Constrained Delegation`.

```
MATCH (c:Computer), (t:Computer), p=((c)-[:AllowedToDelegate]->(t)) RETURN p
```

* Query all users with `Constrained Delegation`.

```
MATCH (u:User), (t:Computer), p=((u)-[:AllowedToDelegate]->(t)) RETURN p
```

* Query all Principals with GenericWrite over GPOs.

```
MATCH (gr:Group), (gp:GPO), p=((gr)-[:GenericWrite]->(gp)) RETURN p
```

* Query ACL for a specify group:

```
MATCH (g1:Group {name:"RDP USERS@CORP.LOCAL"}), (g2:Group), p=((g1)-[:GenericAll]->(g2)) RETURN p
```

* Query potential MS SQL Admins:

```
MATCH p=(u:User)-[:SQLAdmin]->(c:Computer) RETURN p
```