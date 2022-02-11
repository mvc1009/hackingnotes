---
title: Hacking with PowerShell
category: Other
order: 2
---

Basic explanation about what is Powershell and how we can use it in out hacking days.

# What is Powershell?

Powershell is the Windows Scripting Language and shell environment that is built using the **.NET Framework.**

Most Powershell commands, called cmdlets, are written in .NET. Unlike other scripting languages and shell environments, the output of these cmdlets are objects, making Powershell somewhat object oriented.

> **Note**: The normal format of cmdlet is represented using **Verb-Noun.** Ex: **Get-Command**

Common verbs used are the[ following ones:](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7)

* Get
* Start
* Stop
* Read
* Write
* New
* Out

# Using Get-Help

`Get-Help` displays information about a cmdlet. To get help about a particular command, run the following:

```
Get-Help cmdlet
Get-Help cmdlet -Full
Get-Help cmdlet -Examples
```

> **Note**: To show some examples execute **Get-Help cmdlet -Examples**

# **Using Get-Command**

`Get-Command` gets all the cmdlets installed on the current Computer.

Running `Get-Command Verb-*` or `Get-Command *-Noun` filters the search.

# Object Manipulation

If we want to actually maniputare the output, we need to figure out a few things:

* Passing output to other cmdlets.
* Using specific object cmdlets to extract information.

To pas the output to another cmdlet like bash scripting is with the Pipeline "\|".

```
Verb-Noun | Get-Member -MemberType Equals
```

# Creating Objects From Previous cmdlets

One way of manipulating objects is pulling out the properties from the output of a cmdlet and creating a new object. This is done using the `Select-Object` cmdlet.

```
Get-ChildItem | Select-Object -Property Mode, Name
```

# Filtering Objects

When retrieving output objects, you may want to select objects that match a very specific value. You can do that using the `Where-Object`.

```
Verb-Noun | Where-Object -Property PropertyName -operator Value
Verb-Noun | Where-Object {$_.PropertyName -operator Value}
```

This are the[ following operators](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/where-object?view=powershell-6):

* **-contains**: Exact match for the specified value.
* **-eq:** Equals to.
* **-gt:** Greater than.

# Sort Objects

May you need to sort the output of a cmdlet in order to extract the information more efficiently. You can do this with `Sort-Object` cmdlet.

```
Verb-Noun | Sort-Object
```

# Importing modules

It is also posible to import our self modules.

```
Import-Module <modulepath>.ps1
. ./<modulepath>.ps1
```

Onced imported we can list all commands that we previously imported.

```
Get-Command -Module <modulename>
```