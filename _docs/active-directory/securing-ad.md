---
title: Securing Active Directory
category: Active Directory
order: 98
---

In this section some detection, defense tools and security advisors are going to be discussed. It is recommended to protect and limit domain admins:

* Reduce the number of Domain Admins.
* Do not allow or limit the login of DAs to any other machine rather than the Domain Controllers.
* Try to never run a service with a Domain Admin.
* Set `Account is sensitive and cannot be delegated` for Domain Admins.

# Windows Defender

Microsoft Defender Antivirus is available in Windows 10 and Windows 11, and in versions of Windows Server.

Microsoft Defender Antivirus is a major component of your next-generation protection in Microsoft Defender for Endpoint. This protection brings together machine learning, big-data analysis, in-depth threat resistance research, and the Microsoft cloud infrastructure to protect devices (or endpoints) in your organization. Microsoft Defender Antivirus is built into Windows, and it works with Microsoft Defender for Endpoint to provide protection on your device and in the cloud.

It has three different types of modes:

* **Active mode**: In active mode, Microsoft Defender Antivirus is used as the primary antivirus app on the device. Files are scanned, threats are remediated, and detected threats are listed in your organization's security reports and in your Windows Security app.

* **Passive mode**: In passive mode, Microsoft Defender Antivirus is not used as the primary antivirus app on the device. Files are scanned, and detected threats are reported, but threats are not remediated by Microsoft Defender Antivirus. **IMPORTANT**: Microsoft Defender Antivirus can run in passive mode only on endpoints that are onboarded to Microsoft Defender for Endpoint. 

* **Disabled or uninstalled**: When disabled or uninstalled, Microsoft Defender Antivirus is not used. Files are not scanned, and threats are not remediated. In general, we do not recommend disabling or uninstalling Microsoft Defender Antivirus.


More info in:

* [https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-antivirus-windows?view=o365-worldwide](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-antivirus-windows?view=o365-worldwide)

# LSA Protection

In Windows 8.1 and later microsoft has provided addition protection for the LSA to prevent untrusted processess from being able to read its memory or inject code. This will prevent `mimikatz` `sekurlsa::logonpasswords` for working properly.

To activate this protection set to 1 the value of `RunAsPPL`:

```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL

reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL /t REG_DWORD /d `
```
This LSA protection can be bypass using mimikatz `mimidrv.sys` driver:

```
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
```

# Disable WDigest

_Windows Digest (WDigest)_ is a authentication protocol introduced in Windows XP and was designed to be used with HTTP protocol which means that **plain-text passwords** are stored in the LSASS.

```powershell
Invoke-Mimikatz -Command '"sekurlsa::wdigest"'
```

This behaviour can be disabled via registry setting to 1 the value of `UseLogonCredential` and `Negotiate`

```
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential

reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v Negotiate /t REG_DWORD /d 1
```

> **Note**: Microsoft has this protocol **enabled by default** in Windows XP, Windows 8.0, Windows Server 2003 and Windows Server 2012.

# LAPS

LAPS (Local Administrator Password Solution) is a centralized storage of passwords for local administrator in active directory with a periodic randomizing where read permissions are access controlled. Computer objects where LAPS is activated has two new attributes:

* `ms-mcs-AdmPwd` attribute stores the clear text pasword.

* `ms-mcs-AdmPwdExpitarionTime` controls the password change.

Although the password is stored in clear text, te transmission is encrypted. With careful enumeration, it is possible to retrieve which users can access the clear text password providing a list of attractive targets.

More info in:

* [https://docs.microsoft.com/es-es/defender-for-identity/cas-isp-laps](https://docs.microsoft.com/es-es/defender-for-identity/cas-isp-laps)

# Credential Guard

_Credential Guard_ or _Windows Defender Credential Guard_ is a new feature in Windows 10 Entreprise and Education edition and Windows Server 2016 that helps to protect your credentials on a machine from threats such as PassTheHash or Over-PassTheHash by restricting access to NTLM hashes and TGTs.

It uses virtualization based security to isolate secrets so that only privileges system software can access them. Credential Guard must be turned on and deployed in your organization as it is **not enabled by default**.

Since it is activated it is no posible to access the secrets in LSASS.

> **Note**: During the PassTheHash technique we write on LSASS.

To check if Credential Guard is enabled check the following registry:

```
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Credential Guard could be enabled in different ways:

| Value |            Mode           |
|:-----:|:-------------------------:|
|   0   |          Disabled         |
|   1   |   Enabled with UEFI lock  |
|   2   | Enabled without UEFI lock |


Credentials for local accounts in `SAM` and `Service Account Credentials` from LSA Secrets are not protected. 


> **BlueTeam Note**: Credential Guard cannot be enabled on a DC because it breaks the authentication.

More info in:

* [https://docs.microsoft.com/es-es/windows/security/identity-protection/credential-guard/credential-guard-manage](https://docs.microsoft.com/es-es/windows/security/identity-protection/credential-guard/credential-guard-manage)

# Device Guard

_Device Guard_ or _Windows Defender Device Guard_ is a group of features designed to harden a system agains malware attacks. Its focus in preventing malicious code from running by ensuring only known good code can run.

Has three main components:

* **Configurable Code Integrity (CCI)**: Configure only trusted code to run.
* **Virtual Secure Mode Protected Code Integrity**: Enforces CCI with _Kernel Mode (KMCI)_ and _User Mode (UMCI)_.
* **Platform and UEFI Secure Boot**: Ensures boot binaries and firmware integrity.

UMCI is something which interferes with most of the lateral movement attacks we have seen. While it depends on the deployment, many well known applications are whitelisted such as `csc.exe`, `msbuild.exe`, etc...

More info in:

* [https://docs.microsoft.com/es-es/windows/security/threat-protection/device-guard/requirements-and-deployment-planning-guidelines-for-virtualization-based-protection-of-code-integrity](https://docs.microsoft.com/es-es/windows/security/threat-protection/device-guard/requirements-and-deployment-planning-guidelines-for-virtualization-based-protection-of-code-integrity)


# Protected Users Group

_Protected Users_ is a gorup introcued in Server 2012 R2 for better protection against credential theft. Credentials of all members of the the protected users group are not cached in a insecure way. A user added to this group:

* Members cannot use `CredSSP` or `WDigest` for authentication so no more cleartext credentials caching.
* The NTLM hash will not cache the user's plain text credentials or NT one-way function (NTOWF).
* Kerberos does not use DES or RCE4 keys. No caching of clear text credentials or long term keys after the initial TGT is acquired.
* A cached verifier is not created at sig-in or unlock, so offline sign-in is no longer supported.

If the domain functional level is Server 2012 R2:

* No NTLM authentication.
* No DES or RC4 keys in Kerberos pre-auth.
* No delegation (constrained or unconstrained).
* No renewal of TGT beyond initial for hour lifetime. Hardcoded, unconfigurable _Maximum lifetime for use ticket_ and _Maximum lifetime for user ticket renewal_.

Protected accounts and groups in active directory by operating system:

|        **User/Group**        | **Windows Server 2003 RTM** | **Windows Server 2003 SP1+** | **Windows Server 2012, Windows Server 2008 R2, Windows Server 2008** | **Windows Server 2016** |
|:----------------------------:|:---------------------------:|:----------------------------:|:--------------------------------------------------------------------:|:-----------------------:|
|       Account Operators      |              ✓              |               ✓              |                                   ✓                                  |            ✓            |
|         Administrator        |              ✓              |               ✓              |                                   ✓                                  |            ✓            |
|        Administrators        |              ✓              |               ✓              |                                   ✓                                  |            ✓            |
|       Backup Operators       |              ✓              |               ✓              |                                   ✓                                  |            ✓            |
|        Cert Publishers       |              ✓              |               ×              |                                   ×                                  |            ×            |
|         Domain Admins        |              ✓              |               ✓              |                                   ✓                                  |            ✓            |
|      Domain Controllers      |              ✓              |               ✓              |                                   ✓                                  |            ✓            |
|       Enterprise Admins      |              ✓              |               ✓              |                                   ✓                                  |            ✓            |
|            Krbtgt            |              ✓              |               ✓              |                                   ✓                                  |            ✓            |
|        Print Operators       |              ✓              |               ✓              |                                   ✓                                  |            ✓            |
| Read-only Domain Controllers |              ×              |               ×              |                                   ✓                                  |            ✓            |
|          Replicator          |              ✓              |               ✓              |                                   ✓                                  |            ✓            |
|         Schema Admins        |              ✓              |               ✓              |                                   ✓                                  |            ✓            |
|       Server Operators       |              ✓              |               ✓              |                                   ✓                                  |            ✓            |

* **BlueTeam Note**: _Microsoft_ do **not recommend** to add `Domain Admins` or `Enterprise Admins` to this group without testing the potential impact of lock out.

More info in:

* [https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)


# Use of Privileged Administrative Workstations (PAWs)

If the user of the IT department which is a Domain Admin is compromised, in that case there is a risk for the infraestructure and the active directory. For that reason the administrator needs to have aparate hardened workstation to permorm sensitive tasks like administration of domain controllers, cloud infraestructure, sensistive business functions etc...

This can provide protection from phishing attacks, OS vulnerabilities, credential replay attacks, etc...

Admin jump servers should be configured to be accessed only from a PAW. We can apply different strategies:

* Separate privilege and hardware for administrative and normal tasks.
* Having a VM on a PAW for user tasks.

# AD Administrative Tier Model

The _Active Directory Administrative Tier Model_ is composed of three levels only for administrative accounts:

* **Tier 1**: Accoutns, groups and computers which have privileges across athe enterprise like domain controllers, domain admins, entreprise admins.
* **Tier 2**: Accounts, groups and computers which have access to resources having significant amount of business value. A common example role is server administrators who maintain these operating systems with the ability to impact all enterprise servers.
* **Tier 3**: Administrator accounts which have administrative control of a significant amount of business value that is hosted on user workstations and devices. Examples include Help Desk and computer support administrators because can impact the integrity of almost any user data.

## Control Restrictions

Control restrictions is what admins can control.

![](/hackingnotes/images/tier_model_control.png)

## Logon Restrictions

Logon restrictions is where admins can logon.

![](/hackingnotes/images/tier_model_login.png)


# Enhanced Security Admin Environment (ESAE)

Enhanced Security Admin Environment (ESAE) is a dedicated administrative fores for managing critical assets like administrative users, groups and computers. Since a forest is considered a security boundary rather than a domain, this model provides enhanced security controls.

The amdinistrative forest is also called the **Red Forest**. Administrative users in a production forest are used as standard non-privileged users in the administrative forest.

Selective authentication to the Red Forest enables stricter security controls and logon of users from non-administrative forests.