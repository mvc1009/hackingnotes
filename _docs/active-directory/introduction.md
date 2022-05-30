---
title: Basics
category: Active Directory
order: 1
---

# What is Active Directory?

An **Active Directory (AD)** is a system that allows to manage a set of computers and users connected in the same network from a central server.

Active Directory allows this by maintaining a centralized database where all the information about users, computers, policies, permissions, etc, is stored. So, for example, the IT team can connect to this database and create the new users for the interns and assign permissions to them to be only allowed to read files in the indicated directories of the specific servers of their departments.

An Active Directory is installed on **Windows Servers**. Let's see their items.

> **Note**: Be careful with *Clock Skew*, Kerberos uses a synchronous process because use datetime to hash the tickets. Maybe you need to synchronize your date on your system with the DC.
>
> On Linux:
> `rdate -n <DC_IP>`

# Domain

We usually known an Active Directory as a **Domain**. A domain is a set of connected computers that shares an active directory database which is managed by the central servers called **Domain Controllers (DC)**.

Every domain has a DNS name, a NetBIOS name (usually the dns name without the last part), a SID (Security Identifier) and more...

```
PS C:\Users\Administrator> Get-ADDomain

AllowedDNSSuffixes                 : {}
ChildDomains                       : {}
ComputersContainer                 : CN=Computers,DC=corpme,DC=local
DeletedObjectsContainer            : CN=Deleted Objects,DC=corpme,DC=local
DistinguishedName                  : DC=corpme,DC=local
DNSRoot                            : corpme.local
DomainControllersContainer         : OU=Domain Controllers,DC=corpme,DC=local
DomainMode                         : Windows2016Domain
DomainSID                          : S-1-5-21-2476192797-718363329-2951282162
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=corpme,DC=local
Forest                             : corpme.local
InfrastructureMaster               : DC01.corpme.local
LastLogonReplicationInterval       :
LinkedGroupPolicyObjects           : {CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=corpme,DC=loca
                                     l}
LostAndFoundContainer              : CN=LostAndFound,DC=corpme,DC=local
ManagedBy                          :
Name                               : corpme
NetBIOSName                        : CORPME
ObjectClass                        : domainDNS
ObjectGUID                         : b113666c-e88e-47d5-be33-5a752d0d7c73
ParentDomain                       :
PDCEmulator                        : DC01.corpme.local
PublicKeyRequiredPasswordRolling   : True
QuotasContainer                    : CN=NTDS Quotas,DC=corpme,DC=local
ReadOnlyReplicaDirectoryServers    : {}
ReplicaDirectoryServers            : {DC01.corpme.local}
RIDMaster                          : DC01.corpme.local
SubordinateReferences              : {DC=ForestDnsZones,DC=corpme,DC=local, DC=DomainDnsZones,DC=corpme,DC=local,
                                     CN=Configuration,DC=corpme,DC=local}
SystemsContainer                   : CN=System,DC=corpme,DC=local
UsersContainer                     : CN=Users,DC=corpme,DC=local
```

# Forest

Active Directory offers many ways to organize your infraestructure. An organitzation can use domain and subdomains in order to organize the object via departmants, countries, etc...

```
PS C:\Users\Administrator> Get-ADForest

ApplicationPartitions : {DC=ForestDnsZones,DC=corpme,DC=local, DC=DomainDnsZones,DC=corpme,DC=local}
CrossForestReferences : {}
DomainNamingMaster    : DC01.corpme.local
Domains               : {corpme.local}
ForestMode            : Windows2016Forest
GlobalCatalogs        : {DC01.corpme.local}
Name                  : corpme.local
PartitionsContainer   : CN=Partitions,CN=Configuration,DC=corpme,DC=local
RootDomain            : corpme.local
SchemaMaster          : DC01.corpme.local
Sites                 : {Default-First-Site-Name}
SPNSuffixes           : {}
UPNSuffixes           : {}
```
In a forest each domain has its own database and its own domain controllers.

> **Note**: A user of a domain in the forest can also access to the other domains of the same forest.


## Functional Modes

As well as Windows computers, domains/forest can also have their own "version", that is called functional mode. Depending on the mode of the domain/forest, new characteristics can be used.

The modes are named based on the minimum Windows Server operative system required to work with them. There are the following functional modes:

* Windows2000
* Windows2000MixedDomains
* Windows2003
* Windows2008
* Windows2008R2
* Windows2012
* Windows2012R2
* Windows2016

```powershell
PS C:\Users\Administrator> (Get-ADForest).ForestMode
Windows2016Forest
```
Then if, for example, you find a domain/forest with `Windows2012` mode, you can know that all the Domain Controllers are at least Windows Server 2012. You must be aware of the mode in order to use some characteristics of the domain, for example, the Protected Users group requires a Windows2012R2 mode.

# Trusts

In an active directory environment, trust is a relationship between two domains or forests which allows users of one domain or forest to access resources in the other domain or forest.

Trust can be automatic for example parent-child, same forest, etc... or established manually.

Trusted Domain Objects (TDOs) the trust relationship in a domain.

## Directions of Trust

Exist diferent directions of Trust:

* **One-Way Trust**:

It is unidirectional. Users in the trusted domain can access resources in the trusting domain but not backwards.

** **Outgoing trust**: Allows users of the other domain access to your domain.

** **Incoming trust**: Allows users of your domain to access the other domain.

![One-Way-Trust](/hackingnotes/images/one-way-trust.png)

* **Two-Way Trust**:

It is bidirectional. Users of both domains can access resources in the other domain

![Two-Way-Trust](/hackingnotes/images/two-way-trust.png)

## Trust Transitivity

Exist different types of transitivity on a domain:

* **Transitive**:

Transitivie is a property of trust which means that the trust can be extended to etablish trust relationships with other domains.

All the default intra-forest trust relationships such as Tree-Root or Parent-Child between domains within a same forest are transitive Two-Way trusts.

![Trust Transitive](/hackingnotes/images/trust-transitive.png)

Means that Domain A trusts Domain B and Domain B trusts Domain C so Domain A also trusts Domain C in a Two-Way Trust direction.


* **Nontransitive**:

Nontransitive means that the trust can not be extended to other domains in the forest, we can find it on a two-way or one-way.

This is the default trust called external trust between two domains in different forests, when forests do not have a trust relationship.

## Type of Trusts

There are many types of trusts:

* **Parent-Child**:

It is created automatically between the new domain an the domain that precedes it (parent-child trust) in the namespace hierarchy, whenever a domain is added in a tree.

For example lab.corp.local is a child of corp.local. Always the trust is in a two-way transitive.


* **Tree-Root**:

It is created automatically between whenever a new domain tree is added to a forest root.

The trust is always two-way transitive.

![Domain Trusts](/hackingnotes/images/domain-trusts.png)

* **Shortcut**:

The shortcut trust is used to reduce access times in a complex trust scenarios. We can found it in a one-way or two-way transitive form.

![Shortcut Trusts](/hackingnotes/images/shortcut-trust.png)

* **External**:

An external trust gives the opportunity of trust between two domains in different forests which do not have any trust relationship. Can be one-way or two-way and is nontransitive.

![External Trusts](/hackingnotes/images/external-trust.png)

* **Realm**:

A special trust to connect Active Directory and a non-Windows domain.

* **Forest**:

A trust is a connection from a domain to another. Not a physical network connection, but a kind of authentication/authorization connection. You may be able to reach computers on the network that are in others domains, but you cannot log in on those computers with your user of this domain. That is what a trust allows you to do.

Forest trust is a trust between forest root domains. Cannot be extended to a third forest so has no implicit trust.

Can be one-way or two-way and transitive or nontransitive.

![Forest Trusts](/hackingnotes/images/forest-trust.png)

> **Note**: In case of nonsensitvie Forest 1 would not have any type of trust relationship with Forest 3.


## Trust Key

When you use a trust, there is a communication between the DC of your domain andd the DC of the target domain. How communication is made varies depending of the protocol that is being used but in any case, the DCs needs to share a key to keep the communications secure.

This key is known as the trust key and it's created when the trust is established.

When this trust is created, a trust account is created in the domain database. The trust key is stored as if it was the password of the trust user.

# Users




# References

* [https://zer1t0.gitlab.io/posts/attacking_ad/](https://zer1t0.gitlab.io/posts/attacking_ad/)