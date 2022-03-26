---
title: PORT 22/tcp - SSH
category: Services
order: 2
---

# Introduction

The SSH protocol works on the client/server-model. The SSH client always initiates the setup of the secure connection, and the SSH server listens for incoming connection requests (usually on TCP port 22 on the host system) and responds to them.

In the connection setup phase, the SSH server authenticates itself to the client by providing its public key. This allows the SSH client to verify that it is actually communicating with the correct SSH server (instead of an attacker that could be posing as the server).

After a successful authentication the server provides the client access to the host system. This access is governed with the user account permissions at the target host system.

# Donwload Files

To download files we can use `sftp` or `scp`:

* SFTP

Is like ftp:

```
sftp root@ip

> get file.txt
> get -r folder/
```

* SCP

```
scp root@ip:/tmp/file.txt file.txt
scp -r root@ip:/tmp/folder folder 
```