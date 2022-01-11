---
description: >-
  In computer networking, port forwarding or port mapping is an application of
  network address translation that redirects a communication request from one
  address and port number combination to another.
---

# Port Forwarding

## SSH Port Forwarding

Reverse SSH port forwarding specifies that the given port on the remote server host is to be forwarded to the given host and port on the local side.

![SSH Port Forwarding](../.gitbook/assets/ssh_portforwarding.png)

### SSH Local Port Forwarding

**-L** is a local tunnel \(YOU --&gt; CLIENT\). If a site was blocked, you can forward the traffic to a server you own and view it. For example, if _test_ was blocked at work, you can do **the next command.** Going to localhost:9000 on your machine, will load _test_ traffic using your other server.

```text
root@kali:~$ ssh -N -L 900:test.com:80 user@example.com
```

### **SSH Remote Port Forwarding**

**-R** is a remote tunnel \(YOU &lt;-- CLIENT\). You forward your traffic to the other server for others to view. Similar to the example above, but in reverse. Sometimes the ssh server is off and you need to ssh back to your attacking machine in order to forward a traffic port.

```text
user@target:~$ ssh -N -R example.com:80:test.com:80 user@example.com
```

### SSH Dynamic Port Forwarding

This is the coolest one because uses `SOCKS4 proxy` and redirects all traffic sent via proxy to the target machine, which would be similar like launching our scripts from the target machine.

First we need to configure `proxychains`.

```text
sudo echo "socks4    5566" >> /etc/proxychains.conf
```

Create the dynamic tunnel with the specified port.

```text
ssh -N -D 5566 user@example.com
```

After that all commands that begins with `proxychains` will be sent through the proxy.

```text
sudo proxychains nmap -sV -sC 10.10.10.10
```

## Chisel

Chisel is a fast TCP/UDP tunnel, transported over HTTP, secured via SSH. Single executable including both client and server. Written in Go \(golang\). Chisel is mainly useful for passing through firewalls, though it can also be used to provide a secure endpoint into your network. Available on Windows and Linux

* [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)

{% hint style="info" %}
**Note**: Download a Release
{% endhint %}

### Server

Start the _Chisel_ server on your **attacker machine** specifying the port to use.

```text
./chisel server -p PORT --reverse
```

### Client 

On the target machine, you need to start the _Chisel_ client, specify the server IP and port, and specify the ports to tunneling.

```text
./chisel client IP:PORT R:PORT_KALI:localhost:PORT_VICTIM R:PORT2_KALI:localhost:PORT2_VICTIM
```

## rinetd

`rinetd` is a port forwading tool easily configurable and instalable.

```text
sudo apt-get install rinetd
```

The `rinetd` configuration file is `/etc/rinetd.conf` that lists all forwarding rules.

```text
# bindadress  bindport  connectaddress  connectport  options...
# 0.0.0.0     80        192.168.1.2     80
# ::1         80        192.168.1.2     80
# 0.0.0.0     80        fe80::1         80
# 127.0.0.1   4000      127.0.0.1       3000
# 127.0.0.1   4000/udp  127.0.0.1       22           [timeout=1200]
# 127.0.0.1   8000/udp  192.168.1.2     8000/udp     [src=192.168.1.2,timeout=1200]
```

Remember restart the service:

```text
sudo service rinetd restart
```

## httptunnel \(hts\)

`hts` is a the `httptunnel` server which has an easily installation.

```text
sudo apt-get install httptunnel
```

The use is similar a `rinetd` but the configuration is established by parameters.

```text
hts --forward-port localhost:8888 example.com:1234
```



## PLINK.exe

[Plink ](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html)is a windows based command line port forwarding tool based on the PuTTY project. Same as SSH has local, remote and dynamic port forwarding.

```text
plink.exe -ssh -l <user> -pw <pass> -R <kali-ip>:80:127.0.0.1:80 <kali-ip>
plink.exe -ssh -l <user> -pw <pass> -L 127.0.0.1:80:test.com:80 test.com
plink.exe -ssh -l <user> -pw <pass> -D 5566 test.com
```

{% hint style="warning" %}
Warning: May be in a Reverse Shell the command doen't works so you need to pipe to:

 **cmd.exe /c echo y \| plink.exe -ssh .....**
{% endhint %}

## **NETSH**

`netsh` utility is installed by default on every modern version of Windows.

```text
netsh interface portproxy add v4tov4 listenport=4455 listenaddress=10.0.0.1 connectport=445 connectaddress=192.168.0.1
```

By default, Windows will block our connections with the Firewall, being administrator we can easily add a rule to let the traffic pass.

```text
netsh advfirewall firewall add rule name="forward_port_rule" protocol=TCP dir=in localip=10.0.0.1 localport=4455 action=allow
```





