---
title: Port Scanning
category: Enumeration
order: 4
---

The best option to identify Ports, Protocols, and Services (PPS) on a targetwould be to scan all ports (65535) of the remote system.

# TCP Scanning

## Nmap

* Simply Scan

```
nmap -p- --open T5 -v -n IP
nmap --top-ports 5000 --open -T5 -v -n IP
```

* Complex Scan

```
nmap -sV -A -p PORTS IP
```

## Masscan

Masscan is the fastest port scanner, it can scan the whole internet in 6 minutes.

```
sudo masscan -p[PORTS] [IP/MASK] --rate=1000 -e [IFACE] --router-ip [GATEWAY]
```

## Bash Port Scanner

This one is created by [@s4vitar](https://www.youtube.com/channel/UCNHWpNqiM8yOQcHXtsluD7Q):

```
#!/bin/bash
# Usage ./portScanner.sh IP

trap ctrl_c INT
function ctrl_c(){
  echo -e "\n\n[*] Exiting....\n"
  tput cnorm; exit 0
}
for port in $(seq 1 65535);do
  timeout 1 bash -c "echo '' < /dev/tcp/$1/$port" 2>/dev/null && echo "Port $port - OPEN" &
done; wait
tput cnorm
```

Another simple bash port scanner:

```
#!/bin/bash
for i in {1..65535}; do (< "/dev/tcp/$1
/$i") &>/dev/null && { echo; echo "[+] Open Port at: $i"; }  || printf ""; done; echo
```

# UDP Scanning

Pentesters often forgot to scan for open UDP ports, although UDP scanning can be unrealiable, there are plenty of attack vectors lurking behind open UDP ports.

```
sudo nmap -sU IP
```

>**Hint:** You can launch a syn scan and udp scan at same time: `sudo nmap -sS -sU IP`

