---
description: >-
  In this section I will explain techniques to found the original IP of the
  hosted webapp.
---

# WAF Evasion

## SSL Certificates

First we need to look inside the SSL Certificate of the webapp in order to find the fingerprint \(SHA256\)

![Fingerprint of SSL Certifcate](../.gitbook/assets/cert_waf_bypass.png)

With [censys](https://censys.io/certificates) you can search different hosted webpages with the same SSL fingerprint, so these are from the same company.

* [https://censys.io/certificates](https://censys.io/certificates)

![Censys results.](../.gitbook/assets/censys_waf_bypass.png)

Once you obtained the different domains or IPs that have the same fingerprint try to discover the IPs and play with the `Host HTTP header.`

```text
curl -kv https://190.12.34.42/
```

It's common that the companies buys a range of IPs, so you should need to check more parent IPs.

```text
curl -kv https://190.12.34.40/
curl -kv https://190.12.34.41/
curl -kv https://190.12.34.43/
curl -kv https://190.12.34.44/
curl -kv https://190.12.34.45/
curl -kv https://190.12.34.46/
```



