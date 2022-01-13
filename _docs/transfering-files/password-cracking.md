---
description: >-
  Cryptography is a method of protecting information and communications through
  the use of codes, so that only those for whom the information is intended can
  read and process it.
---

# Crypto 101 👁

## Hashing

### **Introduction**

A _hash_ is a function that converts one value to another. _Hashing_ data is a common practice in computer science and is used for several different purposes. Examples include cryptography, compression, checksum generation, and data indexing.

Hashing is a natural fit for cryptography because it masks the original data with another value. A hash function can be used to generate a value that can only be decoded by looking up the value from a hash table. The table may be an [array](https://techterms.com/definition/array), [database](https://techterms.com/definition/database), or other data structure. A good cryptographic hash function is non-invertible, meaning it **cannot be reverse engineered.**

### Password Cracking

In cryptanalysis and computer security, password cracking is the process of recovering passwords from data that has been stored in or transmitted by a computer system.

**Hashcat** is one of the most powerful password cracking tools at the moment. First we need to fount which type of hash we are trying to crack, this [guide](https://hashcat.net/wiki/doku.php?id=example\_hashes) contains all hash types that hashcat supports.

```
hashcat -a 0 -m mode passwd.hash wordlist
```

{% hint style="danger" %}
**Caution**: In order to avoid false positives or false negatives **never use --force** parameter.
{% endhint %}

Or you can use Google Colab to crack the hashes:

* [https://github.com/mxrch/penglab](https://github.com/mxrch/penglab)

Or other online free crackers:

* [https://crackstation.net/](https://crackstation.net)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html)
* [https://md5.gromweb.com/](https://md5.gromweb.com)

#### Rules

Typical password-enforcement rules are collected in some dictionaries, these types of rules generally require the use of upper and olwe-case characters, numbers and special characters.

```
hashcat -a 0 -m mode passwd.hash -r rules wordlist
```

{% hint style="info" %}
**Note**: Hashcat rules are located in `/usr/share/hashcat/rules/`
{% endhint %}

#### Selecting a correct Worlist

We can use common wordlists like `rockyou.txt` or some from SecLists, but also we can create a custom one.

`Cewl` gives us the opportunity to browse the website and manually add commonly-used termns and product names to our custom wordlists. Also we can select the minimum length of the passwords wit `-m` parameter.

```
cewl www.example.com -m 6 -2 wordlist.out
```

## Encryption

### Introduction

The two main categories of Encryption are symmetric and asymmetric.

**Symmetric encryption** uses the same key to encrypt and decrypt the data. Examples of Symmetric encryption are DES (Broken) and AES. These algorithms tend to be faster than asymmetric cryptography, and use smaller keys (128 or 256 bit keys are common for AES, DES keys are 56 bits long).

**Asymmetric encryption** uses a pair of keys, one to encrypt and the other in the pair to decrypt. Examples are RSA and Elliptic Curve Cryptography. Normally these keys are referred to as a public key and a private key. Data encrypted with the private key can be decrypted with the public key, and vice versa. Your private key needs to be kept private, hence the name. Asymmetric encryption tends to be slower and uses larger keys, for example RSA typically uses 2048 to 4096 bit keys.

### Cracking SSH private key

After getting the private ssh key protected with a passphrase, in order to obtain this passphrase we will need to convert that ssh key to john format, for that run ssh2john script:

```
python ssh2john id_rsa > id_rsa.hash
```

And crack it with your fav list:

```
john id_rsa.hash -wordlist=[wordlist]
```

### Cracking KDBX (KeePass Files)

First we need to convert our file to a hash.

```
python keepass2john file.kdbx > kdbx.hash
```

And crack it with your fav list:

```
john kdbx.hash -wordlist=[wordlist]
hashcat -a 0 -m 13400 kdbx.hash [wordlist]
```

### Decrypting openssl enc data with salted password

When we found some file like that:

```
❯ file file.enc
file.enc: openssl enc'd data with salted password
```

We can crack the password with `bruteforce-salted-openssl` specifying the digest and cipher (AES-256-CBC by default).

```
bruteforce-salted-openssl -t 50 -f rockyou.txt -d <digest> file.enc -1
```

Finally we need to decrypt the file with the key obtained while bruteforcing.

```
openssl aes-256-cbc -d -in file.enc -out file.txt -k <KEY>
```

## Ciphers Detection

There are many online tools that helps to detect which type of cipher is applied based on entropy.

* [https://www.boxentriq.com/code-breaking/cipher-identifier](https://www.boxentriq.com/code-breaking/cipher-identifier)

Also there are a lot of online tools to decode or encode with different ciphers:

* [https://www.dcode.fr/](https://www.dcode.fr)
* [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

{% hint style="info" %}
Note: quipqiup is a powerfull tool that solves simple subsitution ciphers.

[https://quipqiup.com/](https://quipqiup.com)
{% endhint %}

## References:

* [https://techterms.com/definition/hash](https://techterms.com/definition/hash)
* [https://www.abhizer.com/crack-ssh-with-john/](https://www.abhizer.com/crack-ssh-with-john/)
