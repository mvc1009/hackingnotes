---
title: Hacking with Python
category: Other
order: 3
---

Useful notes of python in different environments.

# Install pip packages without internet

Sometimes we are on an assesment without internet connection and we need to install some python tools that requires differents packages.

We can download previously on our computer:

```
mkdir mitm6
pip download mitm6 -d "/folder/mitm6"
tar cvfz mitm6.tgz mitm6
```

Finally tranfer the `tgz` file to the target machine an install it with the following commands:

```
tar xvfz mitm6.tgz
cd mitm6
pip install mitm6-0.3.0-py3-none-any.whl -f ./ --no-index
```

You may need to add `--no-deps` to the command as follows:

```
pip install mitm6-0.3.0-py3-none-any.whl -f ./ --no-index --no-deps
```