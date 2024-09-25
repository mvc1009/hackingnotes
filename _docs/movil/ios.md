---
title: iOS
category: Movil
order: 1
---

Setup of the environment

# Jailbreaks

## Jailbreak iOS 14 with Checkra1n

Jailbreak is needed to make an audit of an iOS application. Checkra1n allows us to get our iphone jailbroke.

```
sudo checkra1n 
```

![Checkra1n](/hackingnotes/images/checkra1n_01.png)


In order to get support on iOS 14.2 we need to skip the A11 BPR checks.

![Skip A11 BPR checks](/hackingnotes/images/checkra1n_02.png)

Once properly configured we can jailbreak our iphone.

![Checkra1n](/hackingnotes/images/checkra1n_03.png)

## Jailbreak iOS 15 with Palera1n

Passcode should be deleted previously. You can download palera1n from the following link:

* [https://github.com/palera1n/palera1n/releases/tag/v2.0.0-beta.7](https://github.com/palera1n/palera1n/releases/tag/v2.0.0-beta.7)

Open a terminal and **keep the tab open**.
```
sudo systemctl stop usbmuxd
sudo usbmuxd -f -p
```

First step is to run palera1n without root permissions (rootless).

```
./palera1n-linux-x86_64 -l
```

Once on DFU mode open close the palera1n and execute palera1n another time with root permissions and follow the instructions.

```
sudo ./palera1n-linux-x86_64
```

> **Note**: If fails and the phone gets stucked on DFU or recovery mode execute the following command: `sudo ./palera1n --exit-recovery`

> **Note**: If wifi does not work afeter jailbreak, try to execute palera1n in safe mode: `sudo ./palera1n -s`


# Installing Burp certificate

Once the proxy has been configured on the device, open the browser and search for the url `http://burp`. Download the profile.

![Downloaded Profile](/hackingnotes/images/ios_burp.png)

Then go to settins and a new tabb will appear with the downloaded profiles.

![Downloaded Profile](/hackingnotes/images/ios_profile.png)

Install the profile.

![Install Profile](/hackingnotes/images/ios_install.png)

Finally, we just need to enable and trust with the certificate. Search on settings `trust certificates` and enable PortSwigger CA certificate.

![Burp Certificate](/hackingnotes/images/ios_certi.png)

# Setup openssh server

Root password should be changed before ssh usage. Execute the following commands to change the password from **NewTerm** software on the iOS device.

```
iPhone:~ mobile% sudo passwd root
[sudo] password for mobile: [enter password setup during Palera1n install]
Changing password for root.
Old Password: [alpine]
New Password: [alpine]
Retype New Password: [alpine]
```

# Installing packages

## on Sileo 

In order to make and audit some software is needed:

* **Filza File Manager**: File manager to install ipa files.
* **Openssh server**
* **Frida Server**: Hooking software. Repo -> `https://build.frida.re`.
* **Newterm**: Terminal
* **Shadow**: Jailbreak bypass. Repo -> `https://ios.jjolano.shadow`.
* **SSL Kill Switch 3**: SSL pinning bypass. Repo -> `https://repo.misty.moe/apt`.

## on Kali

* **Frida Client**:

It's important that the frida server (iphone) version match with frida client (pc).

Frida client installation:

```
pip3 install frida
pip3 install frida-tools
```

Useful commands:

```
frida-ls-devices	# list devices
frida-ps -Uia		# running processes
frida upload <local> <remote>
frida download <remote> <local>

frida-trace -U "app" -i "*log*"		# functions called

frida-ios-dump
```

* **Objection**:

Objection is an awesome tool that uses frida to hook functions and make bypasses such as ssl pinning or jailbreak detection.

```
pip3 install objection
```

Usage:

```
frida-ps -Uai
objection --gadget com.example.app explore
```


# IPA extractor

We can extract the IPA from an installed application from APP Store.

* [https://github.com/AloneMonkey/frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump)

Modify the code in order to put the IP and Port of the iOS ssh server.

```
DUMP_JS = os.path.join(script_dir, 'dump.js')

User = 'root'
Password = 'alpine'
Host = 'IP'
Port = 22
KeyFileName = None
```

```
python3 ./dump.py com.example.app
```

# Evasion techniques

## SSL Pinning

* **With Objection**:

Objection can be used with the default scripts.

```
objection --gadget com.example.app
com.example.app on (iPhone: 16.7.9) [usb] # ios sslpinning disable
```
* **With SSL Kill Switch 3**:

With the package SSL Kill Switch 3 we can bypass ssl pinning. It can be installed from any package manager.
Repo: `https://repo.misty.moe/apt`.

## Jailbreak Detection

* **With Shadow**:

With shadow some jailbreak detections can be bypassed.
Repo: `https://ios.jjolano.shadow`.


# Hooking 

## With Objection

Sometimes we can't bypass the defenses with default templates, so should find the method that make the check and hook it properly.

```
env
ios bundles list_bundles
ios bundles list_frameworks

ios keychain dump
ios info binary
ios nsurlcredentialstorage dump
ios nsuserdefaults get
ios cookie get

ios jailbreak disable
ios sslpinning disable

ios hooking list classes
ios hooking search classes <search>
ios hooking list class_methods <class_name>
ios hooking watch class <class_name>		# hook a class
ios hooking watch method "-[<class_name> <method_name>]" --dump-args --dump-return --dump-backtrace 		# hook single method
ios hooking set return_value "-[<class_name> <method_name>]" false 		# change boolean return
ios hooking generate simple <class_name> 		# generate a hooking template
```
## With frida

```
frida -l script.js -f com.example.app 		# basic hook
frida -U --no-pause -l script.js -f com.example.app 	# hook before starting the app
```

* **Python script**:

```
import frida, sys

jscode = open(sys.argv[0]).read()
process = frida.get_usb_device().attach('infosecadventures.fridademo')
script = process.create_script(jscode)
print('[ * ] Running Frida Demo application')
script.load()
sys.stdin.read()
```

# References:

* [https://medium.com/@shivayadav2820/unlocking-ios-a-comprehensive-guide-to-penetration-testing-on-apple-devices-2-5df8f4d72930](https://medium.com/@shivayadav2820/unlocking-ios-a-comprehensive-guide-to-penetration-testing-on-apple-devices-2-5df8f4d72930)
