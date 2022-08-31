# About 

Titan is a User Defined Reflective DLL ( URDLL ) that uses a combination of techniques to achieve initial execution and maintain shell stability for Cobalt Strike in a modern endpoint-deteciton and response heavy environment. Titan was designed to operate against CrowdStrike, SentinelOne, and Cylance environments without being flagged as malware, when combined with unique initial access options. 

Titan is designed to work specifically with Cobalt Strike and with Cobalt Strike alone. It could be ported to other frameworks, but likely is pointless in doing so.

## Table of Contents

 - [Techniques](#Techniques)
     - [Memory Evasion](#Memory-Evasion-Obfuscate-and-Sleep)
     - [DNS over HTTP(s)](#DNS-Now-with-DNS-over-HTTPs)
     - [Injection](#Injection-Return-Oriented-Write)
     - [Single Threaded](#Single-Thread)
     - [System Calls!](#Redirect-To-System-Calls)
 - [Setup](#Setup)
 - [Initial Access Sample](#Initial-Access-Example-With-Shelter)

## Techniques

### Memory Evasion: Obfuscate and Sleep

Titan implements a basic x86_64 memory evasion hook that hides the traces of its implant in memory with the help user-created timer callbacks, a technique popularized by NightHawk and implemented publicly by the user [Paul](https://twitter.com/c5pider) whom published the project under the name [Ekko](https://github.com/Cracked5pider/Ekko). However, both implementation have a few caveats and race conditions that lead to it being unstable.

The latest version supports multiple sessions being spawned within the same process due to the creation of a new thread pool for each Beacon. It no longer breaks the host process's original queue if it is using one.

It currently encryptes when Beacon waits for jobs to complete, while it is sleeping, and while SMB pipes are awaiting a connection, writing to a pipe, or reading from a named pipe to avoid detection when transfering data over the network.

| Beacon                | Obfuscated In Memory |
|-----------------------|----------------------|
| windows/reverse_https | TRUE                 |
| windows/reverse_dns   | TRUE                 |
| windows/smb           | TRUE                 |
| windows/tcp           | FALSE                |

### DNS: Now with DNS over HTTP(s)!

DNS beacons recieved a completed overhall that allowed them to send their traffic over a more secure DNS over HTTP(s) provider that is hardcoded within the hook code itself. Each and every request will be seen sent to those providers, masking the original DNS name with ease. If you wish that your traffic be sent over the original DNS protocol, then you can disable this hook.

### Injection: Return Oriented Write
 
Titan adds a new way to achieve write, replacing WriteProcessMemory and slowing down the writes, leading to less chances of being detected due to the timing of events. It supports migration from the following architectures.

| Architecture | x64 -> x64 | x64 -> x86 | x86 -> x64 | x86 -> x86 |
|--------------|------------|------------|------------|------------|
| x64          | TRUE       | FALSE      | FALSE      | FALSE      |
| x86          | FALSE      | FALSE      | TRUE       | TRUE       |

**THIS FEATURE IS STILL NOT IMPLEMENTED BUT WILL BE IN THE NEAR FUTURE**

### Single Thread

Cobalt is largely single threaded on its own, but Titan forces it to be entirely single threaded. Unfortunately, this breaks some of the internal functionality such as Powershell-based commands 
at the cost of operational security. Largely, this should not break a majority of the functionality you're using, but will break some.

### Redirect To System Calls

Some functions that involve remote process interaction are redirected to System Calls using a mapping of KnownDLLs for x86/x64/WOW64. It avoids some detections that SentinelOne/CrowdStrike implement with their inline hooks.

## Setup

To start utilizing Titan, you will need to install `nasm`, `make`, `python3`, the [pefile module for python](https://github.com/erocarrera/pefile) and Mingw-w64. You will need the mingw-w64 compilers from musl.cc, which is available here for [x86_64-w64-mingw32-cross](https://musl.cc/x86_64-w64-mingw32-cross.tgz), and [i686-w64-mingw32-cross](https://musl.cc/i686-w64-mingw32-cross.tgz) to compile the code, as the ones available in your package managers is not updated to the latest versions. Once you've setup your compilers in the PATH, and installed the above packages, you can start compiling the source code!

Example steps to download the cross-compilers and add them to your PATH:

```
# cd /root/tools
# wget https://musl.cc/x86_64-w64-mingw32-cross.tgz
# tar -xvf x86_64-w64-mingw32-cross.tgz
# cd x86_64-w64-mingw32-cross/bin
# export PATH=$(pwd):$PATH
# cd /root/tools
# wget https://musl.cc/i686-w64-mingw32-cross.tgz
# tar -xvzf i686-w64-mingw32-cross.tgz
# cd i686-w64-mingw32-cross/bin
# export PATH=$(pwd):$PATH
```

A sample output is shown below

 ```shell=/bin/bash
devvm:~/projects/kit/titan $ make
/root/tools/i686-w64-mingw32-cross/bin/../lib/gcc/i686-w64-mingw32/11.2.1/../../../../i686-w64-mingw32/bin/ld: Titan.x86.exe:.text: section below image base
/root/tools/i686-w64-mingw32-cross/bin/../lib/gcc/i686-w64-mingw32/11.2.1/../../../../i686-w64-mingw32/bin/ld: Titan.x86.exe:.edata: section below image base
/root/tools/x86_64-w64-mingw32-cross/bin/../lib/gcc/x86_64-w64-mingw32/11.2.1/../../../../x86_64-w64-mingw32/bin/ld: Titan.x64.exe:.text: section below image base
/root/tools/x86_64-w64-mingw32-cross/bin/../lib/gcc/x86_64-w64-mingw32/11.2.1/../../../../x86_64-w64-mingw32/bin/ld: Titan.x64.exe:.edata: section below image base
```

Success! You've successfully compiled the binary files needed to utilize it. To begin using it, include the `Titan.cna` into your Aggressor Scripts `Cobalt Strike > Script Manager`. Once you've imported the aggressor script into Cobalt, you can begin exporting an `raw` artifact to use with Shelter or embedding into your own artifact kit!

![](https://i.imgur.com/sI5Quif.png)

## Initial Access Example With Shelter

An example scenario is laid out below: you have some kind of access to the target machine, where you can run arbitrary executables, or download arbitrary files to run. With physical access to the target machine, we can begin attempting to gain physical access through a combination of TITAN and SHELTER.

Fortunately, both tools make it relatively simple. Once you've compiled Titan and setup the aggressor script import correctly, its time to export an artifact! Assuming you have staging disabled in your environment, we need to export a stageless Beacon to inject with shelter. Keep in mind, here at GuidePoint Security we have access to the latest version of Shelter, which supports x86/x64 targets.

Pick a target executable to infect. I recommend if you can to survey to the target to locate any files that may be commonly run within the environment, and copy the executable if possible. Otherwise, an arbitrary installer for a common software ( maybe an Endpoint Detection and Response software! ) could be utilized to blend in more easily.

In my particular case, I'm going with a Portable Apps Installer targeting x86, which while I do not see often in environments, is perfect for targeting the common victim, although most likely won't be suitable in a corporate environment :)

Shelter's a pretty fun program to mess with. It gives the user the ability to infect arbitrary executables to run arbitrary malicous code, with full ability to regain control if needed to 
avoid detection. Use `ShelterPro64` or `ShellterPro` respective of your target architecture and shellcode you'll be leveraging.

First and foremost I recommend going with 'Auto' mode unless you are familiar with its options. Spend some time learning about the toolset, its quiete powerful depending on how you utilize it. Next, set your arbitrary executable you will be infecting. I've stored the file within my documents folder as the name I downloaded it as: `PortableApps.comInstaller_3.7.2.paf.exe`. Your output should look something similiar like the following:

![](https://i.imgur.com/LOJyrdX.png)

Next, disable 'Stealth Mode' within the list of options. To explain, 'Stealth Mode' will, after the payload has finished execution, run the original executable as if nothing was changed. For this demo, its not needed, and for initial droppers, it likely will not matter, however, if you plan on targeting and arbitrary executable for persistence purposes, I do recommend leveraging stealth mode as we would not want to alert the target user. 

Furthermore, an EFD ( Execution File Data ) file is not needed. We have not traced this program before, so we can start tracing now. Disable this option and let it run for some period to obtain a place to achieve execution within. 

Once this has completed, you will be able to choose an arbitrary payload. Select 'custom' as we will be providing our Beacon shellcode to inject into. Pass the path to your target shellcode, and disable it as a 'Reflective Loader'. We do not need to inject another arbitrary payload after that. Please choose your number of encoding instructions, and skip embedding an arbitrary certificate, as it is no longer needed.

![](https://i.imgur.com/HrsgCpp.png)

Excellent! You should now have a useable payload that can be used for initial access dropper for physical or remote operations.
