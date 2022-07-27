# About

TITAN is a reflective loader intended to hide the traces of Cobalt Strike in memory. It is not intended to hide from analysts or from any defenders, but may succeed at doing so regardless. When using TITAN, if you export or use a DNS Beacon, the Beacon will instead use `DNS over HTTP(s)` protocol to communicate back to the Teamserver. I recommend only using this option for a low & slow backup communication. If you want to ensure your initial access isnt deleted from memory at the start of an engagement, I recommend using this toolset to your advantage.

## Caveats

Unfortunately, the 'stock' artifact kit for Cobalt Strike ( the one that allows you to export EXE/DLL/SERVICES ) files do not support Titan, as the stock size is too small. I recommend you download the artifact kit and upgrade the size to hold the complete size, as the stock one will not work and cause crashes. 

You can only export a working `RAW` format or `Powershell` formats, as the EXE/DLL templates in Cobalt don't work unless you compile new ones with a larger size, or until I have the time to fix it myself.

You must set the `sleep_mask` setting in your profile to `FALSE` as the built-in hook currently obfuscates beacon, and will break the sleep masking feature. An example profile has been commited under [profile/Titan.cna](profile/Titan.cna)

Additionally, anything that uses Powershell or spawns a new thread in Beacon will be blocked, as I do not  yet have a way of tracking the secondary thread / obfuscating it. This is on my list of improvements to make.

## Setup

To start utilizing Titan, you will need to install `nasm`, `make`, `python3`, the [pefile module for python](https://github.com/erocarrera/pefile) and Mingw-w64. You will need the mingw-w64 compilers from musl.cc, which is available here for [x86_64-w64-mingw32-cross](https://musl.cc/x86_64-w64-mingw32-cross.tgz), and [i686-w64-mingw32-cross](https://musl.cc/i686-w64-mingw32-cross.tgz) to compile the code, as the ones available in your package managers is not updated to the latest versions. Once you've setup your compilers in the PATH, and installed the above packages, you can start compiling the source code!

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

## Shellter Example

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
