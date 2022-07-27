# About

TITAN is a reflective loader intended to hide the traces of Cobalt Strike in memory. It is not intended to hide from analysts or from any defenders, but may succeed at doing so regardless. When using TITAN, if you export or use a DNS Beacon, the Beacon will instead use `DNS over HTTP(s)` protocol to communicate back to the Teamserver. I recommend only using this option for a low & slow backup communication.

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
