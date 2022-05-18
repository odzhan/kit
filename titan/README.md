## About

TITAN is a generic Reflective Loader for Cobalt Strike which attempts to improve the operational security of the implant to ensure stability on endpoint protected hosts. It implements a complete memory obfuscation solution for various IoC's ( Indicator of Compromise's ), and improves internal functionality to avoid detection. 

However, as a result of these tweaks, Beacon is forced to be single threaded. It breaks functionality such as `powershell-import` in favor of more "secure" functionality. In the future, TITAN may support some of this functionality at the cost of Operational Security, but at this time, I have to make informed decisions to ensure we do not lose our footholds.

## Tweaks

TITAN tweaks the internal behavior to:
* Sets the entire memory region to PAGE_READWRITE, and obfuscate using ARC4 when executing some system calls on x86/x64/WOW64, in addition towards hiding the stack of the original primary thread.
* Redirect DNS Beacon in favor of a more "secure" DNS over HTTP(s) ( DoH ).
* Redirect internal injection functions over system calls.
* Disable extra threads from being spawned within Beacon's address space so that it remains single threaded.
