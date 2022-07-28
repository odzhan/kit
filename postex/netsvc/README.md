# About

netsvc is a Beacon Object File for escalating from the Network Service account to SYSTEM. The bug lies in the way logon sessions are seperated on Windows, as described by the bugs creator. James Forshaw.

## Build 

To build the 'Beacon Object File' you will need mingw-w64 from musl.cc. Once you've installed the compilers within your PATH for x86_64 and i686, run make, which will build the BOF file to be used with Cobalt Strike.

Once you've build the corresponding NETSVC BOF for their respective architectures, simply import the NetSvc.cna script into your Aggressor script console. You're ready to start using it!

## Usage

If you're user is running as 'Network Service', you just run `elevate netsvc` which will escalate your user to SYSTEM.
