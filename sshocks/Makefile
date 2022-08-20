CC_X86	:= i686-w64-mingw32-gcc
CC_X64	:= x86_64-w64-mingw32-gcc
CFLAGS	:= -Os -s -Qn -Iinclude -shared -I.
LFLAGS	:= -lbcrypt -lws2_32 -lcrypt32
OUTX86	:= sshocks.x86.dll
OUTX64	:= sshocks.x64.dll

all:
	$(CC_X86) *.c fmt/DllMain.c lib/x86/libssh2.a lib/x86/libz.a -o $(OUTX86) $(CFLAGS) $(LFLAGS) -Wl,--enable-stdcall-fixup
	$(CC_X64) *.c fmt/DllMain.c lib/x64/libssh2.a lib/x64/libz.a -o $(OUTX64) $(CFLAGS) $(LFLAGS) -Wl,--enable-stdcall-fixup

test:
	$(CC_X86) *.c fmt/ExeMain.c lib/x86/libssh2.a lib/x86/libz.a -o test.x86.exe -Os -s -Qn -Iinclude -I. $(LFLAGS) -Wl,--enable-stdcall-fixup
	$(CC_X64) *.c fmt/ExeMain.c lib/x64/libssh2.a lib/x64/libz.a -o test.x64.exe -Os -s -Qn -Iinclude -I. $(LFLAGS) -Wl,--enable-stdcall-fixup

clean:
	rm -rf *.dll
	rm -rf *.exe
