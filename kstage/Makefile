CC_X64	:= x86_64-w64-mingw32-gcc

CFLAGS	:= $(CFLAGS) -Os -fno-asynchronous-unwind-tables -nostdlib 
CFLAGS 	:= $(CFLAGS) -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS  := $(CFLAGS) -s -ffunction-sections -falign-jumps=1 -w
CFLAGS	:= $(CFLAGS) -falign-labels=1 -fPIC -Wl,-TSectionLink.ld
LFLAGS	:= $(LFLAGS) -Wl,-s,--no-seh,--enable-stdcall-fixup

OUTX64	:= kstage.x64.exe
BINX64	:= kstage.x64.bin

all:
	@ nasm -f win64 asm/x64/GetIp.asm -o GetIp.x64.o
	@ $(CC_X64) GetIp.x64.o *.c -o $(OUTX64) $(CFLAGS) $(LFLAGS) -Iinclude/ddk/
	@ python3 python3/extract.py -f $(OUTX64) -o $(BINX64)
	@ rm -rf $(OUTX64)

clean:
	@ rm -rf *.o
	@ rm -rf *.bin
	@ rm -rf *.exe
