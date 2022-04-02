# About

Rogue is minimal access Beacon ( around 20K bytes as of this writing ) that provides access to the machine over a unique protocol named ICMP, prodiminanelty used by "PING" utilities on the host machines. It is not designed to replace other toolsets such as Cobalt Strike, but will act as a minimal persistence and initial access option in substitution with a unique transport.

## Build

To get started with Rogue, you will first have to compile it. It requires that the host it is being compiled on have the latest versions of mingw-w64, nasm, python and the python-pefile module, in addition to make. For mingw-w64, I use the [x86_64-w64-mingw32-gcc](https://musl.cc/x86_64-linux-musl-cross.tgz) and [i686-w64-mingw32-gcc](https://musl.cc/i686-w64-mingw32-cross.tgz) cross compilers to build the C code stored within this repository.

For rogue to connect back to your instance, you will need to change some parameters. Change `ICMP_LISTENER_ADDRESS` in Static.h to the IPv4 address of your Navi listener. For now, the
rest of the options are not customizable.

Once you have the above packages and mingw-w64 compilers installed, execute `make` from within the source directory. An example output would look something similair to the following listed below:



```shell

$ make
/root/tools/mingw/i686-w64-mingw32-cross/bin/../lib/gcc/i686-w64-mingw32/11.2.1/../../../../i686-w64-mingw32/bin/ld: rogue.x86.exe:.text: section below image base
/root/tools/mingw/i686-w64-mingw32-cross/bin/../lib/gcc/i686-w64-mingw32/11.2.1/../../../../i686-w64-mingw32/bin/ld: rogue.x86.exe:.edata: section below image base
/root/tools/mingw/x86_64-w64-mingw32-cross/bin/../lib/gcc/x86_64-w64-mingw32/11.2.1/../../../../x86_64-w64-mingw32/bin/ld: rogue.x64.exe:.text: section below image base
/root/tools/mingw/x86_64-w64-mingw32-cross/bin/../lib/gcc/x86_64-w64-mingw32/11.2.1/../../../../x86_64-w64-mingw32/bin/ld: rogue.x64.exe:.edata: section below image base

```

## Server

Rogue comes with a third-party server nicknamed `Navi` and `Midna`. Install the depencies from the requirements.txt in their respective project directories. Once that is done, it is as simple as just running:



```shell=/bin/bash

$ ./builddb.sh

INFO  [alembic.runtime.migration] Context impl SQLiteImpl.
INFO  [alembic.runtime.migration] Will assume non-transactional DDL.
INFO  [alembic.autogenerate.compare] Detected added table 'software'
INFO  [alembic.autogenerate.compare] Detected added index 'ix_software_description' on '['description']'
INFO  [alembic.autogenerate.compare] Detected added index 'ix_software_id' on '['id']'
INFO  [alembic.autogenerate.compare] Detected added index 'ix_software_name' on '['name']'
INFO  [alembic.autogenerate.compare] Detected added table 'user'
INFO  [alembic.autogenerate.compare] Detected added index 'ix_user_email' on '['email']'
INFO  [alembic.autogenerate.compare] Detected added index 'ix_user_id' on '['id']'
INFO  [alembic.autogenerate.compare] Detected added table 'target'
INFO  [alembic.autogenerate.compare] Detected added index 'ix_target_id' on '['id']'
INFO  [alembic.autogenerate.compare] Detected added table 'task'
INFO  [alembic.autogenerate.compare] Detected added index 'ix_task_id' on '['id']'
  Generating /root/projects/kit/rogue/server/midnav2/alembic/versions/4d6cf5a53efc_initial.py ...  done
INFO:__main__:Initializing service
INFO:__main__:Starting call to '__main__.init', this is the 1st time calling it.
INFO:__main__:Service finished initializing
INFO  [alembic.runtime.migration] Context impl SQLiteImpl.
INFO  [alembic.runtime.migration] Will assume non-transactional DDL.
INFO  [alembic.runtime.migration] Running upgrade  -> 4d6cf5a53efc, initial
INFO:__main__:Creating initial data
INFO:__main__:Initial data time_created

$ sh ./run.sh
INFO:     Will watch for changes in these directories: ['/root/projects/kit/rogue/server/midnav2']
INFO:     Uvicorn running on http://0.0.0.0:8001 (Press CTRL+C to quit)
INFO:     Started reloader process [11728] using statreload
INFO:     Started server process [11730]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
```


To start up the ICMP server, we execute:
```

$ python navi.py
[+] Starting ICMP Server

```

From there on, utilize the `rogue.arch.bin` file as you would any other shellcode! Its completely position independent.
