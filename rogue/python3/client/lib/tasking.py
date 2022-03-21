import enum
import struct

##
## Command to execute
##
COMMAND_HELLO             = 0
COMMAND_EXECUTE_SHELLCODE = 1

##
## Request format
##
class TaskingRequest( ):
    def __init__(self, task_code, unique_task_id, argument1 = '' ):
        self.task_code = int(task_code)
        self.unique_task_id = int(unique_task_id)
        self.argument1 = argument1

    def serialize( self ):
        ##
        ## Do we have an argument?
        ##
        if isinstance( self.argument1, str ):
            self.argument1 = self.argument1.encode()

        ##
        ## Create tasking request
        ##
        serialized_data  = struct.pack('!II', self.task_code, self.unique_task_id)
        serialized_data += struct.pack('!I', len(self.argument1)) + self.argument1

        ##
        ## Return
        ##
        return serialized_data
