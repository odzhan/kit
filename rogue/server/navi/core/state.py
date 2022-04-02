import struct
from enum import Enum


targets = {}
tasks = {}


class Config():
    auth = ""

class TaskingRequest():
    def __init__(self, task_code, unique_task_id, argument1 = b'' ):
        self.task_code = int(task_code)
        self.unique_task_id = int(unique_task_id)
        self.argument1 = argument1

    def serialize(self):
        if isinstance(self.argument1, str):
            self.argument1 = self.argument1.encode()

        serialized_data  = struct.pack('!II', self.task_code, self.unique_task_id)
        serialized_data += struct.pack('!I', len(self.argument1)) + self.argument1

        return serialized_data


class TaskingResponse():
    def __init__(self, serialized_data):
        if serialized_data:
            ( self.unique_task_id, self.return_code, self.winapi_code ) = struct.unpack('!III', serialized_data[ : 12 ])
        self.return_data= serialized_data[ 12 : ]


class Task(object):
    def __init__(self, target_id, task_code, args, status):
        self.target_id = target_id
        self.task_code = task_code
        self.args = args
        self.status = status
        self.return_data = ''
        self.return_code = ''

class Target(object):
    def __init__(self, id, interval):        
        self.id = id
        self.interval = interval
        self.pending_tasks = []
        self.submitted_tasks = []
        self.completed_tasks = []


    def add_task(self, task):
        self.pending_tasks.append(task)


    def check_tasks(self):
        if len(self.pending_tasks) == 0:
            return False

        task = self.pending_tasks.pop(0)
        self.submitted_tasks.append(task)
        return task
        


