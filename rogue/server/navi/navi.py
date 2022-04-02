import asyncio

import base64
import httpx
from threading import Thread
import re
from fastapi_websocket_pubsub import PubSubClient

from core.state import Config

from lib import midna
from lib import icmp
from lib import websocket
from lib import helper
from lib.midna import Midna

from core.state import targets, Target
from core.state import tasks, Task, TaskingResponse
from lib import logging
import config

midna = Midna()
midna.get_auth()
midna.register_self()
#midna.get_listener_#guid()

#sys.path.append(os.path.abspath(os.path.join(os.path.basename(__file__), "..")))




def handle_callback(data, protocol = 'UNK', address = 'Unknown'):
    """
    Retrieve/Send Tasking
    """
    return_data = ''
    
    instance_id = data[ : config.instance_id_length]

    try: # Check to see if the data even looks right
        instance_id = instance_id.decode()
        if not instance_id.isalnum():
            raise Exception('Instance ID is not alphanumeric!')
    except:
        logging.error('Failed to parse callback. Check decryption keys!')
        return b''

    if len(data) == config.instance_id_length:
        # Task doesn't have data. Is just a checkin.
        try:
            tgt = targets[instance_id]
            return_data = tgt.check_tasks()

            if return_data:
                update = {
                    "id": return_data.unique_task_id,
                    "status": 2
                }
                midna.update_task(update)
        except:
            logging.debug(f"Recieved checkin for {instance_id} but no knowledge of it")
            return_data = False
    else:
        # Task has data
        data = data[config.instance_id_length : ]
        tasking_response = TaskingResponse(data)

        ##
        ## Say Hello!
        ##
        if tasking_response.unique_task_id == 0 and tasking_response.return_code != 3:
            # Hello Packet            
            helper.parse_hello_packet(instance_id, tasking_response.return_data, address)
            return b''

        ##
        ## Exit 
        ##
        if tasking_response.return_code == 2:
            # Exit Packet
            midna.clr_target( str( targets[instance_id].id ) );
            del targets[instance_id]
            logging.success( '{} has successfully exited.'.format( instance_id ) );
            return b''

        ##
        ## Print output
        ##
        if tasking_response.return_code == 3:
            ##
            ## Update the current task status
            ##
            midna.update_task( {
                    "id": tasking_response.unique_task_id,
                    "return_data": base64.b64encode( tasking_response.return_data ).decode(),
                    "return_code": tasking_response.return_code,
                    "status": 2
            });
            ##
            ## Abort!
            ##
            return b''


        # Update task with data
        update = {
            "id": tasking_response.unique_task_id,
            "return_data": base64.b64encode( tasking_response.return_data ).decode(),
            "return_code": tasking_response.return_code,
            "status": 3
        }
        x = midna.update_task(update)

    if isinstance(return_data, str):
        return_data = return_data.encode()

    if not return_data:
        return b''
   
    
    return return_data.serialize()

def populate_targets(data):
    """
    Build the targets struct
    """
    for tgt in data:
        try:
            targets[tgt["implant_id"]] = Target(
                tgt["id"],
                tgt["interval"]
            )
        except:
            None
    

def populate_tasks(data):
    """
    Assign tasking to the targets
    """
    for task in data:
        if task['target_id'] in targets.keys():
            tgt = targets[task['target_id']]
            tgt.add_task(task)

if __name__ == '__main__':
    # Get Authentication Token
    populate_targets( midna.get_targets() )
    populate_tasks( midna.get_tasks() )


    icmp_interface = "0.0.0.0"
    icmp_listener = Thread(target = icmp.StartICMPServer, args = (icmp_interface, ))
    icmp_listener.start()
    asyncio.run(websocket.start())
