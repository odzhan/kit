import asyncio


from fastapi_websocket_pubsub import PubSubClient
from core import state

import base64
import logging
import os
import sys
import json
from core.state import targets
import navi

async def tasks(data):
    try:
        if data["status"] == 0:
            tgt = [tgt for tgt in targets if targets[tgt].id == data['target_id']][0]
            tgt = targets[tgt]

            if 'buffer' not in data['args']:
                data['args']['buffer'] = ''

            ##
            ## Is a Log task?
            ##
            if data['return_code'] == 3:
                ##
                ## Is our log!
                ##
                pass
            else:
                task = state.TaskingRequest( data["code"], data["id"], base64.b64decode( data['args']['buffer'] ) )
                tgt.add_task(task)
                data['status'] = 1
                navi.midna.update_task(data)
                logging.debug(f"Adding task: {task}")
    except Exception as e:
        print( e );
        logging.debug(f"Error adding task: {data}")


async def on_events(data, topic):
    if topic == "tasks":
        await tasks(data)
    else:
        print(f"Unknown data: {data}")


async def start():
    # Create a client and subscribe to topics
    async with PubSubClient(["tasks"], on_events, server_uri="ws://localhost:8001/midna") as client:
        # will not end until client.disconnect() is called (by another task / callback)
        await client.wait_until_done()
