#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import base64
import fastapi_websocket_pubsub

gClient = None

async def tcallback( data ):
    try:
        ##
        ## If status == [ 0 ]
        ##
        if data[ "status" ] == 0 and "callback" in data:
            ##
            ## Check if "callback" is defined
            ##
            if data[ "callback" ] == 2 and data[ "code" ] == 0:
                ##
                ## Print Message if matches our client
                ##
                if data['target_id'] == gClient['id']:
                    print( '{}'.format( base64.b64decode( data['args']['buffer'] ).decode() ) );
    except Exception as e:
        print( e )

async def on_events( data, topic ):
    ##
    ## If "topic" == "tasks"
    ##
    if topic == "tasks": await tcallback( data );

async def ListenForLogs( Client ):
    global gClient
    gClient = Client
    async with fastapi_websocket_pubsub.PubSubClient( [ "tasks" ], on_events, server_uri = "ws://localhost:8001/midna" ) as WebSocket:
        await WebSocket.wait_until_done();
