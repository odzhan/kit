import asyncio
import httpx
import json
from core.state import Config
import config
import socket, os, platform


class Midna(object):
    def __init__(self):
        self.token = ""
        self.guid = ""        
        self.url = "http://127.0.0.1:8001"
        self.login_endpoint = "/api/v1/user/login"
        self.targets_endpoint = "/api/v1/target/"
        self.tasks_endpoint = "/api/v1/task/"
        

    # def get_listener_guid(self) -> None:
    #     with httpx.Client() as client:
    #         headers = {
    #             'Authorization': f'Bearer {self.token}',
    #             'Content-Type':'application/x-www-form-urlencoded'
    #         }
    #         r = client.get(
    #             self.url + self.targets_endpoint,  headers=headers)
    #         r = json.loads(r.text)
    #         self.guid = r['guid']            
    #     return True


    def get_auth(self) -> None:
        with httpx.Client() as client:
            data = { 
                "username":config.username, 
                "password":config.password
            }
            headers = {
                'Content-Type':'application/x-www-form-urlencoded'
            }
            r = client.post(
                self.url + self.login_endpoint, data=data, headers=headers)
            self.token = json.loads(r.text)['access_token']
        return True


    def register_self(self) -> None:
        with httpx.Client() as client:
            headers = {
                'Authorization': f'Bearer {self.token}',
                'Content-Type':'application/json'
            }
            target = {
                "machine_name": socket.gethostname(),
                "os_version": " ".join(os.uname()),
                "software_id": config.software_id,
                "architecture": platform.architecture()[0],
                "source_address": "127.0.0.1",
            }
            r = client.post(self.url + self.targets_endpoint, headers=headers, json=target)
        r = json.loads(r.text)
        self.guid = r["guid"]
        return True


    def get_targets(self):
        with httpx.Client() as client:
            headers = { 
                'Authorization': f'Bearer {self.token}',
                'Content-Type': 'application/json' 
            }
            r = client.get(self.url + self.targets_endpoint, headers=headers)
        targets = json.loads(r.text)
        return targets["results"]

    def get_tasks(self):
        with httpx.Client() as client:
            headers = { 
                'Authorization': f'Bearer {self.token}',
                'Content-Type': 'application/json' 
            }
            r = client.get(self.url + self.tasks_endpoint, headers=headers)
        tasks = json.loads(r.text)
        return tasks["results"]

    def update_task(self, task):
        with httpx.Client() as client:
            headers = { 
                'Authorization': f'Bearer {self.token}',
                'Content-Type': 'application/json' 
            }
            r = client.put(self.url + self.tasks_endpoint, headers=headers, json=task)
        return True


    def clr_target(self, target):
        with httpx.Client() as client:
            headers = {
                    'Authorization': f'Bearer {self.token}',
                    'Content-Type': 'application/json'
            }
            r = client.delete( self.url + self.targets_endpoint + target, headers=headers );

        return True

    def new_task( self, task ):
        with httpx.Client() as client:
            headers = {
                    'Authorization': f'Bearer {self.token}',
                    'Content-Type': 'application/json'
            };
            r = client.post( self.url + self.tasks_endpoint, headers=headers, json=task );

    def new_target(self, target):
        with httpx.Client() as client:
            headers = { 
                'Authorization': f'Bearer {self.token}',
                'Content-Type': 'application/json' 
            }
            if "parent" not in target.keys():
                target['parent'] = self.guid

            r = client.post(self.url + self.targets_endpoint, headers=headers, json=target)
        
        return r.text
