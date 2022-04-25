import asyncio
import httpx
import json
import socket
import os
import platform


class Midna(object):
    def __init__( self, username, password ):
        self.token = ""
        self.guid = ""   
        self.username = username
        self.password = password
        self.url = "http://127.0.0.1:8001"
        self.login_endpoint = "/api/v1/user/login"
        self.targets_endpoint = "/api/v1/target/"
        self.tasks_endpoint = "/api/v1/task/"

    def get_auth(self) -> None:
        with httpx.Client() as client:
            data = { 
                "username": self.username, 
                "password": self.password
            }
            headers = {
                'Content-Type':'application/x-www-form-urlencoded'
            }
            r = client.post(
                self.url + self.login_endpoint, data=data, headers=headers, timeout = None );
            self.token = json.loads(r.text)['access_token']
        return True

    def get_targets(self):
        with httpx.Client() as client:
            headers = { 
                'Authorization': f'Bearer {self.token}',
                'Content-Type': 'application/json' 
            }
            r = client.get(self.url + self.targets_endpoint, headers=headers, timeout = None);
        targets = json.loads(r.text)
        return targets["results"]

    def get_task( self, idstr ):
        with httpx.Client() as client:
            headers = {
                    'Authorization': f'Bearer {self.token}',
                    'Content-Type': 'application-json'
            }
            r = client.get( self.url + self.tasks_endpoint + idstr, headers=headers, timeout = None );
            tasks = json.loads(r.text);
            return tasks['results'];

    def get_tasks(self):
        with httpx.Client() as client:
            headers = { 
                'Authorization': f'Bearer {self.token}',
                'Content-Type': 'application/json' 
            }
            r = client.get(self.url + self.tasks_endpoint, headers=headers, timeout = None);
        tasks = json.loads(r.text)
        return tasks["results"]

    def new_task(self, task):
        with httpx.Client() as client:
            headers = {
                "accept": "application/json",
                "Authorization": f'Bearer {self.token}',
                "Content-Type": "application/json"
            };
            r = client.post(self.url + self.tasks_endpoint, headers=headers, json=task, timeout = None);
            return json.loads( r.text );

    def update_task(self, task):
        with httpx.Client() as client:
            headers = { 
                'Authorization': f'Bearer {self.token}',
                'Content-Type': 'application/json' 
            }
            r = client.put(self.url + self.tasks_endpoint, headers=headers, json=task, timeout = None);
        return True

    def remove_target( self, idstr ):
        with httpx.Client() as client:
            headers = {
                'Authorization': f'Bearer {self.token}',
                'Content-Type': 'applicaton/json'
            }
            r = client.delete( self.url + self.targets_endpoint + idstr, headers=headers, timeout=None);
        return True

    def new_target(self, target):
        with httpx.Client() as client:
            headers = { 
                'Authorization': f'Bearer {self.token}',
                'Content-Type': 'application/json' 
            }
            if "parent" not in target.keys():
                target['parent'] = self.guid

            r = client.post(self.url + self.targets_endpoint, headers=headers, json=target, timeout = None );
        
        return r.text
