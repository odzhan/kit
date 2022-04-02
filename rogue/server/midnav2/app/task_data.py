import time
from core.state import ArgType

SOFTWARE = [
    {
        "id": 1,
        "name": "Twili",
        "softwaretype": 0,
        "description": "HTTPS Listener for LongShot/LongClaw"
    },
    {
        "id":2,
        "softwaretype": 0,
        "name": "Navi",
        "description": "HTTPS Listener for HookShot"
    },
    {
        "id": 3,
        "softwaretype": 1,
        "name": "LongShot",
        "description": "Stage 2 HTTPS/SMB Implant for Windows"
    },
    {
        "id": 4,
        "softwaretype": 1,
        "name": "LongClaw",
        "description": "Stage 2 HTTPS/SMB Implant for Windows"
    },
    {
        "id": 5,
        "softwaretype": 1,
        "name": "ScatterShot",
        "description": "Stage 1 ICMP Implant for Windows"
    }
]

SCATTER_SHOT = [
    {
        "id": 0,
        "software_id": 5,
        "name": "hello",
        "category": "General",
        "description": "Resend Hello Packet",
        "priv_level": 0,
        "enabled": True,
        "opsec_risk": 0,
        "arch": 0,
        "os": "any",
        "args": []
    },
    {
        "id": 1,
        "software_id": 5,
        "name": "shell",
        "category": "General",
        "description": "Execute a shell command",
        "priv_level": 0,
        "enabled": True,
        "opsec_risk": 1,
        "arch": 0,
        "os": "any",
        "args": [
            {
                "name": "cmd",
                "required": True,
                "value": "",
                "default_value": "",
                "description": "Shell Command to Run",
                "type": ArgType.string.value
            }
        ]
    },
    {
        "id": 2,
        "software_id": 5,
        "name": "download",
        "category": "General",
        "description": "Download a file",
        "priv_level": 0,
        "enabled": True,
        "opsec_risk": 0,
        "arch": 0,
        "os": "any",
        "args": [
            {
                "name": "file",
                "required": True,
                "value": "",
                "default_value": "",
                "description": "Full path to file",
                "type": ArgType.string.value
            }
        ]
    },
    {
        "id": 3,
        "software_id": 5,
        "name": "period",
        "category": "General",
        "description": "Change callback period",
        "priv_level": 0,
        "enabled": True,
        "opsec_risk": 0,
        "arch": 0,
        "os": "any",
        "args": [
            {
                "name": "seconds",
                "required": True,
                "value": "",
                "default_value": "120",
                "description": "Seconds between callback",
                "type": ArgType.number.value
            }
        ]
    },
    {
        "id": 4,
        "software_id": 5,
        "name": "sleep",
        "category": "General",
        "description": "Task beacon to sleep",
        "priv_level": 0,
        "enabled": True,
        "opsec_risk": 0,
        "arch": 0,
        "os": "any",
        "args": [
            {
                "name": "seconds",
                "required": True,
                "value": "",
                "default_value": "3600",
                "description": "Time to sleep",
                "type": ArgType.number.value
            }
        ]
    },
    {
        "id": 5,
        "software_id": 5,
        "name": "ps",
        "category": "General",
        "description": "Output a process list",
        "priv_level": 0,
        "enabled": True,
        "opsec_risk": 1,
        "arch": 0,
        "os": "any",
        "args": []
    },
    {
        "id": 6,
        "software_id": 5,
        "name": "inject",
        "category": "General",
        "description": "Inject into a process",
        "priv_level": 0,
        "enabled": True,
        "opsec_risk": 5,
        "arch": 0,
        "os": "any",
        "args": [
            {
                "name": "PID",
                "required": True,
                "value": "",
                "default_value": "",
                "description": "Process name or PID",
                "type": ArgType.number.value
            },
            {
                "name": "DLL",
                "required": True,
                "value": "",
                "default_value": "",
                "description": "DLL To Execute",
                "type": ArgType.string.value
            }
        ]
    }
]

USERS = [{
    'id':1,
    'email':'user@midna.local',
    'password':'password',
    'role':1,
    'date': int(time.time()*1000),
    'is_superuser': True
},
{
    'id':2,
    'email':'listener@midna.local',
    'password':'password',
    'role':0,
    'date': int(time.time()*1000),
    'is_superuser': False
}]