from enum import Enum


class ArgType(Enum):
    number = 1,
    boolean = 2,
    string = 3


class ReturnCode(Enum):
    Success = 0
    Failure = 1
    FunctionalityNotImplemented = 2
    ProcessStillRunning = 20
    ModuleNotLoaded = 30


class TaskStatus(Enum):
    Pending = 0
    Assigned = 1
    Working = 2
    Completed = 3


class Role(Enum):
    Listener = 0
    Operator = 1
    Administrator = 2


class SoftwareType(Enum):
    Listener = 0
    Implant = 1
    